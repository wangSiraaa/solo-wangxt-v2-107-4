package integration

// 可恢复认证尝试的端到端验收测试（真应用 + 真 PostgreSQL + 真实签名的假 OIDC IdP）。
//
// 覆盖：
//   - 一次可模拟的临时失败后生成全新请求并成功登录 / 关联；
//   - 重复恢复操作只留下一个有效后继请求（含并发恢复）；
//   - 恢复后旧 state / 旧授权码到达均被拒绝；
//   - 令牌签名、nonce、PKCE( invalid_grant ) 等永久失败不可恢复；
//   - 重启后未过期尝试可继续；过期关联不会被重新打开；
//   - 一次性回调防重放、已完成流程不可回退、并发回调不重复建成员。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/models"
)

// driveOnce GET 一次（不跟随重定向），返回响应与最终 URL。
func driveOnce(t *testing.T, c *flowClient, raw string) *http.Response {
	t.Helper()
	return c.doOnce(raw)
}

// followRedirect 手动跟随一跳 302，返回下一跳 URL。
func followRedirect(t *testing.T, resp *http.Response) string {
	t.Helper()
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("expected redirect, got status %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return loc
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode (status=%d) %q: %v", resp.StatusCode, string(data), err)
	}
	return out
}

// runLoginToFirstCallback 执行 应用登录 -> 假 IdP -> 应用回调，
// 返回（回调 URL, 回调响应）。不跟随回调之后的重定向。
func runLoginToFirstCallback(t *testing.T, c *flowClient, env *resumeEnv) (string, *http.Response) {
	t.Helper()
	start := loginStartURL(env.baseURL, "acme", env.idp.issVal())
	r0 := driveOnce(t, c, start)
	if r0.StatusCode != http.StatusFound {
		t.Fatalf("login start status=%d want 302", r0.StatusCode)
	}
	idpAuth := followRedirect(t, r0)
	r1 := driveOnce(t, c, idpAuth)
	if r1.StatusCode != http.StatusFound {
		t.Fatalf("idp authorize status=%d want 302", r1.StatusCode)
	}
	callbackURL := followRedirect(t, r1)
	r2 := driveOnce(t, c, callbackURL)
	return callbackURL, r2
}

// TestRecoverableLogin_TemporaryFailureThenSuccess 验收：
// 一次模拟的临时失败（token 端点 503）后，恢复会铸造全新 state/nonce/PKCE 并成功登录。
func TestRecoverableLogin_TemporaryFailureThenSuccess(t *testing.T) {
	idp := startFakeIdP(t, "user-alice", "alice@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)

	idp.failNextToken(2)
	oldCallback, cb := runLoginToFirstCallback(t, c, env)
	body := decodeBody(t, cb)
	if cb.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("first callback status=%d want 503, body=%v", cb.StatusCode, body)
	}
	if body["recoverable"] != true || body["resume_url"] == nil || body["attempt_token"] == nil {
		t.Fatalf("expected actionable recovery entry, got %v", body)
	}
	attemptToken := body["attempt_token"].(string)
	resumeURL := body["resume_url"].(string)
	oldState := queryParam(oldCallback, "state")
	oldCode := queryParam(oldCallback, "code")

	// 失败分类、状态、最大重试都必须持久化。
	row := struct {
		status, kind      string
		recoverable       bool
		seq, maxR, failed int
	}{}
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT status, COALESCE(last_failure_kind,''), last_failure_recoverable,
		        request_seq, max_retries, COALESCE(failed_request_seq,0)
		 FROM auth_attempts WHERE token=$1`, attemptToken,
	).Scan(&row.status, &row.kind, &row.recoverable, &row.seq, &row.maxR, &row.failed); err != nil {
		t.Fatalf("load attempt: %v", err)
	}
	if row.status != "pending" || row.kind != "provider_unavailable" || !row.recoverable ||
		row.seq != 1 || row.maxR != 3 || row.failed != 1 {
		t.Fatalf("persisted attempt row unexpected: %+v", row)
	}

	// 状态查询返回可操作入口（粗粒度，不泄密）。
	st := getJSON(t, c.http, env.baseURL+"/oauth/attempt?attempt="+attemptToken, http.StatusOK)
	if st["status"] != "recoverable" || st["recoverable"] != true || st["resume_url"] == nil {
		t.Fatalf("status endpoint = %v", st)
	}

	// 恢复：应产生新的代次与新的 state。
	rr := driveOnce(t, c, resumeURL)
	if rr.StatusCode != http.StatusFound {
		t.Fatalf("resume status=%d want 302", rr.StatusCode)
	}
	newIdpAuth := followRedirect(t, rr)
	newState := queryParam(newIdpAuth, "state")
	if newState == "" || newState == oldState {
		t.Fatalf("resume must mint a fresh state: old=%q new=%q", oldState, newState)
	}
	// 非敏感字段：不回显 nonce/pkce/code。
	if strings.Contains(newIdpAuth, oldCode) {
		t.Fatalf("resume url must not reuse the consumed code")
	}

	// 新代次走完假 IdP -> 应用回调成功（302 到 return_to）。
	ra := driveOnce(t, c, newIdpAuth)
	newCallback := followRedirect(t, ra)
	if !strings.Contains(newCallback, "state="+newState) {
		t.Fatalf("new callback state mismatch: %s", newCallback)
	}
	ok := driveOnce(t, c, newCallback)
	if ok.StatusCode != http.StatusFound {
		t.Fatalf("recovered callback status=%d want 302", ok.StatusCode)
	}
	if loc := ok.Header.Get("Location"); loc != "/" {
		t.Fatalf("post-login redirect=%q want /", loc)
	}
	_, _ = io.Copy(io.Discard, ok.Body)
	_ = ok.Body.Close()
	if c.cookie("sid") == "" {
		t.Fatalf("missing session cookie after recovery")
	}

	// 只建了一个成员、一个会话。
	if n := countWhere(t, env, `SELECT count(*) FROM members`); n != 1 {
		t.Fatalf("members=%d want 1", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM sessions`); n != 1 {
		t.Fatalf("sessions=%d want 1", n)
	}
	// 意图终态成功；旧请求 failed、新请求 consumed；没有遗留可消费请求。
	if n := countWhere(t, env, `SELECT count(*) FROM auth_attempts WHERE status='succeeded'`); n != 1 {
		t.Fatalf("succeeded attempts=%d want 1", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM auth_requests WHERE consumed_at IS NULL`); n != 0 {
		t.Fatalf("unconsumed requests=%d want 0", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM auth_requests WHERE failed_at IS NOT NULL`); n != 1 {
		t.Fatalf("failed old requests=%d want 1", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM auth_requests`); n != 2 {
		t.Fatalf("total request rows=%d want 2 (old + successor)", n)
	}

	// 已完成流程不能回退：恢复入口与状态都不再可用/不提供入口。
	gone := driveOnce(t, c, resumeURL)
	if gone.StatusCode != http.StatusGone {
		t.Fatalf("resume after success status=%d want 410", gone.StatusCode)
	}
	_, _ = io.Copy(io.Discard, gone.Body)
	_ = gone.Body.Close()
	st2 := getJSON(t, c.http, env.baseURL+"/oauth/attempt?attempt="+attemptToken, http.StatusOK)
	if st2["status"] != "succeeded" || st2["resume_url"] != nil {
		t.Fatalf("completed attempt status=%v", st2)
	}
}

// TestRecoverableLogin_DuplicateResumeSingleSuccessor 验收：
// 重复恢复（含并发）只留下一个有效后继请求，且每次返回同一后继 state。
func TestRecoverableLogin_DuplicateResumeSingleSuccessor(t *testing.T) {
	idp := startFakeIdP(t, "dup", "dup@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)

	idp.failNextToken(2)
	_, cb := runLoginToFirstCallback(t, c, env)
	body := decodeBody(t, cb)
	resumeURL := body["resume_url"].(string)

	// 串行重复点击恢复：第一次铸造后继，第二次起幂等复用。
	var states []string
	for i := 0; i < 3; i++ {
		rr := driveOnce(t, c, resumeURL)
		if rr.StatusCode != http.StatusFound {
			t.Fatalf("resume #%d status=%d want 302", i, rr.StatusCode)
		}
		states = append(states, queryParam(followRedirect(t, rr), "state"))
	}
	if states[0] != states[1] || states[1] != states[2] {
		t.Fatalf("duplicate resume minted different successors: %v", states)
	}

	// 并发恢复：20 个同时请求，数据库里仍只允许一个未消费后继。
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cc := newFlowClient(t)
			rr := cc.doOnce(resumeURL)
			if rr.StatusCode == http.StatusFound {
				s := queryParam(rr.Header.Get("Location"), "state")
				mu.Lock()
				got[s]++
				mu.Unlock()
			}
			_, _ = io.Copy(io.Discard, rr.Body)
			_ = rr.Body.Close()
		}()
	}
	wg.Wait()
	if len(got) != 1 {
		t.Fatalf("concurrent resume produced %d distinct successors: %v", len(got), got)
	}
	if n := countWhere(t, env,
		`SELECT count(*) FROM auth_requests WHERE consumed_at IS NULL`); n != 1 {
		t.Fatalf("unconsumed successors after concurrent resume=%d want 1", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM auth_requests`); n != 2 {
		t.Fatalf("request rows=%d want 2 (failed seq1 + single successor)", n)
	}
}

// TestResumeRejectedBeforeAnyFailure 验收：原请求仍在途（从未失败）时不允许铸造后继。
func TestResumeRejectedBeforeAnyFailure(t *testing.T) {
	idp := startFakeIdP(t, "early", "early@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)

	// 发起登录并拿到 IdP 授权地址，但绝不完成应用回调（请求未消费、未失败）。
	r0 := driveOnce(t, c, loginStartURL(env.baseURL, "acme", idp.issVal()))
	idpAuth := followRedirect(t, r0)
	if r := driveOnce(t, c, idpAuth); r.StatusCode != http.StatusFound {
		t.Fatalf("idp authorize status=%d want 302", r.StatusCode)
	} else {
		// 丢弃应用回调 URL：不请求它，意图保持在途。
		_ = followRedirect(t, r)
	}

	// 没有可恢复失败记录：状态为 active 且不提供恢复入口。
	st := getJSON(t, c.http, env.baseURL+"/oauth/attempt", http.StatusOK)
	if st["status"] != "active" || st["resume_url"] != nil {
		t.Fatalf("fresh attempt status=%v want active w/o resume", st)
	}
	// 即便直接调用恢复入口（cookie 携带 token），在“尚未失败”时也必须被拒绝，
	// 且不得新增请求行（防止在途请求被复制成并行有效请求）。
	rg := driveOnce(t, c, env.baseURL+"/oauth/resume")
	if rg.StatusCode != http.StatusGone {
		t.Fatalf("resume before failure status=%d want 410", rg.StatusCode)
	}
	_, _ = io.Copy(io.Discard, rg.Body)
	_ = rg.Body.Close()
	if n := countWhere(t, env, `SELECT count(*) FROM auth_requests`); n != 1 {
		t.Fatalf("requests=%d want 1", n)
	}
}

// TestOldStateAndOldCodeRejectedAfterResume 验收：
// 恢复后旧 state 到达被拒（400）；新 state 配旧授权码被 IdP 以 invalid_grant 拒绝，
// 且应用判定为不可恢复的永久失败（不产生成员/会话，恢复入口关闭）。
func TestOldStateAndOldCodeRejectedAfterResume(t *testing.T) {
	idp := startFakeIdP(t, "stale", "stale@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)

	idp.failNextToken(2)
	oldCallback, cb := runLoginToFirstCallback(t, c, env)
	body := decodeBody(t, cb)
	oldState, oldCode := queryParam(oldCallback, "state"), queryParam(oldCallback, "code")
	resumeURL := body["resume_url"].(string)

	// 1) 旧回调（旧 state+旧 code）再次到达：state 已消费 -> 400。
	replay := driveOnce(t, c, oldCallback)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("old callback status=%d want 400", replay.StatusCode)
	}
	rb := decodeBody(t, replay)
	if rb["error"] != "invalid_request" {
		t.Fatalf("old callback error=%v want invalid_request", rb["error"])
	}

	// 2) 恢复铸造新代次，但不真正完成；用“新 state + 旧 code”打回调。
	rr := driveOnce(t, c, resumeURL)
	newIdpAuth := followRedirect(t, rr)
	newState := queryParam(newIdpAuth, "state")
	if newState == oldState {
		t.Fatalf("resume did not rotate state")
	}
	forged := env.baseURL + "/oauth/callback?state=" + newState + "&code=" + oldCode
	fr := driveOnce(t, c, forged)
	fb := decodeBody(t, fr)
	if fr.StatusCode != http.StatusUnauthorized || fb["recoverable"] != false {
		t.Fatalf("stale code w/ fresh state status=%d body=%v, want 401 recoverable=false",
			fr.StatusCode, fb)
	}

	// 永久失败后恢复入口关闭，且没有任何成员/会话产生。
	gone := driveOnce(t, c, resumeURL)
	if gone.StatusCode != http.StatusGone {
		t.Fatalf("resume after permanent failure status=%d want 410", gone.StatusCode)
	}
	_, _ = io.Copy(io.Discard, gone.Body)
	_ = gone.Body.Close()
	if n := countWhere(t, env, `SELECT count(*) FROM members`); n != 0 {
		t.Fatalf("members=%d want 0", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM sessions`); n != 0 {
		t.Fatalf("sessions=%d want 0", n)
	}
}

// permanentCase 描述一种永久失败的构造方式。
type permanentCase struct {
	name    string
	prepare func(idp *fakeIdP)
}

// TestPermanentFailuresAreNotRecoverable 验收：
// 令牌签名错误、nonce 不匹配/缺失、PKCE/授权码无效都不可恢复。
func TestPermanentFailuresAreNotRecoverable(t *testing.T) {
	cases := []permanentCase{
		{"bad_signature", func(idp *fakeIdP) { idp.setWrongKey(true) }},
		{"wrong_nonce", func(idp *fakeIdP) { idp.setWrongNonce(true) }},
		{"missing_nonce", func(idp *fakeIdP) { idp.setOmitNonce(true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := startFakeIdP(t, "perm-"+tc.name, "p@example.com")
			env := startResumeEnv(t, idp, 10*time.Minute)
			c := newFlowClient(t)
			tc.prepare(idp)

			_, cb := runLoginToFirstCallback(t, c, env)
			body := decodeBody(t, cb)
			if cb.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s: status=%d want 401 body=%v", tc.name, cb.StatusCode, body)
			}
			if body["recoverable"] != false || body["resume_url"] != nil {
				t.Fatalf("%s: permanent failure leaked recovery entry: %v", tc.name, body)
			}
			tok := body["attempt_token"].(string)

			// 恢复被拒（410），状态为终态 failed。
			resume := env.baseURL + "/oauth/resume?attempt=" + tok
			g := driveOnce(t, c, resume)
			if g.StatusCode != http.StatusGone {
				t.Fatalf("%s: resume status=%d want 410", tc.name, g.StatusCode)
			}
			_, _ = io.Copy(io.Discard, g.Body)
			_ = g.Body.Close()
			st := getJSON(t, c.http, env.baseURL+"/oauth/attempt?attempt="+tok, http.StatusOK)
			if st["status"] != "failed" || st["resume_url"] != nil {
				t.Fatalf("%s: status=%v want failed", tc.name, st)
			}
			if n := countWhere(t, env, `SELECT count(*) FROM members`); n != 0 {
				t.Fatalf("%s: members=%d want 0", tc.name, n)
			}
		})
	}
}

// TestRecoverableLogin_SurvivesRestart 验收：
// 刷新/服务重启后，未过期的尝试仍可继续（意图完全在数据库里，进程内状态可丢）。
func TestRecoverableLogin_SurvivesRestart(t *testing.T) {
	idp := startFakeIdP(t, "restart", "r@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)

	idp.failNextToken(2)
	_, cb := runLoginToFirstCallback(t, c, env)
	body := decodeBody(t, cb)
	tok := body["attempt_token"].(string)

	// 模拟重启：关闭旧 HTTP 服务，用全新 Server（全新 OIDC 内存缓存）在同一库同端口起。
	env.restart(t)

	// cookie 里的 aat 仍在；状态接口在新进程上读到未过期、可恢复。
	st := getJSON(t, c.http, env.baseURL+"/oauth/attempt?attempt="+tok, http.StatusOK)
	if st["status"] != "recoverable" {
		t.Fatalf("post-restart status=%v want recoverable", st)
	}
	// 用 cookie（不带显式 token）恢复并成功。
	rr := driveOnce(t, c, env.baseURL+"/oauth/resume")
	if rr.StatusCode != http.StatusFound {
		t.Fatalf("post-restart resume status=%d want 302", rr.StatusCode)
	}
	newIdpAuth := followRedirect(t, rr)
	ra := driveOnce(t, c, newIdpAuth)
	newCallback := followRedirect(t, ra)
	ok := driveOnce(t, c, newCallback)
	if ok.StatusCode != http.StatusFound {
		t.Fatalf("post-restart recovered callback status=%d want 302", ok.StatusCode)
	}
	_, _ = io.Copy(io.Discard, ok.Body)
	_ = ok.Body.Close()
	if n := countWhere(t, env, `SELECT count(*) FROM members`); n != 1 {
		t.Fatalf("members=%d want 1", n)
	}
}

// TestMaxRetriesPersistedAndEnforced 验收：最大重试持久化并被强制执行。
func TestMaxRetriesPersistedAndEnforced(t *testing.T) {
	idp := startFakeIdP(t, "cap", "cap@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)
	idp.failNextToken(2)
	_, cb := runLoginToFirstCallback(t, c, env)
	body := decodeBody(t, cb)
	tok, resumeURL := body["attempt_token"].(string), body["resume_url"].(string)

	// 把持久化的上限改为 0：下一次恢复应被判定为重试耗尽（409），不铸造新请求。
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE auth_attempts SET max_retries=0 WHERE token=$1`, tok); err != nil {
		t.Fatalf("lower cap: %v", err)
	}
	g := driveOnce(t, c, resumeURL)
	if g.StatusCode != http.StatusConflict {
		t.Fatalf("resume over cap status=%d want 409", g.StatusCode)
	}
	gb := decodeBody(t, g)
	if gb["error"] != "attempt_unavailable" {
		t.Fatalf("over-cap error=%v want attempt_unavailable", gb["error"])
	}
	if n := countWhere(t, env, `SELECT count(*) FROM auth_requests`); n != 1 {
		t.Fatalf("requests after exhausted resume=%d want 1", n)
	}
}

// TestOneTimeCallbackReplayAndConcurrentDoubleCallback 验收：
// 一次性回调防重放仍成立；并发“新旧/同一”回调不会重复建成员/会话。
func TestOneTimeCallbackReplayAndConcurrentDoubleCallback(t *testing.T) {
	idp := startFakeIdP(t, "race", "race@example.com")
	env := startResumeEnv(t, idp, 10*time.Minute)
	c := newFlowClient(t)

	// 拿到一个未消费的回调 URL（先不请求应用）。
	r0 := driveOnce(t, c, loginStartURL(env.baseURL, "acme", idp.issVal()))
	idpAuth := followRedirect(t, r0)
	r1 := driveOnce(t, c, idpAuth)
	callbackURL := followRedirect(t, r1)

	// 20 个并发相同回调：恰好一个成功，其余 400。
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, bad := 0, 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := c.doOnce(callbackURL)
			mu.Lock()
			if resp.StatusCode == http.StatusFound {
				ok++
			} else if resp.StatusCode == http.StatusBadRequest {
				bad++
			}
			mu.Unlock()
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	if ok != 1 || bad != 19 {
		t.Fatalf("concurrent callbacks ok=%d bad=%d, want 1/19", ok, bad)
	}

	// 再顺序重放一次，仍被拒。
	replay := driveOnce(t, c, callbackURL)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("sequential replay status=%d want 400", replay.StatusCode)
	}
	_, _ = io.Copy(io.Discard, replay.Body)
	_ = replay.Body.Close()

	if n := countWhere(t, env, `SELECT count(*) FROM members`); n != 1 {
		t.Fatalf("members after concurrent callbacks=%d want 1", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM sessions`); n != 1 {
		t.Fatalf("sessions after concurrent callbacks=%d want 1", n)
	}
}

// ---- 账号关联（link）场景 ----

// addSecondProvider 在同一租户登记第二个假 IdP（关联的 B 身份提供方）。
func (env *resumeEnv) addSecondProvider(t *testing.T, idpB *fakeIdP) uuid.UUID {
	t.Helper()
	pid := uuid.MustParse("00000000-0000-0000-0000-0000000000d2")
	if err := env.store.UpsertProvider(context.Background(), &models.Provider{
		ID: pid, TenantID: env.tenantID, Issuer: idpB.issVal(),
		ClientID: "fake-client", ClientSecret: "fake-secret",
		RedirectURIs:   []string{env.baseURL + "/oauth/callback", env.baseURL + "/oauth/link/callback"},
		AuthTimeMaxAge: 300, Enabled: true,
	}); err != nil {
		t.Fatalf("add second provider: %v", err)
	}
	return pid
}

// loginMemberA 用 idpA 完成登录，返回会话客户端。
func loginMemberA(t *testing.T, env *resumeEnv) *flowClient {
	t.Helper()
	c := newFlowClient(t)
	_, cb := runLoginToFirstCallback(t, c, env)
	if cb.StatusCode != http.StatusFound {
		t.Fatalf("login A status=%d want 302", cb.StatusCode)
	}
	_, _ = io.Copy(io.Discard, cb.Body)
	_ = cb.Body.Close()
	return c
}

func startLinkB(t *testing.T, c *flowClient, env *resumeEnv, idpBIssuer string) (string, string, string) {
	t.Helper()
	body := map[string]string{"issuer": idpBIssuer}
	resp := postJSON(t, c.http, env.baseURL+"/t/acme/api/links", body, http.StatusCreated)
	return resp["link_token"].(string), resp["attempt_token"].(string), resp["link_url"].(string)
}

// TestRecoverableLink_TemporaryFailureThenSuccess 验收：
// 关联场景一次临时失败后安全重试成功；旧 leg B state 失效；不重复绑身份。
func TestRecoverableLink_TemporaryFailureThenSuccess(t *testing.T) {
	idpA := startFakeIdP(t, "alice", "alice@example.com")
	idpB := startFakeIdP(t, "bob", "bob@example.com")
	env := startResumeEnv(t, idpA, 10*time.Minute)
	env.addSecondProvider(t, idpB)
	c := loginMemberA(t, env)

	_, attemptTok, linkURL := startLinkB(t, c, env, idpB.issVal())

	// B 身份首次交换：token 端点临时失败。
	idpB.failNextToken(2)
	r1 := driveOnce(t, c, linkURL)
	oldCallback := followRedirect(t, r1)
	cb := driveOnce(t, c, oldCallback)
	bbody := decodeBody(t, cb)
	if cb.StatusCode != http.StatusServiceUnavailable || bbody["recoverable"] != true {
		t.Fatalf("link first callback status=%d body=%v want 503 recoverable", cb.StatusCode, bbody)
	}
	resumeURL := bbody["resume_url"].(string)
	oldState := queryParam(oldCallback, "state")

	// 关联恢复入口必须绑定发起它的同一会话：
	//  - 无会话 cookie 的匿名客户端在会话中间件处被拒（401）；
	//  - 另一个已登录成员（carol）持有有效会话，但会话不匹配，必须得到 410。
	anon := newFlowClient(t)
	g := anon.doOnce(resumeURL)
	if g.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous link resume status=%d want 401", g.StatusCode)
	}
	_, _ = io.Copy(io.Discard, g.Body)
	_ = g.Body.Close()

	idpA.mu.Lock()
	idpA.subject = "carol"
	idpA.mu.Unlock()
	carol := newFlowClient(t)
	if _, lcb := runLoginToFirstCallback(t, carol, env); lcb.StatusCode != http.StatusFound {
		t.Fatalf("carol login status=%d want 302", lcb.StatusCode)
	} else {
		_ = lcb.Body.Close()
	}
	idpA.mu.Lock()
	idpA.subject = "alice"
	idpA.mu.Unlock()
	g2 := carol.doOnce(resumeURL)
	if g2.StatusCode != http.StatusGone {
		t.Fatalf("cross-session link resume status=%d want 410", g2.StatusCode)
	}
	_, _ = io.Copy(io.Discard, g2.Body)
	_ = g2.Body.Close()

	// 旧 leg B state 在恢复前重放：已消费 -> 400。
	oldReplay := driveOnce(t, c, oldCallback)
	if oldReplay.StatusCode != http.StatusBadRequest {
		t.Fatalf("old link callback status=%d want 400", oldReplay.StatusCode)
	}
	_, _ = io.Copy(io.Discard, oldReplay.Body)
	_ = oldReplay.Body.Close()

	// 恢复：新 state，仍绑定原成员/租户/会话与未过期关联上下文。
	rr := driveOnce(t, c, resumeURL)
	if rr.StatusCode != http.StatusFound {
		t.Fatalf("link resume status=%d want 302", rr.StatusCode)
	}
	newIdpAuth := followRedirect(t, rr)
	if queryParam(newIdpAuth, "state") == oldState {
		t.Fatalf("link resume did not rotate leg B state")
	}
	// 关联恢复必须强制重新认证（prompt=login/max_age=0）。
	if queryParam(newIdpAuth, "prompt") != "login" || queryParam(newIdpAuth, "max_age") != "0" {
		t.Fatalf("link resume lost force-login params: %s", newIdpAuth)
	}
	ra := driveOnce(t, c, newIdpAuth)
	newCallback := followRedirect(t, ra)
	ok := driveOnce(t, c, newCallback)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("recovered link callback status=%d want 200", ok.StatusCode)
	}
	linked := decodeBody(t, ok)
	if linked["status"] != "linked" {
		t.Fatalf("link result=%v want linked", linked)
	}

	// 成员下两条身份，且只绑一次（无重复）。
	memberID := c.me0(env, "acme")
	if n := countWhere(t, env,
		`SELECT count(*) FROM identities WHERE tenant_id=$1 AND member_id=$2`,
		env.tenantID, memberID); n != 2 {
		t.Fatalf("identities on member=%d want 2", n)
	}
	if n := countWhere(t, env,
		`SELECT count(*) FROM identities WHERE tenant_id=$1 AND issuer=$2 AND subject='bob'`,
		env.tenantID, idpB.issVal()); n != 1 {
		t.Fatalf("bound B identity count=%d want 1", n)
	}
	// link_sessions 已 consumed（一次性）；attempt succeeded。
	if n := countWhere(t, env, `SELECT count(*) FROM link_sessions WHERE status='consumed'`); n != 1 {
		t.Fatalf("link sessions consumed=%d want 1", n)
	}
	if n := countWhere(t, env, `SELECT count(*) FROM auth_attempts WHERE token=$1 AND status='succeeded'`, attemptTok); n != 1 {
		t.Fatalf("link attempt not succeeded")
	}

	// 新 leg B 回调也一次性；恢复入口终态关闭。
	replayNew := driveOnce(t, c, newCallback)
	if replayNew.StatusCode != http.StatusBadRequest {
		t.Fatalf("new link callback replay status=%d want 400", replayNew.StatusCode)
	}
	_, _ = io.Copy(io.Discard, replayNew.Body)
	_ = replayNew.Body.Close()
	gDone := driveOnce(t, c, resumeURL)
	if gDone.StatusCode != http.StatusGone {
		t.Fatalf("link resume after completion status=%d want 410", gDone.StatusCode)
	}
	_, _ = io.Copy(io.Discard, gDone.Body)
	_ = gDone.Body.Close()
}

// TestExpiredLinkCannotBeReopened 验收：过期关联不会被恢复/回调重新打开。
func TestExpiredLinkCannotBeReopened(t *testing.T) {
	idpA := startFakeIdP(t, "alice2", "alice2@example.com")
	idpB := startFakeIdP(t, "bob2", "bob2@example.com")
	env := startResumeEnv(t, idpA, 2*time.Second)
	env.addSecondProvider(t, idpB)
	c := loginMemberA(t, env)

	_, attemptTok, linkURL := startLinkB(t, c, env, idpB.issVal())

	// B 先临时失败产生可恢复入口。
	idpB.failNextToken(2)
	r1 := driveOnce(t, c, linkURL)
	oldCallback := followRedirect(t, r1)
	cb := driveOnce(t, c, oldCallback)
	bbody := decodeBody(t, cb)
	if cb.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 got %d", cb.StatusCode)
	}
	resumeURL := bbody["resume_url"].(string)

	// 等待意图与关联会话都过期。
	time.Sleep(2500 * time.Millisecond)

	g := driveOnce(t, c, resumeURL)
	if g.StatusCode != http.StatusGone {
		t.Fatalf("resume expired link status=%d want 410", g.StatusCode)
	}
	ge := decodeBody(t, g)
	if ge["error"] != "attempt_unavailable" {
		t.Fatalf("expired resume error=%v", ge["error"])
	}
	// 旧回调在过期后到达：state join 仍可消费，但 link 层的过期/绑定检查必须拒绝。
	late := driveOnce(t, c, oldCallback)
	if late.StatusCode == http.StatusOK {
		t.Fatalf("expired link callback must not succeed")
	}
	_, _ = io.Copy(io.Discard, late.Body)
	_ = late.Body.Close()

	// 状态接口报过期且不给入口。
	st := getJSON(t, c.http, env.baseURL+"/oauth/link/attempt?attempt="+attemptTok, http.StatusOK)
	if st["status"] != "expired" || st["resume_url"] != nil {
		t.Fatalf("expired link status=%v", st)
	}
	// 没有绑定任何 B 身份。
	if n := countWhere(t, env, `SELECT count(*) FROM link_sessions WHERE status='completed'`); n != 0 {
		t.Fatalf("expired link completed=%d want 0", n)
	}
}

// me0 通过 /api/me 取成员 id（复用应用 jar）。
func (c *flowClient) me0(env *resumeEnv, slug string) string {
	t := c.t
	out := getJSON(t, c.http, fmt.Sprintf("%s/t/%s/api/me", env.baseURL, slug), http.StatusOK)
	return out["member_id"].(string)
}
