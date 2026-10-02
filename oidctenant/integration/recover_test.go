package integration

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	sec "github.com/example/oidctenant/internal/auth"
)

// 本文件覆盖“可恢复认证尝试”的全部验收点，使用进程内模拟 IdP + 真实应用，
// 不依赖外部 Keycloak。故障注入见 mockidp_test.go。

// TestRecoverLoginAfterTemporaryTokenFailure：
// 一次可模拟的临时失败（令牌端点 503）后生成全新请求并成功登录。
func TestRecoverLoginAfterTemporaryTokenFailure(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authURL := c.startLogin(env)
	cb1 := c.followAuthToCallback(authURL) // 拿到第 1 个 code（尚未交换）

	// 让下一次令牌交换返回暂时性 503。
	failExchangeForCallback(env.idpA, cb1)
	status, body := c.hitCallback(cb1)
	if status != http.StatusServiceUnavailable ||
		body["error"] != "provider_temporarily_unavailable" {
		t.Fatalf("transient failure: status=%d body=%v, want 503 provider_temporarily_unavailable",
			status, body)
	}
	tok := mustStr(body, "recovery_token")
	if tok == "" || mustStr(body, "recover_url") == "" {
		t.Fatalf("missing recovery entry in %v", body)
	}
	if v, _ := body["retries_left"].(float64); v != 2 {
		t.Fatalf("retries_left=%v, want 2", body["retries_left"])
	}
	// 没有任何成员/会话在暂时性失败时产生。
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 0 {
		t.Fatalf("members after transient failure=%d, want 0", n)
	}
	if n := countRows(t, env, "SELECT count(*) FROM sessions"); n != 0 {
		t.Fatalf("sessions after transient failure=%d, want 0", n)
	}

	// 恢复：全新 state/nonce/PKCE -> 302 JSON 含新的授权地址（POST 路径）。
	recStatus, recBody, _ := c.postRecover(env, tok)
	if recStatus != http.StatusOK {
		t.Fatalf("recover status=%d body=%v, want 200", recStatus, recBody)
	}
	newAuthURL := mustStr(recBody, "authorization_url")
	if newAuthURL == "" || newAuthURL == authURL {
		t.Fatalf("recovery must mint a fresh authorization URL, got %q vs %q", newAuthURL, authURL)
	}
	if used, _ := recBody["reused_active"].(bool); used {
		t.Fatalf("first recovery must create a new request, reused_active should be false")
	}

	// 全新 code 走全新回调成功。
	cb2 := c.followAuthToCallback(newAuthURL)
	status2, body2 := c.hitCallback(cb2)
	if status2 != http.StatusFound {
		t.Fatalf("recovered callback status=%d body=%v, want 302", status2, body2)
	}
	if code, _ := c.me(env); code != http.StatusOK {
		t.Fatalf("me after recover status=%d", code)
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 1 {
		t.Fatalf("members after recovered login=%d, want exactly 1", n)
	}
	if n := countRows(t, env, "SELECT count(*) FROM auth_requests WHERE consumed_at IS NOT NULL") +
		countRows(t, env, "SELECT count(*) FROM auth_requests WHERE invalidated_at IS NOT NULL"); n < 2 {
		t.Fatalf("expected old requests consumed/invalidated, got %d", n)
	}
}

// TestRecoverDuplicateLeavesSingleSuccessor：
// 重复恢复操作只留下一个有效后继请求（幂等复用，不新增 state/nonce/PKCE）。
func TestRecoverDuplicateLeavesSingleSuccessor(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authURL := c.startLogin(env)
	cb1 := c.followAuthToCallback(authURL)
	failExchangeForCallback(env.idpA, cb1)
	_, body := c.hitCallback(cb1)
	tok := mustStr(body, "recovery_token")

	_, b1, _ := c.postRecover(env, tok)
	u1 := mustStr(b1, "authorization_url")
	if u1 == "" {
		t.Fatalf("first recover missing url: %v", b1)
	}
	// 立刻第二次恢复（模拟双击/刷新恢复入口）。
	_, b2, _ := c.postRecover(env, tok)
	u2 := mustStr(b2, "authorization_url")
	if reused, _ := b2["reused_active"].(bool); !reused {
		t.Fatalf("duplicate recovery must reuse active successor, body=%v", b2)
	}
	if u1 != u2 {
		t.Fatalf("duplicate recovery minted a second request:\n%s\n%s", u1, u2)
	}
	// 第三次（GET 路径，浏览器）也必须复用并 302 到同一授权地址。
	resp := c.get(env.baseURL + "/oauth/recover")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != u1 {
		t.Fatalf("GET recover status=%d loc=%q, want 302 same url",
			resp.StatusCode, resp.Header.Get("Location"))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 数据库：该意图 attempts 只增加过一次，有效具体请求恰好 1 个。
	var attempts int
	var active sql.NullString
	hashRow(env, t, tok, &attempts, &active)
	if attempts != 2 {
		t.Fatalf("attempts=%d, want 2 (initial + single successor)", attempts)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM auth_requests
		 WHERE attempt_id=(SELECT id FROM auth_attempts WHERE active_state=$1)
		   AND consumed_at IS NULL AND invalidated_at IS NULL`, active.String); n != 1 {
		t.Fatalf("valid successor requests=%d, want exactly 1", n)
	}
}

// TestOldStateAndCodeRejectedAfterRecovery：
// 恢复后旧 state、旧授权码到达回调都被拒绝；旧码即使用新请求也换不出令牌。
func TestOldStateAndCodeRejectedAfterRecovery(t *testing.T) {
	env := startRecoverEnv(t)

	// ---- A. 合法路径：一次临时失败 -> 恢复 -> 全新请求成功 ----
	good := newHTTPClient(t, false)
	authURL1 := good.startLogin(env)
	cb1 := good.followAuthToCallback(authURL1)
	oldState := queryParam(cb1, "state")

	failExchangeForCallback(env.idpA, cb1)
	_, body := good.hitCallback(cb1)
	tok := mustStr(body, "recovery_token")
	_, rec, _ := good.postRecover(env, tok)
	newAuthURL := mustStr(rec, "authorization_url")
	cb2 := good.followAuthToCallback(newAuthURL)
	if queryParam(cb2, "state") == oldState {
		t.Fatalf("recovery must rotate state")
	}
	// 恢复后的新请求成功登录。
	if st, b := good.hitCallback(cb2); st != http.StatusFound {
		t.Fatalf("legit recovered callback status=%d body=%v, want 302", st, b)
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 1 {
		t.Fatalf("members=%d, want 1", n)
	}
	// 旧 state（合法路径已用过）再次到达：400，与未知 state 行为一致。
	if st, b := good.hitCallback(cb1); st != http.StatusBadRequest ||
		b["error"] != "invalid_request" {
		t.Fatalf("old state replay status=%d body=%v, want 400 invalid_request", st, b)
	}

	// ---- B. 攻击路径：独立尝试里“新 state + 旧授权码”必须永久失败 ----
	// 先制造一个已被消费（交换成功）的授权码。
	victim := newHTTPClient(t, false)
	vAuth := victim.startLogin(env)
	vCB := victim.followAuthToCallback(vAuth)
	usedCode := queryParam(vCB, "code")
	if st, _ := victim.hitCallback(vCB); st != http.StatusFound {
		t.Fatalf("victim login should succeed")
	}

	atk := newHTTPClient(t, false)
	aAuth := atk.startLogin(env)
	// 发起后立即恢复出第二个具体请求，拿它尚未使用的新 state；不真正走 IdP，
	// 直接把“受害者的旧授权码”配到攻击者的新 state 上打回调。
	aCB1 := atk.followAuthToCallback(aAuth)
	failExchangeForCallback(env.idpA, aCB1)
	_, ab := atk.hitCallback(aCB1)
	aTok := mustStr(ab, "recovery_token")
	_, arec, _ := atk.postRecover(env, aTok)
	freshState := queryParam(mustStr(arec, "authorization_url"), "state")

	forged := env.baseURL + "/oauth/callback?state=" + freshState + "&code=" + usedCode
	stForged, bForged := atk.hitCallback(forged)
	if stForged != http.StatusUnauthorized || bForged["error"] != "authentication_failed" {
		t.Fatalf("fresh state + used code status=%d body=%v, want 401 authentication_failed",
			stForged, bForged)
	}
	// 永久失败后该尝试不可恢复。
	_, bRec, _ := atk.postRecover(env, aTok)
	if code := intFrom(bRec, "_status_code"); code != http.StatusGone {
		t.Fatalf("recover after permanent failure status=%d body=%v, want 410", code, bRec)
	}
	// 攻击不产生额外成员：受害者与合法用户是同一 (issuer,subject)，业务上
	// 本来就复用同一成员，因此总成员数仍为 1。
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 1 {
		t.Fatalf("members=%d, want exactly 1 (attack must not create any member)", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM auth_attempts WHERE status='failed_permanent'`); n != 1 {
		t.Fatalf("attack attempt must be permanently failed")
	}
}

// TestPermanentFailuresAreNotRecoverable：
// 签名错误 / nonce 篡改 / PKCE 不匹配 都是永久失败，绝不给出恢复入口。
func TestPermanentFailuresAreNotRecoverable(t *testing.T) {
	cases := []struct {
		name   string
		inject func(env *recoverEnv, authURL, code string)
	}{
		{
			name: "bad signature",
			inject: func(env *recoverEnv, _ string, code string) {
				env.idpA.useBadSigningKey()
			},
		},
		{
			name: "wrong nonce",
			inject: func(env *recoverEnv, _ string, code string) {
				env.idpA.mutateClaims(func(claims map[string]any) {
					claims["nonce"] = "forged-nonce"
				})
			},
		},
		{
			name: "stale code (invalid_grant)",
			inject: func(env *recoverEnv, _ string, code string) {
				env.idpA.setCodeStatus(code, http.StatusBadRequest)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := startRecoverEnv(t)
			c := newHTTPClient(t, false)
			authURL := c.startLogin(env)
			cb := c.followAuthToCallback(authURL)
			code := queryParam(cb, "code")
			tc.inject(env, authURL, code)

			status, body := c.hitCallback(cb)
			if status != http.StatusUnauthorized || body["error"] != "authentication_failed" {
				t.Fatalf("permanent failure status=%d body=%v, want 401 authentication_failed",
					status, body)
			}
			// 响应里不得出现任何恢复入口。
			if body["recovery_token"] != nil || body["recover_url"] != nil {
				t.Fatalf("permanent failure leaked recovery entry: %v", body)
			}

			// 从数据库取恢复令牌（等于客户端持有的 cookie 值无法直接构造，
			// 这里通过意图状态断言：必须是 failed_permanent 且不可恢复）。
			if n := countRows(t, env,
				`SELECT count(*) FROM auth_attempts
				 WHERE status='failed_permanent' AND recoverable=false`); n != 1 {
				t.Fatalf("attempt not permanently failed (count=%d)", n)
			}
			if n := countRows(t, env, "SELECT count(*) FROM members"); n != 0 {
				t.Fatalf("members=%d, want 0", n)
			}
		})
	}
}

// TestRecoverPersistsAcrossRestartLikeBoundary：
// 未过期尝试可继续（状态查询+恢复都正常）；过期的尝试与关联不能重新打开。
func TestRecoverPersistsAcrossRestartLikeBoundary(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authURL := c.startLogin(env)
	cb := c.followAuthToCallback(authURL)
	failExchangeForCallback(env.idpA, cb)
	_, body := c.hitCallback(cb)
	tok := mustStr(body, "recovery_token")

	// 状态查询：未过期 pending 可恢复（等价于刷新页面/重启后读取持久化意图）。
	st, sb := c.postStatus(env, tok)
	if st != http.StatusOK || sb["status"] != "pending" {
		t.Fatalf("status of fresh recoverable attempt: %d %v", st, sb)
	}
	if rec, _ := sb["recoverable"].(bool); !rec {
		t.Fatalf("expected recoverable=true, got %v", sb)
	}

	// 模拟服务重启后的过期清理：直接把到期意图标记 expired（与 cleanupLoop 等价），
	// 恢复与状态查询都必须拒绝（已过期不重开）。
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE auth_attempts SET expires_at = now() - interval '1 second'
		 WHERE status='pending'`); err != nil {
		t.Fatalf("age attempt: %v", err)
	}
	if n, err := env.store.ExpirePendingAttempts(context.Background(), time.Now()); err != nil || n != 1 {
		t.Fatalf("ExpirePendingAttempts n=%d err=%v, want 1", n, err)
	}
	stExp, bExp := c.postStatus(env, tok)
	if stExp != http.StatusGone {
		t.Fatalf("expired attempt status=%d body=%v, want 410", stExp, bExp)
	}
	_, bRec, _ := c.postRecover(env, tok)
	if code := intFrom(bRec, "_status_code"); code != http.StatusGone {
		t.Fatalf("recover expired attempt status=%d body=%v, want 410", code, bRec)
	}
}

// TestRecoverContinuesAfterServerRestart：
// 暂时性失败后重启应用进程，未过期尝试仍可凭持久化的恢复令牌继续并成功。
func TestRecoverContinuesAfterServerRestart(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authURL := c.startLogin(env)
	cb := c.followAuthToCallback(authURL)
	failExchangeForCallback(env.idpA, cb)
	st, body := c.hitCallback(cb)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 transient, got %d %v", st, body)
	}
	tok := mustStr(body, "recovery_token")

	// 重启服务（新的 oidc manager / 路由 / 内存；同一数据库）。
	env.restartServer(t)

	// 重启后状态查询仍报告 pending + recoverable。
	if s, b := c.postStatus(env, tok); s != http.StatusOK || b["status"] != "pending" {
		t.Fatalf("post-restart status query=%d %v, want 200 pending", s, b)
	}
	// 恢复成功并走全新请求登录。
	recStatus, rec, _ := c.postRecover(env, tok)
	if recStatus != http.StatusOK {
		t.Fatalf("post-restart recover=%d %v", recStatus, rec)
	}
	cb2 := c.followAuthToCallback(mustStr(rec, "authorization_url"))
	if st, b := c.hitCallback(cb2); st != http.StatusFound {
		t.Fatalf("post-restart callback=%d %v, want 302", st, b)
	}
	if code, _ := c.me(env); code != http.StatusOK {
		t.Fatalf("me after restart-recover failed")
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 1 {
		t.Fatalf("members=%d, want 1", n)
	}
}

// TestRecoverMaxAttemptsEnforced：达到上限后恢复被拒绝（410）。
func TestRecoverMaxAttemptsEnforced(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	var tok string
	// max_attempts=3：初始 + 2 次恢复后继；第 3 次恢复必须 410。
	authURL := c.startLogin(env)
	for i := 0; i < 3; i++ {
		cb := c.followAuthToCallback(authURL)
		failExchangeForCallback(env.idpA, cb)
		_, body := c.hitCallback(cb)
		if code := intFrom(body, "_status_code"); code != http.StatusServiceUnavailable {
			t.Fatalf("iteration %d expected 503, got %d %v", i, code, body)
		}
		tok = mustStr(body, "recovery_token")
		if i == 2 {
			break
		}
		_, rec, _ := c.postRecover(env, tok)
		authURL = mustStr(rec, "authorization_url")
		if authURL == "" {
			t.Fatalf("iteration %d recover failed: %v", i, rec)
		}
	}
	// 第三次暂时性失败后 attempts 已达 3，恢复被拒。
	st, b, _ := c.postRecover(env, tok)
	if st != http.StatusGone || b["error"] != "recovery_unavailable" {
		t.Fatalf("exhausted recover status=%d body=%v, want 410 recovery_unavailable", st, b)
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 0 {
		t.Fatalf("members=%d, want 0", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM auth_attempts WHERE status='exhausted'`); n != 1 {
		t.Fatalf("attempt should be exhausted")
	}
}

// TestOldAndNewCallbacksConcurrentNoDuplicateMember：
// 旧、新回调同时/乱序到达，绝不重复建成员、不回退已完成流程。
func TestOldAndNewCallbacksConcurrentNoDuplicateMember(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authURL := c.startLogin(env)
	cb1 := c.followAuthToCallback(authURL)
	failExchangeForCallback(env.idpA, cb1)
	_, body := c.hitCallback(cb1) // 旧请求消费 + 503
	tok := mustStr(body, "recovery_token")
	_, rec, _ := c.postRecover(env, tok)
	cb2 := c.followAuthToCallback(mustStr(rec, "authorization_url"))

	// 新回调成功；与此同时（乱序）旧回调重放 —— 并发各打一遍，重复多次。
	var wg sync.WaitGroup
	results := make(chan int, 6)
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); st, _ := c.hitCallback(cb2); results <- st }()
		go func() { defer wg.Done(); st, _ := c.hitCallback(cb1); results <- st }()
	}
	wg.Wait()
	close(results)
	var ok302, bad400 int
	for st := range results {
		switch st {
		case http.StatusFound:
			ok302++
		case http.StatusBadRequest:
			bad400++
		default:
			t.Fatalf("unexpected concurrent callback status=%d", st)
		}
	}
	if ok302 != 1 {
		t.Fatalf("exactly one callback should succeed (302), got %d (400s=%d)", ok302, bad400)
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 1 {
		t.Fatalf("members after concurrent callbacks=%d, want exactly 1", n)
	}
	if n := countRows(t, env, "SELECT count(*) FROM sessions"); n != 1 {
		t.Fatalf("sessions after concurrent callbacks=%d, want exactly 1", n)
	}
	// 成功后再恢复必须被拒（已完成流程不回退）。
	st, b, _ := c.postRecover(env, tok)
	if st != http.StatusGone {
		t.Fatalf("recover after success status=%d body=%v, want 410", st, b)
	}
}

// TestRecoverLinkHappyPath：账号关联在临时失败后用全新请求成功，
// 仍绑定原成员、原租户、原关联会话。
func TestRecoverLinkHappyPath(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	// A 身份登录（idpA）。
	authA := c.startLogin(env)
	cbA := c.followAuthToCallback(authA)
	if st, _ := c.hitCallback(cbA); st != http.StatusFound {
		t.Fatalf("login A failed")
	}
	memberID := memberIDFromMe(t, c, env)

	// 发起关联到 idpB，leg B 令牌端点临时失败一次。
	linkTok, recTok, linkURL := c.startLink(env, env.idpB.issuer())
	cbLink1 := c.followAuthToCallback(linkURL)
	failExchangeForCallback(env.idpB, cbLink1)
	st, body := c.hitCallback(cbLink1)
	if st != http.StatusServiceUnavailable ||
		body["error"] != "provider_temporarily_unavailable" {
		t.Fatalf("link transient failure status=%d body=%v, want 503", st, body)
	}

	// 恢复链接：仍需同一会话（本客户端持有 sid+aat），生成全新 leg B 请求。
	recStatus, recBody, _ := c.postRecover(env, recTok)
	if recStatus != http.StatusOK {
		t.Fatalf("link recover status=%d body=%v", recStatus, recBody)
	}
	newLinkURL := mustStr(recBody, "authorization_url")
	if newLinkURL == "" || newLinkURL == linkURL {
		t.Fatalf("link recovery must rotate request url")
	}
	cbLink2 := c.followAuthToCallback(newLinkURL)
	st2, body2 := c.hitCallback(cbLink2)
	if st2 != http.StatusOK || body2["status"] != "linked" {
		t.Fatalf("recovered link status=%d body=%v, want 200 linked", st2, body2)
	}

	// 成员名下有两条身份，且无跨租户/新成员产生。
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE tenant_id=$1 AND member_id=$2`,
		env.tenantID, memberID); n != 2 {
		t.Fatalf("identities on member after recovered link=%d, want 2", n)
	}
	// link_session 已完成、一次性；关联意图 succeeded。
	if n := countRows(t, env,
		`SELECT count(*) FROM link_sessions WHERE token=$1 AND status='consumed'`,
		linkTok); n != 1 {
		t.Fatalf("link session not consumed")
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM auth_attempts WHERE kind='link_b' AND status='succeeded'`); n != 1 {
		t.Fatalf("link attempt not succeeded")
	}
	// 旧链接 state 重放被拒。
	if stOld, bOld := c.hitCallback(cbLink1); stOld != http.StatusBadRequest ||
		bOld["error"] != "invalid_request" {
		t.Fatalf("old link callback status=%d body=%v, want 400", stOld, bOld)
	}
}

// TestRecoverLinkExpiredContextNotReopened：
// 关联上下文过期后，恢复入口不能把它重新打开（即使认证尝试本身还没到期）。
func TestRecoverLinkExpiredContextNotReopened(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authA := c.startLogin(env)
	if st, _ := c.hitCallback(c.followAuthToCallback(authA)); st != http.StatusFound {
		t.Fatalf("login A failed")
	}
	linkTok, recTok, linkURL := c.startLink(env, env.idpB.issuer())
	cb := c.followAuthToCallback(linkURL)
	initialBState := queryParam(cb, "state")
	failExchangeForCallback(env.idpB, cb)
	if st, _ := c.hitCallback(cb); st != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 transient")
	}

	// 只把关联会话改到过期（认证尝试仍未过期）。
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE link_sessions SET expires_at = now() - interval '1 second'
		 WHERE status='pending'`); err != nil {
		t.Fatalf("age link session: %v", err)
	}
	st, b, _ := c.postRecover(env, recTok)
	if st != http.StatusGone || b["error"] != "recovery_unavailable" {
		t.Fatalf("expired link recover status=%d body=%v, want 410", st, b)
	}
	// 过期关联没有被重开为有效 pending 会话。
	if n := countRows(t, env,
		`SELECT count(*) FROM link_sessions
		 WHERE status='pending' AND expires_at > now()`); n != 0 {
		t.Fatalf("expired link must not be reopened as a live pending session")
	}
	// 恢复被拒后：尝试终态化为 expired，attempts 不增加。
	var attempts int
	var status string
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT attempts, status FROM auth_attempts WHERE recovery_token_hash=$1`,
		sec.HashToken(recTok)).Scan(&attempts, &status); err != nil {
		t.Fatalf("load attempt: %v", err)
	}
	if attempts != 1 || status != "expired" {
		t.Fatalf("expired-link attempt attempts=%d status=%s, want 1/expired", attempts, status)
	}
	// b_state 未被恢复改绑：仍是发起时的初始 state（该请求已被消费），
	// 没有任何新具体请求被绑定进关联会话。
	var bState sql.NullString
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT b_state FROM link_sessions WHERE token=$1`, linkTok).Scan(&bState); err != nil {
		t.Fatalf("load link session: %v", err)
	}
	if bState.String != initialBState {
		t.Fatalf("expired link b_state was rotated during recovery: got %q want %q",
			bState.String, initialBState)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE issuer=$1`, env.idpB.issuer()); n != 0 {
		t.Fatalf("no B identity should be bound")
	}
}

// TestRecoverLinkRequiresOriginalSession：
// 另一个浏览器会话（不同 sid）不能恢复别人的链接尝试。
func TestRecoverLinkRequiresOriginalSession(t *testing.T) {
	env := startRecoverEnv(t)
	owner := newHTTPClient(t, false)
	authA := owner.startLogin(env)
	if st, _ := owner.hitCallback(owner.followAuthToCallback(authA)); st != http.StatusFound {
		t.Fatalf("login A failed")
	}
	_, recTok, linkURL := owner.startLink(env, env.idpB.issuer())
	cb := owner.followAuthToCallback(linkURL)
	failExchangeForCallback(env.idpB, cb)
	if st, _ := owner.hitCallback(cb); st != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 transient")
	}

	// 攻击者/第二个浏览器：有自己的 sid，但没有原始 sid；只能凭 body 拿到 token。
	attacker := newHTTPClient(t, false)
	// 攻击者先登录建立自己的会话。
	atkAuth := attacker.startLogin(env)
	if st, _ := attacker.hitCallback(attacker.followAuthToCallback(atkAuth)); st != http.StatusFound {
		t.Fatalf("attacker login failed")
	}
	st, b, _ := attacker.postRecover(env, recTok)
	if st != http.StatusUnauthorized {
		t.Fatalf("cross-session link recover status=%d body=%v, want 401", st, b)
	}
}

// ---------- helpers ----------

func intFrom(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return -1
}

// hashRow 用恢复令牌原文经应用同样的哈希查询尝试。
func hashRow(env *recoverEnv, t *testing.T, rawToken string, attempts *int, active *sql.NullString) {
	t.Helper()
	err := env.store.DB().QueryRow(context.Background(),
		`SELECT attempts, active_state FROM auth_attempts WHERE recovery_token_hash=$1`,
		sec.HashToken(rawToken)).Scan(attempts, active)
	if err != nil {
		t.Fatalf("query attempt by recovery hash: %v", err)
	}
}

func memberIDFromMe(t *testing.T, c *httpClient, env *recoverEnv) string {
	t.Helper()
	st, b := c.me(env)
	if st != http.StatusOK {
		t.Fatalf("me status=%d body=%v", st, b)
	}
	return mustStr(b, "member_id")
}
