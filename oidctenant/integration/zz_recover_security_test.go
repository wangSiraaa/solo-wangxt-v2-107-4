package integration

import (
	"net/http"
	"testing"
)

// TestUnknownRecoveryTokenIndistinguishable：未知/伪造恢复令牌返回
// 一致的 400 invalid_request，无法借此枚举有效尝试。
func TestUnknownRecoveryTokenIndistinguishable(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)
	for _, tok := range []string{"", "totally-made-up-token", "0123456789abcdef0123456789abcdef"} {
		st, b, _ := c.postRecover(env, tok)
		if st != http.StatusBadRequest || b["error"] != "invalid_request" {
			t.Fatalf("unknown token=%q status=%d body=%v, want 400 invalid_request", tok, st, b)
		}
	}
}

// TestRecoverViaBearerHeader：没有 cookie 的纯 API 客户端可用
// Authorization: Bearer 携带恢复令牌恢复（令牌绝不经 URL query）。
func TestRecoverViaBearerHeader(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)
	authURL := c.startLogin(env)
	cb := c.followAuthToCallback(authURL)
	failExchangeForCallback(env.idpA, cb)
	_, body := c.hitCallback(cb)
	tok := mustStr(body, "recovery_token")

	// 全新客户端（没有 aat cookie），仅凭 Bearer 头恢复。
	api := newHTTPClient(t, false)
	req, _ := http.NewRequest(http.MethodPost, env.baseURL+"/oauth/recover", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp := api.do(req)
	b := bodyMap(resp)
	if resp.StatusCode != http.StatusOK || mustStr(b, "authorization_url") == "" {
		t.Fatalf("bearer recover status=%d body=%v, want 200", resp.StatusCode, b)
	}
}

// TestIdPErrorCallbackIsPermanent：提供方在重定向里带 error（用户拒绝/登录失败）
// 是终态，不得给出恢复入口。
func TestIdPErrorCallbackIsPermanent(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)
	authURL := c.startLogin(env)
	cb := c.followAuthToCallback(authURL)
	// 把回调 URL 改写成带 error、去掉 code。
	errURL := env.baseURL + "/oauth/callback?state=" + queryParam(cb, "state") +
		"&error=access_denied"
	st, b := c.hitCallback(errURL)
	if st != http.StatusUnauthorized || b["error"] != "authentication_failed" {
		t.Fatalf("idp error callback status=%d body=%v, want 401 authentication_failed", st, b)
	}
	if b["recovery_token"] != nil {
		t.Fatalf("idp error callback must not offer recovery: %v", b)
	}
}

// TestOldCodeCannotPairWithRecoveredState：临时失败时旧授权码在 IdP 侧
// 其实还没被消费，但恢复轮换了 PKCE verifier；把旧码配到恢复后的新 state
// 上必须因 PKCE 不匹配被永久拒绝（重试绝不复用旧 code/PKCE）。
func TestOldCodeCannotPairWithRecoveredState(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)

	authURL := c.startLogin(env)
	cb1 := c.followAuthToCallback(authURL)
	oldCode := queryParam(cb1, "code")
	failExchangeForCallback(env.idpA, cb1) // code-0 在 IdP 侧仍有效（503 未消费）
	_, body := c.hitCallback(cb1)
	tok := mustStr(body, "recovery_token")

	_, rec, _ := c.postRecover(env, tok)
	newState := queryParam(mustStr(rec, "authorization_url"), "state")

	// 在走全新 /auth 拿新码之前，先拿“旧码 + 新 state”打回调。
	forged := env.baseURL + "/oauth/callback?state=" + newState + "&code=" + oldCode
	st, b := c.hitCallback(forged)
	if st != http.StatusUnauthorized || b["error"] != "authentication_failed" {
		t.Fatalf("old code + recovered state status=%d body=%v, want 401 (PKCE rotation)", st, b)
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 0 {
		t.Fatalf("members=%d, want 0", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM auth_attempts WHERE status='failed_permanent'`); n != 1 {
		t.Fatalf("attempt must be permanently failed after PKCE-mismatched code reuse")
	}
}
