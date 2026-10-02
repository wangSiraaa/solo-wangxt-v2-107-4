package integration

import (
	"net/http"
	"strings"
	"testing"
)

// TestRecoverResponseDoesNotLeakSecrets：503 恢复入口只暴露可操作的
// 恢复令牌/入口/计数，绝不回显授权码、state、nonce、PKCE 或令牌。
func TestRecoverResponseDoesNotLeakSecrets(t *testing.T) {
	env := startRecoverEnv(t)
	c := newHTTPClient(t, false)
	authURL := c.startLogin(env)
	cb := c.followAuthToCallback(authURL)
	failExchangeForCallback(env.idpA, cb)
	st, body := c.hitCallback(cb)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", st)
	}
	for _, secret := range []string{"code", "state", "nonce", "verifier", "id_token", "access_token"} {
		if _, present := body[secret]; present {
			t.Fatalf("503 body leaks %q: %v", secret, body)
		}
	}
	if mustStr(body, "recovery_token") == "" || mustStr(body, "recover_url") == "" {
		t.Fatalf("missing actionable recovery entry: %v", body)
	}
	// 任何字段都不得包含本次授权码原文（recovery_token 是独立随机值）。
	code := queryParam(cb, "code")
	for k, v := range body {
		if s, ok := v.(string); ok && strings.Contains(s, code) {
			t.Fatalf("field %q leaks authorization code", k)
		}
	}
}
