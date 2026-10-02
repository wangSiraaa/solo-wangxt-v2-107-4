package oidcx_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"

	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
)

// 本测试不依赖外部 IdP：本地起最小 OIDC 发现 + JWKS 服务，
// 用测试私钥自行签发 ID token，从而精确构造
// 签名/受众/nonce/过期/issuer 等被拒场景。

type testIdP struct {
	srv      *httptest.Server
	signer   gojose.Signer
	otherKey *rsa.PrivateKey // 用于构造“错误签名”令牌
	clientID string
}

func (p *testIdP) issuer() string { return p.srv.URL }

func startTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen other rsa: %v", err)
	}
	const kid = "test-kid-1"
	var signerOpts gojose.SignerOptions
	signerOpts.WithHeader(gojose.HeaderKey("kid"), kid)
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key}, &signerOpts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	idp := &testIdP{signer: signer, otherKey: other, clientID: "test-client"}

	jwk := gojose.JSONWebKey{
		Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
		  "issuer": %q,
		  "authorization_endpoint": %q,
		  "token_endpoint": %q,
		  "jwks_uri": %q,
		  "id_token_signing_alg_values_supported": ["RS256"],
		  "response_types_supported": ["code"],
		  "subject_types_supported": ["public"],
		  "code_challenge_methods_supported": ["S256"]
		}`, idp.issuer(), idp.issuer()+"/auth", idp.issuer()+"/token", idp.issuer()+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

type tokenInput struct {
	Issuer   string
	Audience any
	Subject  string
	Nonce    string
	IssuedAt time.Time
	Expiry   time.Time
}

// issue 用 IdP 正常私钥签发。
func (p *testIdP) issue(t *testing.T, in tokenInput) string {
	t.Helper()
	return p.signWith(t, p.signer, in)
}

// issueWithWrongKey 用一把不在 JWKS 中的私钥签发（模拟伪造/被吊销密钥）。
func (p *testIdP) issueWithWrongKey(t *testing.T, in tokenInput) string {
	t.Helper()
	var evilOpts gojose.SignerOptions
	evilOpts.WithHeader(gojose.HeaderKey("kid"), "test-kid-1") // 伪装成合法 kid
	evil, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: p.otherKey}, &evilOpts)
	if err != nil {
		t.Fatalf("evil signer: %v", err)
	}
	return p.signWith(t, evil, in)
}

func (p *testIdP) signWith(t *testing.T, signer gojose.Signer, in tokenInput) string {
	t.Helper()
	aud := in.Audience
	if aud == nil {
		aud = p.clientID
	}
	claims := map[string]any{
		"iss":            in.Issuer,
		"aud":            aud,
		"sub":            in.Subject,
		"nonce":          in.Nonce,
		"iat":            in.IssuedAt.Unix(),
		"exp":            in.Expiry.Unix(),
		"email":          "x@example.com",
		"email_verified": true,
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sig, err := signer.Sign(cb)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	return raw
}

func newManagerProvider(iss string) (*oidcx.Manager, *models.Provider) {
	return oidcx.NewManager(), &models.Provider{
		Issuer:       iss,
		ClientID:     "test-client",
		ClientSecret: "secret",
		RedirectURIs: []string{"http://localhost/cb"},
		Enabled:      true,
	}
}

// TestVerifyValidToken 基线：合法签名、受众、issuer、未过期、nonce 匹配 -> 通过。
func TestVerifyValidToken(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	ver, err := mgr.Verifier(context.Background(), p, "correct-nonce")
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	now := time.Now()
	raw := idp.issue(t, tokenInput{
		Issuer: idp.issuer(), Subject: "user-1", Nonce: "correct-nonce",
		IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour),
	})
	claims, err := ver.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "x@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

// TestVerifyRejectsBadNonce 证明 nonce 必须与授权请求一致。
func TestVerifyRejectsBadNonce(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	ver, _ := mgr.Verifier(context.Background(), p, "expected-nonce")
	now := time.Now()
	raw := idp.issue(t, tokenInput{
		Issuer: idp.issuer(), Subject: "u", Nonce: "attacker-nonce",
		IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour),
	})
	_, err := ver.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("token with wrong nonce accepted")
	}
	ve, ok := oidcx.AsVerifyError(err)
	if !ok || ve.Kind != oidcx.KindNonce {
		t.Fatalf("wrong nonce error kind=%v err=%v", ve, err)
	}
}

// TestVerifyRejectsBadAudience 证明受众必须包含本 client_id。
func TestVerifyRejectsBadAudience(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	ver, _ := mgr.Verifier(context.Background(), p, "n")
	now := time.Now()
	raw := idp.issue(t, tokenInput{
		Issuer: idp.issuer(), Subject: "u", Nonce: "n", Audience: "some-other-client",
		IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour),
	})
	_, err := ver.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("token for another audience accepted")
	}
	ve, ok := oidcx.AsVerifyError(err)
	if !ok || ve.Kind != oidcx.KindAudience {
		t.Fatalf("bad audience error kind=%v err=%v", ve, err)
	}
}

// TestVerifyRejectsExpired 证明过期 token 被拒。
func TestVerifyRejectsExpired(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	ver, _ := mgr.Verifier(context.Background(), p, "n")
	now := time.Now()
	raw := idp.issue(t, tokenInput{
		Issuer: idp.issuer(), Subject: "u", Nonce: "n",
		IssuedAt: now.Add(-2 * time.Hour), Expiry: now.Add(-time.Hour),
	})
	_, err := ver.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("expired token accepted")
	}
	ve, ok := oidcx.AsVerifyError(err)
	if !ok || ve.Kind != oidcx.KindExpired {
		t.Fatalf("expired error kind=%v err=%v", ve, err)
	}
}

// TestVerifyRejectsWrongIssuer 证明 issuer 不匹配被拒（go-oidc 按 discovery issuer 校验）。
func TestVerifyRejectsWrongIssuer(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	ver, _ := mgr.Verifier(context.Background(), p, "n")
	now := time.Now()
	raw := idp.issue(t, tokenInput{
		Issuer: "https://evil.example.test", Subject: "u", Nonce: "n",
		IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour),
	})
	if _, err := ver.Verify(context.Background(), raw); err == nil {
		t.Fatal("token with spoofed issuer accepted")
	}
}

// TestVerifyRejectsBadSignature 证明用不在 JWKS 中的密钥签名会被拒绝。
func TestVerifyRejectsBadSignature(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	ver, _ := mgr.Verifier(context.Background(), p, "n")
	now := time.Now()
	raw := idp.issueWithWrongKey(t, tokenInput{
		Issuer: idp.issuer(), Subject: "u", Nonce: "n",
		IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour),
	})
	_, err := ver.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("token signed by an untrusted key accepted")
	}
	ve, ok := oidcx.AsVerifyError(err)
	if !ok {
		t.Fatalf("untrusted key error not a VerifyError: %v", err)
	}
	if ve.Kind != oidcx.KindSignature {
		t.Fatalf("untrusted key error kind=%v, want signature", ve.Kind)
	}
}

// TestPermanentVerifyFailuresNotTemporary 证明所有密码学/协议永久失败
// 都不会被标记为可恢复。
func TestPermanentVerifyFailuresNotTemporary(t *testing.T) {
	idp := startTestIdP(t)
	mgr, p := newManagerProvider(idp.issuer())
	now := time.Now()
	cases := []struct {
		name string
		raw  string
		kind oidcx.VerifyKind
	}{
		{"bad_nonce", idp.issue(t, tokenInput{
			Issuer: idp.issuer(), Subject: "u", Nonce: "other",
			IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour)}), oidcx.KindNonce},
		{"bad_audience", idp.issue(t, tokenInput{
			Issuer: idp.issuer(), Subject: "u", Nonce: "n", Audience: "other-c",
			IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour)}), oidcx.KindAudience},
		{"expired", idp.issue(t, tokenInput{
			Issuer: idp.issuer(), Subject: "u", Nonce: "n",
			IssuedAt: now.Add(-2 * time.Hour), Expiry: now.Add(-time.Hour)}), oidcx.KindExpired},
		{"bad_signature", idp.issueWithWrongKey(t, tokenInput{
			Issuer: idp.issuer(), Subject: "u", Nonce: "n",
			IssuedAt: now.Add(-time.Minute), Expiry: now.Add(time.Hour)}), oidcx.KindSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver, _ := mgr.Verifier(context.Background(), p, "n")
			_, err := ver.Verify(context.Background(), tc.raw)
			ve, ok := oidcx.AsVerifyError(err)
			if !ok {
				t.Fatalf("not a VerifyError: %v", err)
			}
			if ve.Temporary {
				t.Fatalf("%s must not be recoverable", tc.name)
			}
			if ve.Kind != tc.kind {
				t.Fatalf("%s kind=%s want %s", tc.name, ve.Kind, tc.kind)
			}
		})
	}
}

// startTokenOnlyIdP 起一个只含发现文档与令牌端点的最小 IdP，
// 令牌响应由 tokenHandler 决定；返回 issuer 基址。
func startTokenOnlyIdP(t *testing.T, tokenHandler http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
		  "issuer": %q,
		  "authorization_endpoint": %q,
		  "token_endpoint": %q,
		  "jwks_uri": %q,
		  "id_token_signing_alg_values_supported": ["RS256"],
		  "response_types_supported": ["code"],
		  "subject_types_supported": ["public"],
		  "code_challenge_methods_supported": ["S256"]
		}`, srv.URL, srv.URL+"/auth", srv.URL+"/token", srv.URL+"/jwks")
	})
	mux.HandleFunc("/token", tokenHandler)
	return srv.URL
}

// TestExchangeFailureClassification 验证令牌端点失败的恢复语义：
// 5xx/429 暂时性可恢复；400 invalid_grant（重放码/PKCE）永久不可恢复。
func TestExchangeFailureClassification(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		temporary bool
		wantKind  oidcx.VerifyKind
	}{
		{"503", http.StatusServiceUnavailable, `{"error":"server_error"}`, true, oidcx.KindProviderUnavailable},
		{"500", http.StatusInternalServerError, `{"error":"server_error"}`, true, oidcx.KindProviderUnavailable},
		{"429", http.StatusTooManyRequests, `{"error":"slow_down"}`, true, oidcx.KindProviderUnavailable},
		{"400 invalid_grant", http.StatusBadRequest, `{"error":"invalid_grant"}`, false, oidcx.KindPKCE},
		{"400 pkce", http.StatusBadRequest, `{"error":"invalid_grant","error_description":"code_verifier"}`,
			false, oidcx.KindPKCE},
		{"401", http.StatusUnauthorized, `{"error":"invalid_client"}`, false, oidcx.KindExchange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iss := startTokenOnlyIdP(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			mgr, p := newManagerProvider(iss)
			cfg, err := mgr.OAuth2Config(context.Background(), p, "http://localhost/cb")
			if err != nil {
				t.Fatalf("oauth config: %v", err)
			}
			ver, err := mgr.Verifier(context.Background(), p, "n")
			if err != nil {
				t.Fatalf("verifier: %v", err)
			}
			_, _, xerr := mgr.ExchangeAndVerify(context.Background(), p, cfg, ver, "some-code", "verifier")
			ve, ok := oidcx.AsVerifyError(xerr)
			if !ok {
				t.Fatalf("expected VerifyError, got %v", xerr)
			}
			if ve.Temporary != tc.temporary {
				t.Fatalf("temporary=%v want %v (kind=%s)", ve.Temporary, tc.temporary, ve.Kind)
			}
			if ve.Kind != tc.wantKind {
				t.Fatalf("kind=%s want %s", ve.Kind, tc.wantKind)
			}
		})
	}
}

// TestDiscoveryFailureIsTemporary 验证发现文档暂时拉不到时为可恢复分类。
func TestDiscoveryFailureIsTemporary(t *testing.T) {
	// 指向一个立即关闭的服务器地址：连接被拒属暂时性网络故障。
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	mgr, p := newManagerProvider(srv.URL)
	if _, err := mgr.OAuth2Config(context.Background(), p, "http://localhost/cb"); err == nil {
		t.Fatal("expected discovery failure")
	} else if ve, ok := oidcx.AsVerifyError(err); !ok || !ve.Temporary {
		t.Fatalf("discovery failure should be temporary, err=%v", err)
	}
}
