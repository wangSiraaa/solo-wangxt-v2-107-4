package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
)

// mockIdP 是一个最小但真实的 OIDC 提供方（发现/JWKS/授权/令牌端点），
// 用测试私钥自签 ID token，应用侧走完整 go-oidc 校验链路。
//
// 它支持精确的故障注入（无需外部 Keycloak）：
//   - tokenFailOnce：令牌端点下一次请求返回 503（暂时性）；
//   - tokenStatusFor(code)：按授权码返回固定状态（如 500 暂时性 / 400 永久）；
//   - discoveryFailUntil：发现端点在截止时间前返回 500；
//   - badSignKey：用另一把私钥签发（签名永久失败）；
//   - tokenClaimsMutator：在签发前篡改 claims（如错误 nonce）。
type mockIdP struct {
	srv       *httptest.Server
	signer    gojose.Signer
	badSigner gojose.Signer
	privKey   *rsa.PrivateKey
	kid       string
	clientID  string
	// defaultSubject 是未带 subject_hint 时发码使用的主体。
	defaultSubject string
	defaultEmail   string

	mu sync.Mutex
	// tokenFailCode + tokenFailHits：指定 code 的接下来 tokenFailHits 次
	// 令牌交换返回 503（oauth2 一轮有 Basic/body 两次探测，故置 2）。
	// code 被成功消费后该标记失效，因此恢复后旧码重放只会得到 invalid_grant。
	tokenFailCode     string
	tokenFailHits     int
	tokenFailUntil    time.Time
	tokenStatusByCode map[string]int
	discUntil         time.Time
	jwksUntil         time.Time
	badSignKey        bool
	mutator           func(claims map[string]any)
	codes             map[string]pendingCode
}

type pendingCode struct {
	RedirectURI  string
	CodeVerifier string // 期望的 S256 challenge（由 /auth 记下 state→challenge）
	Nonce        string
	Subject      string
	Email        string
	AuthTime     time.Time
}

func startMockIdP(t testingTB, clientID string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	const kid = "mock-kid-1"
	opts := (&gojose.SignerOptions{}).WithHeader(gojose.HeaderKey("kid"), kid)
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	badOpts := (&gojose.SignerOptions{}).WithHeader(gojose.HeaderKey("kid"), kid)
	badSigner, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: other}, badOpts)
	if err != nil {
		t.Fatalf("new bad signer: %v", err)
	}

	idp := &mockIdP{
		signer: signer, badSigner: badSigner, privKey: key, kid: kid,
		clientID:          clientID,
		defaultSubject:    "mock-subject-1",
		defaultEmail:      "mock@example.test",
		tokenStatusByCode: map[string]int{},
		codes:             map[string]pendingCode{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", idp.discovery)
	mux.HandleFunc("/jwks", idp.jwks)
	mux.HandleFunc("/auth", idp.authEndpoint)
	mux.HandleFunc("/token", idp.tokenEndpoint)
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// testingTB 让模拟 IdP 同时可被 *testing.T 与其他辅助使用。
type testingTB interface {
	Helper()
	Cleanup(func())
	Fatalf(format string, args ...any)
}

func (p *mockIdP) issuer() string { return p.srv.URL }

// failNextTokenExchangeForCode 让指定授权码的下一轮令牌交换（oauth2 会发
// Basic 与 body 两次认证探测）持续返回 503；探测结束/窗口过期后恢复正常。
// 旧 code 一旦被成功消费即从记录中移除，因此恢复后重放旧码只会得到
// invalid_grant，而不会再次命中暂时性故障。
func (p *mockIdP) failNextTokenExchangeForCode(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenFailCode = code
	p.tokenFailHits = 2 // Basic 探测 + body 探测
	p.tokenFailUntil = time.Now().Add(5 * time.Second)
}

// setTokenFailOnce 在已知 code 前可使用的便捷注入（兼容旧调用）。
func (p *mockIdP) setTokenFailOnce() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenFailUntil = time.Now().Add(500 * time.Millisecond)
}

// setCodeStatus：指定 code 的令牌交换返回固定 HTTP 状态。
func (p *mockIdP) setCodeStatus(code string, status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenStatusByCode[code] = status
}

// failDiscoveryFor：发现端点在 d 内返回 500。
func (p *mockIdP) failDiscoveryFor(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discUntil = time.Now().Add(d)
}

// failJWKSFor：JWKS 端点在 d 内返回 500。
func (p *mockIdP) failJWKSFor(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.jwksUntil = time.Now().Add(d)
}

// useBadSigningKey：后续签发的 ID token 使用不在 JWKS 中的私钥（签名永久失败）。
func (p *mockIdP) useBadSigningKey() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.badSignKey = true
}

// mutateClaims：签发前篡改 claims（如改 nonce）。
func (p *mockIdP) mutateClaims(f func(claims map[string]any)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mutator = f
}

func (p *mockIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	failing := time.Now().Before(p.discUntil)
	p.mu.Unlock()
	if failing {
		http.Error(w, "discovery unavailable", http.StatusInternalServerError)
		return
	}
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
	}`, p.issuer(), p.issuer()+"/auth", p.issuer()+"/token", p.issuer()+"/jwks")
}

func (p *mockIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	failing := time.Now().Before(p.jwksUntil)
	p.mu.Unlock()
	if failing {
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	jwk := gojose.JSONWebKey{
		Key: &p.privKey.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}})
}

// authEndpoint 模拟 IdP 的授权端点：直接发码并 302 回 redirect_uri
// （测试无需交互式登录页）。记录 code_challenge/nonce 供 /token 校验。
func (p *mockIdP) authEndpoint(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	code := randomB64(16)
	subject := q.Get("subject_hint")
	if subject == "" {
		subject = p.defaultSubject
	}
	email := p.defaultEmail
	if email == "" {
		email = "mock@example.test"
	}
	p.mu.Lock()
	// code_challenge 在交换时与 code_verifier 的 S256 比对；nonce 原样进 ID token。
	p.codes[code] = pendingCode{
		RedirectURI: redirectURI, CodeVerifier: challenge, Nonce: nonce,
		AuthTime: time.Now(), Subject: subject, Email: email,
	}
	p.mu.Unlock()

	u, _ := url.Parse(redirectURI)
	qq := u.Query()
	qq.Set("code", code)
	qq.Set("state", state)
	u.RawQuery = qq.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

func (p *mockIdP) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.PostForm.Get("code")
	verifier := r.PostForm.Get("code_verifier")

	p.mu.Lock()
	pc, ok := p.codes[code]
	// 暂时性故障只对“仍在记录中且仍有失败配额”的 code 生效：
	// 恢复后旧 code 已被成功消费删除，重放得到的是 invalid_grant 而非再次 503。
	failingByCode := false
	if ok && p.tokenFailCode == code && p.tokenFailHits > 0 &&
		time.Now().Before(p.tokenFailUntil) {
		failingByCode = true
		p.tokenFailHits--
	}
	// failingByTime 保留语义占位：时间窗只作为 code 级配额上限。
	failingByTime := false
	// 注入状态持续生效（覆盖 Basic/body 两次认证探测），由测试在用例结束时
	// 随 mock 一起丢弃；不在此删除，避免第二次探测绕过注入。
	injectedStatus, hasInjected := p.tokenStatusByCode[code]
	if hasInjected {
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(injectedStatus)
		if injectedStatus == http.StatusTooManyRequests || injectedStatus >= 500 {
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}
		return
	}
	badSign := p.badSignKey
	mutator := p.mutator
	p.mu.Unlock()

	// 接受 Basic（oauth2 默认探测方式）或 body 形式的客户端认证。
	cid, csecret, _ := r.BasicAuth()
	if cid == "" {
		cid = r.PostForm.Get("client_id")
		csecret = r.PostForm.Get("client_secret")
	}
	if cid != p.clientID || csecret != clientSecretOf(cid) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}

	if failingByCode || failingByTime {
		http.Error(w, `{"error":"temporarily_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if !ok {
		// 授权码已消费或伪造：与真实 IdP 一致返回 invalid_grant（不消费任何东西）。
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	// PKCE：S256(code_verifier) 必须等于授权时记下的 challenge。
	// PKCE 不通过时不消费 code 以外的状态（真实 IdP 在授权码策略上各异；
	// 这里保持 code 仍在以便客户端认证探测重试不污染语义）。
	if s256B64(verifier) != pc.CodeVerifier {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code_verifier mismatch"}`))
		return
	}

	// 授权码一次性：只有走到这里（客户端认证 + PKCE 全部通过）才消费。
	p.mu.Lock()
	delete(p.codes, code)
	if p.tokenFailCode == code {
		p.tokenFailCode = ""
	}
	p.mu.Unlock()

	claims := map[string]any{
		"iss":            p.issuer(),
		"aud":            p.clientID,
		"azp":            p.clientID,
		"sub":            pc.Subject,
		"nonce":          pc.Nonce,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(5 * time.Minute).Unix(),
		"email":          pc.Email,
		"email_verified": true,
		"name":           "Mock User",
		"auth_time":      pc.AuthTime.Unix(),
	}
	if mutator != nil {
		mutator(claims)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signer := p.signer
	if badSign {
		signer = p.badSigner
	}
	obj, err := signer.Sign(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idToken, err := obj.CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "mock-access",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func s256B64(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// clientSecretOf 返回测试 client 的密钥（与 seed 配置一致）。
func clientSecretOf(clientID string) string {
	switch clientID {
	case "rp-a":
		return "rp-a-secret"
	case "rp-b":
		return "rp-b-secret"
	}
	return ""
}
