package integration

// 本文件提供一个“可编程的假 OIDC IdP”，用真实 RS256 签名、真实 discovery/JWKS、
// 真实授权码 + PKCE + nonce 流程驱动真应用 + 真 PostgreSQL，
// 从而在不依赖外部 Keycloak 的情况下做可恢复认证尝试的端到端验收。
//
// 关键可控开关：
//   - failNextToken(n)：接下来 n 次 /token 返回暂时性错误（默认 503），随后自动恢复；
//   - setWrongKey(true)：用不在 JWKS 里的私钥签名（永久签名失败）；
//   - setWrongNonce / setOmitNonce：构造 nonce 永久失败；
//   - setAuthorizeError：让授权直接以 OIDC error 参数回调。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	gojose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/api"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

type issuedCode struct {
	redirectURI string
	nonce       string
	subject     string
	email       string
	authTime    time.Time
	used        bool
	challenge   string // S256 code_challenge，/token 时校验 code_verifier
}

// fakeIdP 是最小可用 OIDC provider。
type fakeIdP struct {
	t        *testing.T
	srv      *httptest.Server
	signer   gojose.Signer
	other    gojose.Signer
	clientID string
	iss      string

	mu            sync.Mutex
	codes         map[string]*issuedCode
	failTokenN    int
	failStatus    int
	tokenHits     int
	tokenResults  []string
	wrongKey      bool
	wrongNonce    bool
	omitNonce     bool
	authorizeHook func(q url.Values) string
	subject       string
	email         string
}

func startFakeIdP(t *testing.T, subject, email string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen other rsa: %v", err)
	}
	kid := "fake-kid"
	var opts gojose.SignerOptions
	opts.WithHeader(gojose.HeaderKey("kid"), kid)
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key}, &opts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	var evilOpts gojose.SignerOptions
	evilOpts.WithHeader(gojose.HeaderKey("kid"), kid)
	evilSigner, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: other}, &evilOpts)
	if err != nil {
		t.Fatalf("evil signer: %v", err)
	}

	jwk := gojose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig"}
	idp := &fakeIdP{
		t: t, signer: signer, other: evilSigner, clientID: "fake-client",
		codes: map[string]*issuedCode{}, failStatus: http.StatusServiceUnavailable,
		subject: subject, email: email,
	}
	idp.authorizeHook = func(url.Values) string { return "" }

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
		}`, idp.issVal(), idp.issVal()+"/auth", idp.issVal()+"/token", idp.issVal()+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/auth", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	idp.iss = idp.srv.URL
	return idp
}

func (p *fakeIdP) issVal() string { return p.srv.URL }

// handleAuthorize 模拟“用户已登录”，直接 302 回 redirect_uri 带 code/state。
func (p *fakeIdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if p.authorizeHook != nil {
		if hook := p.authorizeHook(q); hook != "" {
			http.Redirect(w, r, hook, http.StatusFound)
			return
		}
	}
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	code := "code-" + randCode()
	p.mu.Lock()
	p.codes[code] = &issuedCode{
		redirectURI: redirect, nonce: q.Get("nonce"),
		subject: p.subject, email: p.email, authTime: time.Now(),
		challenge: q.Get("code_challenge"),
	}
	p.mu.Unlock()
	u, _ := url.Parse(redirect)
	rq := u.Query()
	rq.Set("state", state)
	rq.Set("code", code)
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleToken 校验授权码（一次性），用私钥签发带正确 nonce 的 id_token。
func (p *fakeIdP) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	code := form.Get("code")

	p.mu.Lock()
	p.tokenHits++
	if p.failTokenN > 0 {
		p.failTokenN--
		status := p.failStatus
		p.tokenResults = append(p.tokenResults, fmt.Sprintf("#%d fail(%d) code=%s", p.tokenHits, status, code))
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusTooManyRequests {
			_, _ = w.Write([]byte(`{"error":"slow_down"}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		}
		return
	}
	rec := p.codes[code]
	// 真实 PKCE(S256) 与 redirect_uri 校验：未知码/已用码/错配一律 invalid_grant。
	if rec == nil || rec.used ||
		form.Get("redirect_uri") != rec.redirectURI ||
		!pkceMatches(rec.challenge, form.Get("code_verifier")) {
		p.tokenResults = append(p.tokenResults, fmt.Sprintf("#%d invalid_grant code=%s", p.tokenHits, code))
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	rec.used = true
	p.tokenResults = append(p.tokenResults, fmt.Sprintf("#%d ok code=%s", p.tokenHits, code))
	nonce := rec.nonce
	subject, email, authTime := rec.subject, rec.email, rec.authTime
	wrongKey, wrongNonce, omitNonce := p.wrongKey, p.wrongNonce, p.omitNonce
	p.mu.Unlock()

	idToken := p.issueIDToken(nonce, subject, email, authTime, wrongKey, wrongNonce, omitNonce)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "fake-access", "token_type": "Bearer",
		"expires_in": "3600", "id_token": idToken,
	})
}

func (p *fakeIdP) issueIDToken(nonce, subject, email string, authTime time.Time,
	wrongKey, wrongNonce, omitNonce bool) string {
	now := time.Now()
	claims := map[string]any{
		"iss": p.issVal(), "aud": p.clientID, "sub": subject,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
		"email": email, "email_verified": true, "auth_time": authTime.Unix(),
	}
	if !omitNonce {
		if wrongNonce {
			claims["nonce"] = "attacker-nonce"
		} else {
			claims["nonce"] = nonce
		}
	}
	raw, _ := json.Marshal(claims)
	signer := p.signer
	if wrongKey {
		signer = p.other
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		p.t.Fatalf("sign id token: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		p.t.Fatalf("serialize: %v", err)
	}
	return compact
}

// ---- 可编程开关（测试用） ----

func (p *fakeIdP) failNextToken(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failTokenN = n
}

func (p *fakeIdP) setFailStatus(s int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failStatus = s
}
func (p *fakeIdP) setWrongKey(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wrongKey = v
}
func (p *fakeIdP) setWrongNonce(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wrongNonce = v
}
func (p *fakeIdP) setOmitNonce(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.omitNonce = v
}

// setAuthorizeError 让授权直接以 OIDC error 参数回调。
func (p *fakeIdP) setAuthorizeError(errorCode string) {
	p.authorizeHook = func(q url.Values) string {
		redirect := q.Get("redirect_uri")
		state := q.Get("state")
		u, _ := url.Parse(redirect)
		rq := u.Query()
		rq.Set("state", state)
		rq.Set("error", errorCode)
		u.RawQuery = rq.Encode()
		return u.String()
	}
}

func randCode() string {
	s := uuid.NewString()
	bs := []byte(s)
	out := make([]byte, 0, 24)
	for _, c := range bs {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') {
			out = append(out, c)
		}
		if len(out) == 24 {
			break
		}
	}
	return string(out)
}

// pkceMatches 校验 S256：BASE64URL(SHA256(verifier)) 必须等于授权时登记的 challenge。
func pkceMatches(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

// ---- 独立应用 + 嵌入式 PG（不依赖 Keycloak、不占用固定 18080 端口） ----

type resumeEnv struct {
	t        *testing.T
	pg       *embedded.EmbeddedPostgres
	store    *store.Store
	baseURL  string
	idp      *fakeIdP
	tenantID uuid.UUID
	srv      *http.Server
	cfg      *config.Config
}

func startResumeEnv(t *testing.T, idp *fakeIdP, ttl time.Duration) *resumeEnv {
	t.Helper()
	pgPort := freeTCPPort(t)
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Version(embedded.V16).
		Port(pgPort).
		Database("oidctenant").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}

	dsn := formatDSN(pgPort, "oidctenant")
	ctx := context.Background()
	database, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(database)

	tenantID := uuid.MustParse("00000000-0000-0000-0000-0000000000c1")
	providerID := uuid.MustParse("00000000-0000-0000-0000-0000000000c2")
	if err := st.UpsertTenant(ctx, tenantID, "acme", "Acme Corp"); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	appPort := freeTCPPort(t)
	base := fmt.Sprintf("http://localhost:%d", appPort)
	if err := st.UpsertProvider(ctx, &models.Provider{
		ID: providerID, TenantID: tenantID, Issuer: idp.issVal(),
		ClientID: "fake-client", ClientSecret: "fake-secret",
		RedirectURIs:   []string{base + "/oauth/callback", base + "/oauth/link/callback"},
		AuthTimeMaxAge: 300, Enabled: true,
	}); err != nil {
		t.Fatalf("provider: %v", err)
	}

	cfg := &config.Config{
		DatabaseURL: dsn, BaseURL: base, Addr: fmt.Sprintf(":%d", appPort),
		SessionTTL: time.Hour, LinkTTL: ttl, AuthRequestTTL: ttl,
		AttemptMaxRetries: 3, CookieSecure: false, CookieSameSite: "lax",
	}
	env := &resumeEnv{
		t: t, pg: pg, store: st, baseURL: base, idp: idp, tenantID: tenantID, cfg: cfg,
	}
	env.srv = &http.Server{
		Addr: cfg.Addr,
		Handler: api.NewServer(cfg, st, oidcx.NewManager(),
			log.New(os.Stderr, "[app] ", 0)).Routes(),
	}
	go func() { _ = env.srv.ListenAndServe() }()
	waitReady(t, base+"/healthz")

	t.Cleanup(func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = env.srv.Shutdown(shCtx)
		database.Close()
		_ = pg.Stop()
	})
	return env
}

// restart 模拟服务重启：关闭 HTTP 层并以全新 api.Server（清空进程内 OIDC 缓存）
// 监听同一地址；数据库（含意图/请求/关联）保持不变。
func (env *resumeEnv) restart(t *testing.T) {
	t.Helper()
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := env.srv.Shutdown(shCtx); err != nil {
		t.Fatalf("shutdown for restart: %v", err)
	}
	env.srv = &http.Server{
		Addr: env.cfg.Addr,
		Handler: api.NewServer(env.cfg, env.store, oidcx.NewManager(),
			log.New(os.Stderr, "[app] ", 0)).Routes(),
	}
	go func() { _ = env.srv.ListenAndServe() }()
	waitReady(t, env.baseURL+"/healthz")
}

func discardLogger() *log.Logger { return log.New(os.Stdout, "[resume-test] ", log.LstdFlags) }
