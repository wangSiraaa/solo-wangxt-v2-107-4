package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/oidctenant/internal/api"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

// recoverEnv 是不依赖外部 Keycloak 的端到端环境：
// 进程内 PostgreSQL + 进程内模拟 IdP + 真实应用（走完整 OIDC 校验链路）。
type recoverEnv struct {
	t        *testing.T
	pg       *embedded.EmbeddedPostgres
	store    *store.Store
	cfg      *config.Config
	baseURL  string
	tenantID uuid.UUID
	idpA     *mockIdP
	idpB     *mockIdP
	httpd    *http.Server
}

// DB 返回连接池（供通用断言辅助使用）。
func (e *recoverEnv) DB() *pgxpool.Pool { return e.store.DB() }

// restartServer 关闭并在同一数据库上重建应用 HTTP 服务（进程重启等价物）：
// OIDC 发现缓存、内存状态全部清空，仅持久化数据保留。
func (e *recoverEnv) restartServer(t *testing.T) {
	t.Helper()
	shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := e.httpd.Shutdown(shCtx); err != nil {
		t.Fatalf("shutdown before restart: %v", err)
	}
	cancel()
	srv := &http.Server{
		Addr: e.cfg.Addr,
		Handler: api.NewServer(e.cfg, e.store, oidcx.NewManager(),
			log.New(os.Stdout, "[rec-restart] ", log.LstdFlags|log.Lmicroseconds)).Routes(),
	}
	e.httpd = srv
	go func() { _ = srv.ListenAndServe() }()
	waitReady(t, e.baseURL+"/healthz")
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	return uint32(port.Port)
}

func startRecoverEnv(t *testing.T) *recoverEnv {
	t.Helper()
	pgPort := freePort(t)
	appPort := freePort(t)
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(pgPort).
		Database("oidctenant").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	dsn := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/oidctenant?sslmode=disable", pgPort)
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
	idpAID := uuid.MustParse("00000000-0000-0000-0000-0000000000c2")
	idpBID := uuid.MustParse("00000000-0000-0000-0000-0000000000c3")
	baseURL := fmt.Sprintf("http://localhost:%d", appPort)
	loginCB := baseURL + "/oauth/callback"
	linkCB := baseURL + "/oauth/link/callback"

	env := &recoverEnv{
		t: t, pg: pg, store: st, baseURL: baseURL, tenantID: tenantID,
	}
	// IdP 必须在 seed 前启动（seed 只存配置，不发起发现，先后无强依赖，但保持清晰）。
	env.idpA = startMockIdP(t, "rp-a")
	env.idpA.defaultSubject = "user-a"
	env.idpA.defaultEmail = "a@example.test"
	env.idpB = startMockIdP(t, "rp-b")
	env.idpB.defaultSubject = "user-b"
	env.idpB.defaultEmail = "b@example.test"

	if err := st.UpsertTenant(ctx, tenantID, "acme", "Acme Corp"); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	for _, p := range []models.Provider{
		{
			ID: idpAID, TenantID: tenantID,
			Issuer: env.idpA.issuer(), ClientID: "rp-a", ClientSecret: "rp-a-secret",
			RedirectURIs: []string{loginCB, linkCB}, AuthTimeMaxAge: 300, Enabled: true,
		},
		{
			ID: idpBID, TenantID: tenantID,
			Issuer: env.idpB.issuer(), ClientID: "rp-b", ClientSecret: "rp-b-secret",
			RedirectURIs: []string{loginCB, linkCB}, AuthTimeMaxAge: 300, Enabled: true,
		},
	} {
		if err := st.UpsertProvider(ctx, &p); err != nil {
			t.Fatalf("upsert provider: %v", err)
		}
	}

	cfg := &config.Config{
		DatabaseURL:     dsn,
		BaseURL:         baseURL,
		Addr:            fmt.Sprintf(":%d", appPort),
		SessionTTL:      time.Hour,
		LinkTTL:         10 * time.Minute,
		AuthRequestTTL:  10 * time.Minute,
		MaxAuthAttempts: 3,
		CookieSecure:    false,
		CookieSameSite:  "lax",
	}
	env.cfg = cfg
	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: api.NewServer(cfg, st, oidcx.NewManager(),
			log.New(os.Stdout, "[rec-test] ", log.LstdFlags|log.Lmicroseconds)).Routes(),
	}
	env.httpd = srv
	go func() { _ = srv.ListenAndServe() }()
	waitReady(t, baseURL+"/healthz")
	t.Cleanup(func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		database.Close()
	})
	return env
}

// httpClient 是跟随/不跟随重定向可控、带 cookie jar 的客户端。
type httpClient struct {
	t      *testing.T
	app    *http.Client
	follow bool
}

func newHTTPClient(t *testing.T, follow bool) *httpClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	check := func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if follow {
		check = nil
	}
	return &httpClient{
		t: t,
		app: &http.Client{
			Jar: jar, Timeout: 20 * time.Second,
			CheckRedirect: check,
		},
	}
}

func (c *httpClient) do(req *http.Request) *http.Response {
	c.t.Helper()
	resp, err := c.app.Do(req)
	if err != nil {
		c.t.Fatalf("HTTP %s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

func (c *httpClient) get(raw string) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, raw, nil)
	return c.do(req)
}

func (c *httpClient) postJSON(raw string, body any) *http.Response {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(http.MethodPost, raw, rdr)
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func bodyMap(resp *http.Response) map[string]any {
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if out == nil {
		out = map[string]any{}
	}
	out["_status_code"] = resp.StatusCode
	return out
}

// startLogin 调发起端点（不跟随重定向），返回 302 的 IdP 授权地址。
func (c *httpClient) startLogin(env *recoverEnv) string {
	u := env.baseURL + "/t/acme/login?issuer=" + url.QueryEscape(env.idpA.issuer())
	resp := c.get(u)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("login start status=%d body=%v", resp.StatusCode, bodyMap(resp))
	}
	return resp.Header.Get("Location")
}

// followAuthToCallback 跟随 IdP 授权地址：mock IdP 直接 302 回应用回调，
// 返回应用回调的完整 URL（含 state/code），不自动请求。
func (c *httpClient) followAuthToCallback(authURL string) string {
	resp := c.get(authURL)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("idp auth status=%d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://localhost") {
		c.t.Fatalf("idp redirected off-app: %s", loc)
	}
	return loc
}

// failExchangeForCallback 让给定回调 URL 中授权码的下一轮交换暂时性失败。
func failExchangeForCallback(idp *mockIdP, callbackURL string) {
	idp.failNextTokenExchangeForCode(queryParam(callbackURL, "code"))
}

// hitCallback 请求一次应用回调，返回响应（Body 已关闭，body 已解析）。
func (c *httpClient) hitCallback(callbackURL string) (int, map[string]any) {
	resp := c.get(callbackURL)
	b := bodyMap(resp)
	return resp.StatusCode, b
}

// postRecover 以 POST body 提供恢复令牌，返回状态与 JSON。
func (c *httpClient) postRecover(env *recoverEnv, token string) (int, map[string]any, string) {
	resp := c.postJSON(env.baseURL+"/oauth/recover",
		map[string]string{"recovery_token": token})
	loc := resp.Header.Get("Location")
	b := bodyMap(resp)
	return resp.StatusCode, b, loc
}

func (c *httpClient) postStatus(env *recoverEnv, token string) (int, map[string]any) {
	resp := c.postJSON(env.baseURL+"/oauth/attempt",
		map[string]string{"recovery_token": token})
	return resp.StatusCode, bodyMap(resp)
}

func (c *httpClient) me(env *recoverEnv) (int, map[string]any) {
	resp := c.get(env.baseURL + "/t/acme/api/me")
	return resp.StatusCode, bodyMap(resp)
}

func mustStr(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}

// startLink 发起关联（需已登录客户端），返回 link_token、recovery_token、link_url。
func (c *httpClient) startLink(env *recoverEnv, issuer string) (string, string, string) {
	resp := c.postJSON(env.baseURL+"/t/acme/api/links",
		map[string]string{"issuer": issuer})
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("link start status=%d body=%v", resp.StatusCode, bodyMap(resp))
	}
	b := bodyMap(resp)
	return mustStr(b, "link_token"), mustStr(b, "recovery_token"), mustStr(b, "link_url")
}
