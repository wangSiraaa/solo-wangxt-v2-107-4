package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

func (s *Server) redirectURLLogin() string {
	return s.cfg.BaseURL + callbackPath
}

func (s *Server) redirectURLLink() string {
	return s.cfg.BaseURL + linkCBPath
}

func (s *Server) now() time.Time { return s.nowFunc() }

// loadTenantProvider 解析租户 slug + issuer 查询参数，并确保该租户启用了该 IdP。
func (s *Server) loadTenantProvider(ctx context.Context, slug, issuer string) (
	*models.Tenant, *models.Provider, *APIError) {
	tenant, err := s.store.TenantBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, tenantForbidden("unknown tenant")
		}
		return nil, nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup tenant failed")
	}
	if issuer == "" {
		return nil, nil, badRequest("issuer query parameter is required")
	}
	prov, err := s.store.ProviderByIssuer(ctx, tenant.ID, issuer)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// 租户未授权该 issuer —— 与签名失败明确区分。
			return nil, nil, tenantForbidden("this issuer is not authorized for the tenant")
		}
		return nil, nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed")
	}
	if !prov.Enabled {
		return nil, nil, tenantForbidden("identity provider is disabled for the tenant")
	}
	return tenant, prov, nil
}

// safeReturnTo 仅允许应用内相对路径跳转，防止登录后 open redirect。
func safeReturnTo(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return "/"
	}
	return v
}

// GET /t/{slug}/login?issuer=...&return_to=/...
//
// 这里同时持久化“用户意图（auth_attempt）”与“首个具体 OIDC 请求
// （state/nonce/PKCE）”。意图在后续暂时性失败后仍可用，具体请求一次性。
func (s *Server) loginStart(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	issuer := r.URL.Query().Get("issuer")
	tenant, prov, ae := s.loadTenantProvider(r.Context(), slug, issuer)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}

	redirectURI := s.redirectURLLogin()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		// 只允许数据库中为该 provider 登记过的回调地址。
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	secr, ok := s.generateAttemptSecrets(w)
	if !ok {
		return
	}
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	attempt := &models.AuthAttempt{
		ID:         secr.id,
		Token:      secr.token,
		Kind:       "login",
		TenantID:   tenant.ID,
		IDPID:      prov.ID,
		ReturnTo:   returnTo,
		MaxRetries: s.cfg.AttemptMaxRetries,
	}
	ar := &models.AuthRequest{
		State:        secr.state,
		Nonce:        secr.nonce,
		PKCEVerifier: secr.verifier,
	}
	if err := s.store.CreateAuthAttemptWithRequest(r.Context(), attempt, ar, s.cfg.AuthRequestTTL); err != nil {
		s.logger.Printf("persist auth attempt failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth attempt failed"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		s.logger.Printf("oidc config error: %v", err)
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}

	s.setAttemptCookie(w, attempt.Token)
	http.Redirect(w, r, buildAuthURL(cfg, secr, false), http.StatusFound)
}

// GET /oauth/resume?attempt=...
//
// 安全重试入口：只有上一代次失败被明确分类为“暂时性提供方错误”时，
// store 才会在事务里作废旧请求并创建全新 state/nonce/PKCE。
// 重复点击在新代次未消费时幂等复用同一后继请求（只产生一个有效后继）。
func (s *Server) loginResume(w http.ResponseWriter, r *http.Request) {
	// 恢复后会 302 到外部 IdP：不向外发送 Referer，避免恢复令牌经 Referer 泄露。
	w.Header().Set("Referrer-Policy", "no-referrer")
	token := attemptTokenFromRequest(r)
	a, ae := s.loadAttemptForResume(r, token, false)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	prov, ae := s.resumeProvider(r, a)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	res, authURL, ae := s.performResume(w, r, prov, s.redirectURLLogin(), false)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}
	if res == nil {
		return // performResume 已直接写响应（如发现阶段再次暂时失败）
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// loadAttemptForResume 按令牌加载意图并做场景归属校验，不泄露存在性。
// requireSession=true 用于关联意图（必须同会话）；登录意图必须无会话绑定。
func (s *Server) loadAttemptForResume(r *http.Request, token string, requireSession bool) (
	*models.AuthAttempt, *APIError) {
	if token == "" {
		return nil, badRequest("missing attempt token")
	}
	a, err := s.store.AuthAttemptByToken(r.Context(), token)
	if err != nil {
		return nil, attemptGone("the authentication attempt is no longer available")
	}
	switch {
	case a.Status == "expired" || a.ExpiresAt.Before(s.now()):
		return nil, attemptGone("the authentication attempt has expired; please start over")
	case a.Status != "pending":
		return nil, attemptGone("the authentication attempt cannot be resumed")
	case a.LastFailureAt.Valid && !a.LastFailureRecoverable:
		// 最近一次是永久失败：恢复入口无效。
		return nil, attemptGone("the authentication attempt cannot be resumed")
	}
	if requireSession {
		ac := authed(r)
		if a.Kind != "link_b" || a.SessionID == nil || *a.SessionID != ac.session.ID ||
			a.TenantID != ac.session.TenantID {
			return nil, attemptGone("the authentication attempt is no longer available")
		}
	} else {
		if a.Kind != "login" || a.SessionID != nil {
			return nil, attemptGone("the authentication attempt is no longer available")
		}
	}
	return a, nil
}

// resumeProvider 按意图记录的 idp 重新解析提供方（恢复仍绑定原租户与 IdP），
// 并校验 IdP 仍被授权、回调地址仍在白名单。
func (s *Server) resumeProvider(r *http.Request, a *models.AuthAttempt) (*models.Provider, *APIError) {
	prov, err := s.store.ProviderByID(r.Context(), a.TenantID, a.IDPID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, tenantForbidden("provider is no longer authorized for the tenant")
		}
		return nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed")
	}
	if !prov.Enabled {
		return nil, tenantForbidden("identity provider is disabled for the tenant")
	}
	redirectURI := s.redirectURLLogin()
	if a.Kind == "link_b" {
		redirectURI = s.redirectURLLink()
	}
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		return nil, badRequest("callback url is not registered for this provider")
	}
	return prov, nil
}

// GET /oauth/callback?state=...&code=...
//
// 重复到达（同一 state 两次）在 ConsumeAuthRequest 处被原子拦截，
// 旧代次迟到回调同样在消费/意图状态检查处被拒绝，因此任何迟到回调
// 都不可能再走“找到/创建成员”，也就不可能创建多个成员或使已完成流程回退。
func (s *Server) loginCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}
	if errParam := q.Get("error"); errParam != "" {
		// IdP 在回调里直接报错：消费 state 防重放后按协议分类
		// （server_error/temporarily_unavailable 可恢复，其余永久失败）。
		s.consumeAndFailCallback(w, r, state, false, s.redirectURLLogin())
		return
	}

	// 原子取出并消费 state：伪造、重放、旧代次、已终结意图得到同样结果。
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}
	if ar.Kind != "login" {
		writeAPIError(w, badRequest("state is not valid for the login callback"))
		return
	}
	if ar.AttemptID == nil {
		// 不属于任何意图的遗留行：拒绝（迁移后不应出现）。
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}

	// 回调必须在租户仍授权该 issuer 的前提下继续。
	prov, err := s.store.ProviderByID(r.Context(), ar.TenantID, ar.IDPID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, tenantForbidden("provider is no longer authorized for the tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	redirectURI := s.redirectURLLogin()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	cfg, ver, cae := s.oauthConfigAndVerifier(r, prov, redirectURI, ar.Nonce)
	if cae != nil {
		// 发现失败：暂时性可恢复，永久则失败。
		s.writeProviderFailure(w, r, ar, cae.cause, false, redirectURI)
		return
	}

	// 令牌交换 + 签名/受众/issuer/过期/nonce/PKCE 校验。
	// 授权码重放、PKCE 不匹配在这里被判为永久失败（不可恢复）。
	claims, _, err := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if err != nil {
		s.writeProviderFailure(w, r, ar, err, false, redirectURI)
		return
	}

	// 先抢占意图终态：并发的旧/新回调只有一个能越过这里，杜绝重复建成员/会话。
	if err := s.store.MarkAuthAttemptSucceeded(r.Context(), *ar.AttemptID); err != nil {
		s.logger.Printf("mark attempt succeeded failed: %v", err)
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}

	// 业务身份只基于已核实的 (issuer, subject)，邮箱不参与。
	result, err := s.store.LoginOrRegisterMember(r.Context(), store.LoginIdentity{
		TenantID:      ar.TenantID,
		Issuer:        claims.Issuer,
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
	})
	if err != nil {
		s.logger.Printf("login upsert failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "login failed"))
		return
	}

	token, err := sec.SessionToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "session token failed"))
		return
	}
	if _, err := s.store.CreateSession(r.Context(), ar.TenantID, result.Member.ID,
		sec.HashToken(token), s.cfg.SessionTTL); err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "create session failed"))
		return
	}
	s.setSessionCookie(w, token)
	s.clearAttemptCookie(w)

	target := ar.ReturnTo
	if target == "" {
		target = "/"
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// oauthConfigAndVerifier 同时准备 oauth2 配置与 ID token 校验器；
// 发现失败时返回带 cause（已分类可恢复性）的 APIError。
func (s *Server) oauthConfigAndVerifier(r *http.Request, prov *models.Provider,
	redirectURI, nonce string) (*oauth2.Config, *oidcx.Verifier, *classifiedAPIError) {
	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		s.logger.Printf("oidc config error: %v", err)
		return nil, nil, &classifiedAPIError{
			APIError: authn("failed to initialize provider configuration"), cause: err,
		}
	}
	ver, err := s.oidc.Verifier(r.Context(), prov, nonce)
	if err != nil {
		s.logger.Printf("oidc verifier error: %v", err)
		return nil, nil, &classifiedAPIError{
			APIError: authn("failed to initialize token verifier"), cause: err,
		}
	}
	return cfg, ver, nil
}

type classifiedAPIError struct {
	*APIError
	cause error
}

// consumeAndFailCallback 处理“回调带 error 参数”等不进入令牌交换的失败：
// 先消费 state（一次性），再按协议把失败分类持久化到意图，
// 只有 server_error / temporarily_unavailable 提供恢复入口。
func (s *Server) consumeAndFailCallback(w http.ResponseWriter, r *http.Request, state string,
	forceLogin bool, redirectURI string) {
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}
	ep := r.URL.Query().Get("error")
	var cause error
	if ep == "server_error" || ep == "temporarily_unavailable" {
		cause = oidcx.NewProviderUnavailable("provider reported a temporary error")
	} else {
		// access_denied / invalid_request 等协议层永久失败。
		cause = oidcx.NewVerifyError(oidcx.KindClaims,
			"provider returned error: "+sanitizeErrParam(ep))
	}
	s.writeProviderFailure(w, r, ar, cause, forceLogin, redirectURI)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	sec := http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: sameSite(s.cfg.CookieSameSite),
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	}
	http.SetCookie(w, &sec)
}

func (s *Server) logVerifyFailure(err error) {
	if ve, ok := oidcx.AsVerifyError(err); ok {
		// 只记录分类，不记录令牌或授权码。
		s.logger.Printf("oidc verification failed: kind=%s recoverable=%t", ve.Kind, ve.Recoverable)
		return
	}
	s.logger.Printf("oidc verification failed (untyped)")
}

func sameSite(v string) http.SameSite {
	switch strings.ToLower(v) {
	case "none":
		return http.SameSiteNoneMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteLaxMode
	}
}

func sanitizeErrParam(v string) string {
	// 只保留 OIDC 标准错误码字符，防止把任意文本反射到响应。
	v = url.QueryEscape(v)
	if len(v) > 40 {
		v = v[:40]
	}
	return v
}
