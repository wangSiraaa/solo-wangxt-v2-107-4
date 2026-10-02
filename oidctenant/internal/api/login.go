package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
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
// 创建“认证意图 + 首个具体 OIDC 请求”（单事务落库），随后 302 到 IdP。
// 即便发现文档暂时拉不到，意图与恢复能力令牌也已持久化 ——
// 客户端拿到 503 的恢复入口，提供方恢复后可直接续跑而不必从头开始。
func (s *Server) loginStart(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	issuerParam := r.URL.Query().Get("issuer")
	tenant, prov, ae := s.loadTenantProvider(r.Context(), slug, issuerParam)
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

	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state generation failed"))
		return
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce generation failed"))
		return
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce generation failed"))
		return
	}
	recoveryToken, err := sec.LinkToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "recovery token failed"))
		return
	}

	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	attempt, err := s.store.CreateLoginAttempt(r.Context(), &store.CreateAttemptInput{
		ID:                uuid.New(),
		Kind:              "login",
		TenantID:          tenant.ID,
		IDPID:             prov.ID,
		ReturnTo:          returnTo,
		RecoveryTokenHash: sec.HashToken(recoveryToken),
		State:             state,
		Nonce:             nonce,
		PKCEVerifier:      verifier,
	}, s.cfg.AuthRequestTTL, s.cfg.MaxAuthAttempts)
	if err != nil {
		s.logger.Printf("persist auth attempt failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth attempt failed"))
		return
	}
	s.setAttemptCookie(w, recoveryToken)

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		// 发现暂时不可用：意图已持久化，返回恢复入口而不是让用户从头开始。
		s.handleDiscoveryFailure(w, r, attempt, recoveryToken, err)
		return
	}

	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	authURL := oidcx.AuthCodeURL(cfg, state, nonce, challenge, "S256", false, nil)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GET /oauth/callback?state=...&code=...
//
// 多层防重放/防回退：
//  1. state 原子消费：伪造/已用/已失效（恢复后的旧 state）得到一致的 400；
//  2. 意图必须仍 pending：已成功的流程绝不可能因迟到回调回退；
//  3. 成功终态化是条件 UPDATE：旧/新回调同时到达时只有一个能继续；
//  4. 成员创建仍有咨询锁 + UNIQUE 锚点兜底。
//
// 令牌交换或验证遇到“明确的暂时性提供方错误”时，意图转为可恢复，
// 当前具体请求永久失效，响应给出恢复入口；其余失败一律永久不可恢复。
func (s *Server) loginCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	if errParam := q.Get("error"); errParam != "" {
		// IdP 在重定向里带回错误（access_denied/login_required/...）：授权已被
		// IdP 终止，属终态失败，仅回传错误码（描述不可信），不给恢复入口。
		// 若 state 可识别，顺手把意图终态化，避免悬挂一个 pending 尝试。
		if state != "" {
			if ar, cerr := s.store.ConsumeAuthRequest(r.Context(), state); cerr == nil {
				_ = s.store.RecordAttemptPermanentFailure(r.Context(), ar.AttemptID,
					"provider_error:"+sanitizeErrParam(errParam))
			}
		}
		s.clearAttemptCookie(w)
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(errParam)))
		return
	}
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}

	// 原子取出并消费 state：伪造/已消费/已失效 state 行为一致。
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}
	if ar.Kind != "login" {
		writeAPIError(w, badRequest("state is not valid for the login callback"))
		return
	}
	rawRecovery := recoveryCookieValue(r)
	attempt, err := s.store.AttemptMustBePending(r.Context(), ar.AttemptID)
	if err != nil {
		// 意图已终态（成功/过期/永久失败）：迟到回调一律拒绝，不回退。
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}

	// 回调必须在租户仍授权该 issuer 的前提下继续。
	prov, aerr := s.callbackProvider(w, r, attempt, ar.TenantID, ar.IDPID)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	redirectURI := s.redirectURLLogin()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		s.terminalizePolicyFailure(r, attempt, "redirect_not_allowed")
		s.clearAttemptCookie(w)
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	cfg, ver, derr := s.buildOIDC(r.Context(), prov, redirectURI, ar.Nonce)
	if derr != nil {
		s.handleDiscoveryFailure(w, r, attempt, rawRecovery, derr)
		return
	}

	// 令牌交换 + 签名/受众/issuer/过期/nonce/PKCE 校验。
	claims, _, xerr := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if xerr != nil {
		s.classifyAttemptFailure(w, r, attempt, rawRecovery, xerr)
		return
	}

	// 条件终态化：只有一个回调（无论新旧 state）能越过这道闸门。
	if !s.finishAttemptSuccess(w, r, attempt) {
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

	target := ar.ReturnTo
	if target == "" {
		target = "/"
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

// buildOIDC 构造 oauth2 config 与 ID token verifier。
// 发现/构造失败返回原始错误，调用方用 classify 决定是否可恢复。
func (s *Server) buildOIDC(ctx context.Context, prov *models.Provider,
	redirectURI, nonce string) (*oauth2.Config, *oidcx.Verifier, error) {
	cfg, err := s.oidc.OAuth2Config(ctx, prov, redirectURI)
	if err != nil {
		return nil, nil, err
	}
	ver, err := s.oidc.Verifier(ctx, prov, nonce)
	if err != nil {
		return nil, nil, err
	}
	return cfg, ver, nil
}

// handleDiscoveryFailure 处理发现/构造阶段失败：暂时性给恢复入口，
// 其余按永久失败终态化。
func (s *Server) handleDiscoveryFailure(w http.ResponseWriter, r *http.Request,
	a *models.AuthAttempt, rawToken string, err error) {
	if ve, ok := oidcx.AsVerifyError(err); ok && ve.Temporary {
		s.logVerifyFailure(err)
		if recErr := s.store.RecordAttemptTemporaryFailure(r.Context(), a.ID, string(ve.Kind)); recErr != nil {
			s.clearAttemptCookie(w)
			writeAPIError(w, authn("this sign-in has already been finalized"))
			return
		}
		refreshed, _ := s.store.AttemptByID(r.Context(), a.ID)
		if refreshed != nil {
			a = refreshed
		}
		s.writeRecoverable(w, a, rawToken, string(ve.Kind))
		return
	}
	s.logger.Printf("oidc config error: %v", err)
	_ = s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, "config")
	s.clearAttemptCookie(w)
	writeAPIError(w, authn("failed to initialize provider configuration"))
}

// callbackProvider 解析回调对应 provider，策略变化（移除/禁用）永久终态化。
func (s *Server) callbackProvider(w http.ResponseWriter, r *http.Request,
	attempt *models.AuthAttempt, tenantID, idpID uuid.UUID) (*models.Provider, *APIError) {
	prov, err := s.store.ProviderByID(r.Context(), tenantID, idpID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.terminalizePolicyFailure(r, attempt, "provider_removed")
			s.clearAttemptCookie(w)
			return nil, tenantForbidden("provider is no longer authorized for the tenant")
		}
		return nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed")
	}
	if !prov.Enabled {
		s.terminalizePolicyFailure(r, attempt, "provider_disabled")
		s.clearAttemptCookie(w)
		return nil, tenantForbidden("identity provider is disabled for the tenant")
	}
	return prov, nil
}

func recoveryCookieValue(r *http.Request) string {
	if c, err := r.Cookie(attemptCookie); err == nil {
		return c.Value
	}
	return ""
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
		s.logger.Printf("oidc verification failed: kind=%s temporary=%t", ve.Kind, ve.Temporary)
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
