package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

const (
	// loginResumePath / linkResumePath 是“继续认证”入口（安全重试）。
	loginResumePath = "/oauth/resume"
	linkResumePath  = "/oauth/link/resume"
	// attemptStatusPath 查询意图状态（只暴露粗粒度状态，不泄露失败细节）。
	attemptStatusPath = "/oauth/attempt"
	// attemptCookie 在登录场景的浏览器里保存当前意图令牌（HttpOnly），
	// 使刷新后仍能拿到可操作的恢复入口；权威值始终是服务端记录。
	attemptCookie = "aat"
)

// newAttemptToken 生成意图主键、对外不透明令牌与首代次 state/nonce/PKCE。
type attemptSecrets struct {
	id       uuid.UUID
	token    string
	state    string
	nonce    string
	verifier string
}

func (s *Server) generateAttemptSecrets(w http.ResponseWriter) (*attemptSecrets, bool) {
	token, err := sec.AttemptToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "attempt token failed"))
		return nil, false
	}
	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state generation failed"))
		return nil, false
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce generation failed"))
		return nil, false
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce generation failed"))
		return nil, false
	}
	return &attemptSecrets{id: uuid.New(), token: token, state: state, nonce: nonce, verifier: verifier}, true
}

// buildAuthURL 用某具体请求的 state/nonce/PKCE 构造 IdP 授权地址。
// forceLogin（关联）强制 prompt=login,max_age=0。
func buildAuthURL(cfg *oauth2.Config, secr *attemptSecrets, forceLogin bool) string {
	challenge := oauth2.S256ChallengeFromVerifier(secr.verifier)
	return oidcx.AuthCodeURL(cfg, secr.state, secr.nonce, challenge, "S256", forceLogin, nil)
}

// failureView 是回调失败时返回给界面/API 的可操作恢复信息。
// 不含 state/nonce/PKCE/code/令牌或任何提供方错误细节。
type failureView struct {
	Error           string `json:"error"`
	Message         string `json:"message"`
	Recoverable     bool   `json:"recoverable"`
	ResumeURL       string `json:"resume_url,omitempty"`
	AttemptToken    string `json:"attempt_token,omitempty"`
	AttemptsUsed    int    `json:"attempts_used"`
	AttemptsAllowed int    `json:"attempts_allowed"`
}

// writeProviderFailure 处理回调中“与提供方交互/校验”阶段的失败：
// 先把失败分类持久化到意图（可恢复 vs 永久），再返回可操作但不泄密的响应。
// 返回 false 表示已经写过响应，调用方应直接返回。
func (s *Server) writeProviderFailure(w http.ResponseWriter, r *http.Request,
	ar *models.AuthRequest, cause error, forceLogin bool, redirectURI string) {

	s.logVerifyFailure(cause)

	ve, isVerify := oidcx.AsVerifyError(cause)
	recoverable := isVerify && ve.Recoverable
	kind := "verification"
	if isVerify {
		kind = string(ve.Kind)
	}

	attempt, err := s.store.RecordAuthRequestFailure(r.Context(),
		*ar.AttemptID, ar.RequestSeq, kind, recoverable)
	if err != nil {
		// 记录失败本身出错（罕见基础设施问题）：退化为普通认证失败，不给恢复入口。
		s.logger.Printf("record auth failure failed: %v", err)
		writeAPIError(w, authn("authentication failed"))
		return
	}

	if !recoverable {
		// 永久失败：旧请求已失效，意图已终结，不提供恢复入口；
		// 仅回传不透明 attempt 令牌，供界面查询终态，不含任何敏感材料。
		writeJSON(w, http.StatusUnauthorized, failureView{
			Error:           string(ErrAuthn),
			Message:         "authentication failed; please start over",
			Recoverable:     false,
			AttemptToken:    attempt.Token,
			AttemptsUsed:    attempt.RequestSeq,
			AttemptsAllowed: 1 + attempt.MaxRetries,
		})
		return
	}

	// 暂时性提供方错误：给出可立即使用的安全重试入口。
	s.writeRecoverableFailure(w, r, attempt, forceLogin, redirectURI)
}

// writeRecoverableFailure 返回 503 + 恢复入口；503 语义上就是“暂时不可用，稍后重试”。
func (s *Server) writeRecoverableFailure(w http.ResponseWriter, r *http.Request,
	a *models.AuthAttempt, forceLogin bool, redirectURI string) {

	resumePath := loginResumePath
	if forceLogin {
		resumePath = linkResumePath
	}
	resumeURL := s.cfg.BaseURL + resumePath + "?attempt=" + a.Token

	// 登录场景同步刷新 HttpOnly cookie，使浏览器刷新后仍能恢复。
	if a.Kind == "login" {
		s.setAttemptCookie(w, a.Token)
	}

	writeJSON(w, http.StatusServiceUnavailable, failureView{
		Error:           "provider_temporarily_unavailable",
		Message:         "the identity provider is temporarily unavailable; you can safely retry",
		Recoverable:     true,
		ResumeURL:       resumeURL,
		AttemptToken:    a.Token,
		AttemptsUsed:    a.RequestSeq,
		AttemptsAllowed: 1 + a.MaxRetries,
	})
}

func (s *Server) setAttemptCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     attemptCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: sameSite(s.cfg.CookieSameSite),
		MaxAge:   int(s.cfg.AuthRequestTTL.Seconds()),
	})
}

func (s *Server) clearAttemptCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     attemptCookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: sameSite(s.cfg.CookieSameSite),
		MaxAge:   -1,
		Expires:  s.now().AddDate(0, 0, -1),
	})
}

// attemptTokenFromRequest 取恢复令牌：显式 ?attempt= 优先，其次 HttpOnly cookie。
// 只在恢复/状态入口使用，绝不作为身份凭据（另有会话/租户/成员校验）。
func attemptTokenFromRequest(r *http.Request) string {
	if t := r.URL.Query().Get("attempt"); t != "" {
		return t
	}
	if c, err := r.Cookie(attemptCookie); err == nil {
		return c.Value
	}
	return ""
}

// resumeResult 是安全重试的结果。
type resumeResult struct {
	attempt *models.AuthAttempt
	request *models.AuthRequest
}

// performResume 是登录/关联恢复入口共用的核心逻辑：
// 在单个事务里完成“旧请求失效 + 新代次 state/nonce/PKCE 创建”，
// 并返回新的 IdP 授权地址。重复调用在本代次未消费时幂等复用同一后继请求。
func (s *Server) performResume(w http.ResponseWriter, r *http.Request,
	prov *models.Provider, redirectURI string, forceLogin bool) (*resumeResult, string, *APIError) {

	token := attemptTokenFromRequest(r)
	if token == "" {
		return nil, "", badRequest("missing attempt token")
	}

	secr, ok := s.generateAttemptSecrets(w)
	if !ok {
		return nil, "", nil // 响应已写
	}

	attempt, next, err := s.store.ResumeAuthAttempt(r.Context(), token, &models.AuthRequest{
		State:        secr.state,
		Nonce:        secr.nonce,
		PKCEVerifier: secr.verifier,
	})
	if err != nil {
		return nil, "", s.mapResumeError(err)
	}

	// 幂等复用时，next 是库中已存在的未消费后继请求，其 verifier 已在库里；
	// 我们要返回指向该既有请求的授权地址，因此用它的值覆盖本地生成值。
	if next.State != secr.state {
		secr.state = next.State
		secr.nonce = next.Nonce
		secr.verifier = next.PKCEVerifier
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		// 发现失败本身也分暂时性/永久；意图此刻仍 pending，可再恢复。
		if ve, ok := oidcx.AsVerifyError(err); ok && ve.Recoverable {
			s.writeRecoverableFailure(w, r, attempt, forceLogin, redirectURI)
			return nil, "", nil
		}
		s.logger.Printf("oidc config error on resume: %v", err)
		return nil, "", authn("failed to initialize provider configuration")
	}

	if attempt.Kind == "login" {
		s.setAttemptCookie(w, attempt.Token)
	}
	return &resumeResult{attempt: attempt, request: next}, buildAuthURL(cfg, secr, forceLogin), nil
}

func (s *Server) mapResumeError(err error) *APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		// 不区分“不存在/不属于你/已终结”，统一 410，不泄露存在性。
		return attemptGone("the authentication attempt is no longer available")
	case errors.Is(err, store.ErrExpired):
		return attemptGone("the authentication attempt has expired; please start over")
	case errors.Is(err, store.ErrExhausted):
		return newAPIError(http.StatusConflict, ErrAttemptGone,
			"the maximum number of retries has been reached; please start over")
	case errors.Is(err, store.ErrConflict):
		return attemptGone("the authentication attempt cannot be resumed")
	default:
		s.logger.Printf("resume attempt failed: %v", err)
		return newAPIError(http.StatusInternalServerError, "internal_error", "resume failed")
	}
}

func attemptGone(msg string) *APIError {
	return newAPIError(http.StatusGone, ErrAttemptGone, msg)
}

// attemptStatusView 是对外的粗粒度意图状态（不含失败细节/材料）。
type attemptStatusView struct {
	Status          string `json:"status"`
	Recoverable     bool   `json:"recoverable"`
	ResumeURL       string `json:"resume_url,omitempty"`
	AttemptsUsed    int    `json:"attempts_used"`
	AttemptsAllowed int    `json:"attempts_allowed"`
}

// loginAttemptStatus 是公开入口（GET /oauth/attempt），只服务登录意图；
// 关联意图在这里一律按“不可用”处理（关联状态必须经会话中间件查询）。
func (s *Server) loginAttemptStatus(w http.ResponseWriter, r *http.Request) {
	s.serveAttemptStatus(w, r, false)
}

// linkAttemptStatus 是会话入口（GET /oauth/link/attempt），只服务关联意图。
func (s *Server) linkAttemptStatus(w http.ResponseWriter, r *http.Request) {
	s.serveAttemptStatus(w, r, true)
}

// serveAttemptStatus 用于界面在刷新/重启后查询“还能不能继续”。
// 只返回粗粒度状态，绝不暴露失败细节/材料：
//   - active：当前有未消费请求；
//   - recoverable：上一代次遇到明确的暂时故障，恢复入口可用；
//   - succeeded/failed/expired：终态，不提供入口。
//
// requireSession=true 时（关联）必须由发起它的同一会话查询，否则按不存在处理。
func (s *Server) serveAttemptStatus(w http.ResponseWriter, r *http.Request, requireSession bool) {
	token := attemptTokenFromRequest(r)
	if token == "" {
		writeAPIError(w, attemptGone("no authentication attempt in progress"))
		return
	}
	a, err := s.store.AuthAttemptByToken(r.Context(), token)
	if err != nil {
		writeAPIError(w, attemptGone("the authentication attempt is no longer available"))
		return
	}

	switch {
	case requireSession && a.Kind != "link_b":
		writeAPIError(w, attemptGone("the authentication attempt is no longer available"))
		return
	case !requireSession && a.Kind != "login":
		writeAPIError(w, attemptGone("the authentication attempt is no longer available"))
		return
	}
	if a.Kind == "link_b" {
		// 关联意图绑定发起会话：别的会话/成员/租户看不到它。
		ac := authed(r)
		if a.SessionID == nil || *a.SessionID != ac.session.ID ||
			a.TenantID != ac.session.TenantID {
			writeAPIError(w, attemptGone("the authentication attempt is no longer available"))
			return
		}
	}

	resumePath := loginResumePath
	if a.Kind == "link_b" {
		resumePath = linkResumePath
	}

	now := s.now()
	status := "active"
	recoverable := false
	resumeURL := ""
	switch {
	case a.ExpiresAt.Before(now):
		status = "expired"
	case a.Status == "succeeded":
		status = "succeeded"
	case a.Status == "failed":
		status = "failed"
	case a.LastFailureAt.Valid && a.LastFailureRecoverable:
		status = "recoverable"
		recoverable = true
		resumeURL = s.cfg.BaseURL + resumePath + "?attempt=" + a.Token
	case a.LastFailureAt.Valid && !a.LastFailureRecoverable:
		status = "failed"
	}
	writeJSON(w, http.StatusOK, attemptStatusView{
		Status: status, Recoverable: recoverable, ResumeURL: resumeURL,
		AttemptsUsed: a.RequestSeq, AttemptsAllowed: 1 + a.MaxRetries,
	})
}
