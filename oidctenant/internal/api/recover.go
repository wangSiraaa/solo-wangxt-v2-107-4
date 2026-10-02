package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

// 恢复能力令牌的载体：
//   - 浏览器：HttpOnly Cookie（aat），不出现在 URL/日志中；
//   - API 客户端：503 响应体里的 recovery_token，调用方自行保存，
//     之后以 POST body 或 Authorization 头带回（绝不放进 GET query，避免泄露到日志）。
const recoverPath = "/oauth/recover"
const attemptPath = "/oauth/attempt"

// setAttemptCookie 在客户端种下恢复能力令牌（与 sid 同安全级别）。
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
		Name: attemptCookie, Path: "/", HttpOnly: true, MaxAge: -1,
		Expires:  s.now().AddDate(0, 0, -1),
		SameSite: sameSite(s.cfg.CookieSameSite),
		Secure:   s.cfg.CookieSecure,
	})
}

// recoveryToken 从 Cookie、POST JSON body 或 Authorization 头提取恢复令牌。
// 令牌绝不从 GET query 读取（避免进入 access log）。
func recoveryTokenFromRequest(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(attemptCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if r.Method == http.MethodPost && r.Body != nil {
		var body struct {
			RecoveryToken string `json:"recovery_token"`
		}
		// Body 此前不会被其他处理器读取；限制大小，读完即弃。
		raw, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<10))
		_ = json.Unmarshal(raw, &body)
		if body.RecoveryToken != "" {
			return body.RecoveryToken
		}
	}
	if v := r.Header.Get("Authorization"); len(v) > 7 && v[:7] == "Bearer " {
		return v[7:]
	}
	return ""
}

// writeRecoverable 返回 503 + 可操作但不泄密的恢复入口。
// 响应只包含“暂时性不可用、可恢复、恢复入口、剩余重试次数”，
// 不含 state/code/token，也不回显提供方的原始错误细节。
func (s *Server) writeRecoverable(w http.ResponseWriter, a *models.AuthAttempt, rawToken, kind string) {
	s.setAttemptCookie(w, rawToken)
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error":          ErrProviderTemporarilyUnavailable,
		"message":        "identity provider is temporarily unavailable; you can safely resume this sign-in",
		"status":         "recoverable",
		"recovery_token": rawToken,
		"recover_url":    s.cfg.BaseURL + recoverPath,
		"attempt_kind":   a.Kind,
		"failure":        kind,
		"attempts":       a.Attempts,
		"max_attempts":   a.MaxAttempts,
		"retries_left":   max0(a.MaxAttempts - a.Attempts),
	})
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// GET|POST /oauth/recover
//
// 从一次暂时性失败中恢复：在原意图下生成全新的 state/nonce/PKCE（旧请求
// 已永久失效）。GET（浏览器）302 到新的 IdP 授权地址；POST（API）返回 JSON。
// 重复调用（双击/刷新恢复入口）在 store 层幂等：已存在有效后继时复用同一后继，
// 任何时刻都只留下一个有效具体请求。
func (s *Server) recoverStart(w http.ResponseWriter, r *http.Request) {
	raw := recoveryTokenFromRequest(w, r)
	if raw == "" {
		writeAPIError(w, badRequest("recovery token is required"))
		return
	}
	a, err := s.store.AttemptByRecoveryHash(r.Context(), sec.HashToken(raw))
	if err != nil {
		// 未知/不存在的恢复令牌与失效令牌返回一致错误，无法枚举。
		writeAPIError(w, badRequest("recovery link is unknown or no longer usable"))
		return
	}

	// 链接意图必须由发起它的同一会话恢复；登录意图无会话绑定。
	if a.SessionID != nil {
		ac := maybeAuthed(r)
		if ac == nil || ac.session.ID != *a.SessionID {
			writeAPIError(w, authn("account linking must be resumed in the same browser session"))
			return
		}
	}

	prov, err := s.store.ProviderByID(r.Context(), a.TenantID, a.IDPID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_ = s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, "provider_removed")
			s.clearAttemptCookie(w)
			writeAPIError(w, tenantForbidden("provider is no longer authorized for the tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed"))
		return
	}
	if !prov.Enabled {
		_ = s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, "provider_disabled")
		s.clearAttemptCookie(w)
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	redirectURI := s.redirectURLLogin()
	if a.Kind == "link_b" {
		redirectURI = s.redirectURLLink()
	}
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		_ = s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, "redirect_not_allowed")
		s.clearAttemptCookie(w)
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	// 发现仍不可用时不消耗重试预算：保持 recoverable，稍后可再次恢复。
	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		if ve, ok := oidcx.AsVerifyError(err); ok && ve.Temporary {
			s.writeRecoverable(w, a, raw, string(ve.Kind))
			return
		}
		writeAPIError(w, authn("failed to initialize provider configuration"))
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

	var inSessionID *uuid.UUID
	if ac := maybeAuthed(r); ac != nil {
		id := ac.session.ID
		inSessionID = &id
	}
	out, rerr := s.store.RecoverAttempt(r.Context(), &store.RecoverInput{
		RecoveryTokenHash: sec.HashToken(raw),
		SessionID:         inSessionID,
		NewState:          state,
		NewNonce:          nonce,
		NewPKCE:           verifier,
	})
	if rerr != nil {
		switch {
		case errors.Is(rerr, store.ErrAttemptExpired),
			errors.Is(rerr, store.ErrAttemptExhausted),
			errors.Is(rerr, store.ErrAttemptTerminal):
			s.clearAttemptCookie(w)
			writeAPIError(w, recoveryUnavailable("this sign-in can no longer be resumed; please start over"))
			return
		case errors.Is(rerr, store.ErrConflict):
			writeAPIError(w, authn("account linking must be resumed in the same browser session"))
			return
		default:
			s.logger.Printf("recover attempt failed: %v", rerr)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "recovery failed"))
			return
		}
	}

	challenge := oauth2.S256ChallengeFromVerifier(out.PKCE)
	authURL := oidcx.AuthCodeURL(cfg, out.State, out.Nonce, challenge, "S256",
		a.Kind == "link_b", nil)

	// 刷新恢复 cookie（意图仍然有效；旧的具体请求已失效）。
	s.setAttemptCookie(w, raw)

	if r.Method == http.MethodGet {
		w.Header().Set("Location", authURL)
		w.WriteHeader(http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "pending",
		"authorization_url": authURL,
		"attempts":          out.Attempt.Attempts,
		"max_attempts":      out.Attempt.MaxAttempts,
		"reused_active":     out.Reused,
	})
}

// GET|POST /oauth/attempt
//
// 查询当前认证意图状态（界面/前端在刷新后据此决定显示“继续登录”还是“重新开始”）。
// 终态返回 410 并清除恢复 cookie；pending 返回是否可恢复与重试计数。
// 响应不泄露任何 state/nonce/code，只暴露粗粒度状态。
func (s *Server) attemptStatus(w http.ResponseWriter, r *http.Request) {
	raw := recoveryTokenFromRequest(w, r)
	if raw == "" {
		writeAPIError(w, badRequest("recovery token is required"))
		return
	}
	a, err := s.store.AttemptByRecoveryHash(r.Context(), sec.HashToken(raw))
	if err != nil {
		writeAPIError(w, badRequest("recovery link is unknown or no longer usable"))
		return
	}
	if a.SessionID != nil {
		ac := maybeAuthed(r)
		if ac == nil || ac.session.ID != *a.SessionID {
			writeAPIError(w, authn("this attempt belongs to another browser session"))
			return
		}
	}

	expired := !a.ExpiresAt.After(s.now())
	if a.Status == models.AttemptPending && !expired {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "pending",
			"recoverable":  a.Recoverable,
			"attempt_kind": a.Kind,
			"attempts":     a.Attempts,
			"max_attempts": a.MaxAttempts,
			"retries_left": max0(a.MaxAttempts - a.Attempts),
			"recover_url":  s.cfg.BaseURL + recoverPath,
		})
		return
	}

	s.clearAttemptCookie(w)
	reason := a.Status
	if expired {
		reason = models.AttemptExpired
	}
	writeJSON(w, http.StatusGone, map[string]any{
		"error":   ErrRecoveryUnavailable,
		"message": "this sign-in can no longer be resumed; please start over",
		"status":  reason,
	})
}

// classifyAttemptFailure 统一处理回调中的 OIDC 失败落库：
// 暂时性 -> 503 + 恢复入口；永久性 -> 清除恢复 cookie + 原错误响应。
func (s *Server) classifyAttemptFailure(w http.ResponseWriter, r *http.Request,
	a *models.AuthAttempt, rawToken string, err error) {

	ve, ok := oidcx.AsVerifyError(err)
	if !ok {
		// 未分类错误按保守原则：不允许恢复。
		s.logger.Printf("oidc verification failed (untyped)")
		_ = s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, "untyped")
		s.clearAttemptCookie(w)
		writeAPIError(w, authn("token exchange or id token verification failed"))
		return
	}
	s.logger.Printf("oidc verification failed: kind=%s temporary=%t", ve.Kind, ve.Temporary)
	if ve.Temporary {
		if recErr := s.store.RecordAttemptTemporaryFailure(r.Context(), a.ID, string(ve.Kind)); recErr != nil {
			// 意图已在并发中终态（旧/新回调同时到达，另一个已成功）：
			// 绝不回退，按不可恢复响应。
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
	_ = s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, string(ve.Kind))
	s.clearAttemptCookie(w)
	writeAPIError(w, authn("token exchange or id token verification failed"))
}

// finishAttemptSuccess 成功终态化；失败（并发终态）时写出错误并返回 false，
// 调用方必须停止创建会话/绑定身份 —— 已完成流程不得回退或重复建成员。
func (s *Server) finishAttemptSuccess(w http.ResponseWriter, r *http.Request, a *models.AuthAttempt) bool {
	if err := s.store.MarkAttemptSucceeded(r.Context(), a.ID); err != nil {
		s.clearAttemptCookie(w)
		writeAPIError(w, authn("this sign-in has already been finalized"))
		return false
	}
	s.clearAttemptCookie(w)
	return true
}

// terminalizePolicyFailure 把“提供方策略变化”类失败记为永久失败。
func (s *Server) terminalizePolicyFailure(r *http.Request, a *models.AuthAttempt, kind string) {
	if err := s.store.RecordAttemptPermanentFailure(r.Context(), a.ID, kind); err != nil {
		s.logger.Printf("terminalize attempt %s: %v", a.ID, err)
	}
}
