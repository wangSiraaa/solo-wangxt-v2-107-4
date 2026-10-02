package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

type linkStartRequest struct {
	Issuer string `json:"issuer"`
	// AnchorIssuer 指定用当前成员的哪个已核实身份作为 A。
	// 成员只有一个身份时可省略；有多个身份时必填。
	AnchorIssuer string `json:"anchor_issuer"`
}

// POST /t/{slug}/api/links
// body: {"issuer": "<target issuer>", "anchor_issuer": "<current issuer>"}
//
// 返回 201 + {"link_token": "...", "link_url": "...", "recovery_token": "..."}，
// 调用方让浏览器跳转 link_url。两个身份各自重新认证：
//   - A（当前会话身份）：linkStart 时刻记录 a_auth_time，完成时校验仍在强认证窗口内；
//   - B（目标 IdP 身份）：授权请求强制 prompt=login,max_age=0，
//     回调核对 IdP 返回的 auth_time 必须足够新。
//
// 关联会话、认证意图、首个 leg B 具体请求与 b_state 绑定在单事务内落库。
func (s *Server) linkStart(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	var req linkStartRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	if req.Issuer == "" {
		writeAPIError(w, badRequest("issuer is required"))
		return
	}

	slug := r.PathValue("slug")
	tenant, targetProv, ae := s.loadTenantProvider(r.Context(), slug, req.Issuer)
	if ae != nil {
		writeAPIError(w, ae) // 租户未授权该 issuer 时为 403 tenant_unauthorized
		return
	}

	// 选择锚点身份 A：必须是该成员已经拥有的、由已核实 (issuer,subject) 标识的身份。
	ids, err := s.store.IdentitiesOfMember(r.Context(), tenant.ID, ac.member.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load identities failed"))
		return
	}
	if len(ids) == 0 {
		writeAPIError(w, authn("current member has no verified identity to anchor the link"))
		return
	}
	var anchor *models.Identity
	if req.AnchorIssuer == "" {
		if len(ids) != 1 {
			writeAPIError(w, badRequest("anchor_issuer is required when the member has multiple identities"))
			return
		}
		anchor = &ids[0]
	} else {
		for i := range ids {
			if ids[i].Issuer == req.AnchorIssuer {
				anchor = &ids[i]
				break
			}
		}
		if anchor == nil {
			writeAPIError(w, conflict("anchor issuer is not bound to the current member"))
			return
		}
	}

	redirectURI := s.redirectURLLink()
	if !sec.RedirectURIAllowed(targetProv.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	linkTok, err := sec.LinkToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "link token failed"))
		return
	}
	recoveryToken, err := sec.LinkToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "recovery token failed"))
		return
	}
	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state failed"))
		return
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce failed"))
		return
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce failed"))
		return
	}
	sessionID := ac.session.ID

	// 单事务：关联会话（含 leg A 锚点）+ 认证意图 + leg B 首个具体请求。
	attempt, err := s.store.CreateLinkAttempt(r.Context(), &store.LinkAttemptInput{
		Attempt: store.CreateAttemptInput{
			ID:                uuid.New(),
			Kind:              "link_b",
			TenantID:          tenant.ID,
			IDPID:             targetProv.ID,
			ReturnTo:          "/",
			LinkToken:         linkTok,
			SessionID:         &sessionID,
			RecoveryTokenHash: sec.HashToken(recoveryToken),
			State:             state,
			Nonce:             nonce,
			PKCEVerifier:      verifier,
		},
		AnchorMemberID: ac.member.ID,
		TargetIDPID:    targetProv.ID,
		AIssuer:        anchor.Issuer,
		ASubject:       anchor.Subject,
		AAuthTime:      s.now(),
		LinkTTL:        s.cfg.LinkTTL,
	}, s.cfg.AuthRequestTTL, s.cfg.MaxAuthAttempts)
	if err != nil {
		s.logger.Printf("create link attempt failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "create link session failed"))
		return
	}
	s.setAttemptCookie(w, recoveryToken)

	cfg, err := s.oidc.OAuth2Config(r.Context(), targetProv, redirectURI)
	if err != nil {
		s.handleDiscoveryFailure(w, r, attempt, recoveryToken, err)
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	linkURL := oidcx.AuthCodeURL(cfg, state, nonce, challenge, "S256", true, nil)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"link_token":     linkTok,
		"link_url":       linkURL,
		"recovery_token": recoveryToken,
	})
}

// GET /oauth/link/callback?state=...&code=...
//
// 完成 B 身份的强制重新认证与全套校验，随后原子完成关联。
// 防重放/防回退层次（与登录一致）：
//   - state 一次性消费；恢复后的旧 state 已 invalidated，与未知 state 行为一致；
//   - 意图必须仍 pending，且与发起会话/成员/租户/目标 provider 一致；
//   - 暂时性提供方错误才允许恢复（恢复时关联会话与 b_state 原子改绑新请求）；
//   - 关联成功先条件终态化意图，再做一次性 link token 消费。
func (s *Server) linkCallback(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if ep := r.URL.Query().Get("error"); ep != "" {
		// IdP 终止了授权（终态）：可识别 state 时顺手终态化意图，不给恢复入口。
		if state != "" {
			if ar, cerr := s.store.ConsumeAuthRequest(r.Context(), state); cerr == nil {
				_ = s.store.RecordAttemptPermanentFailure(r.Context(), ar.AttemptID,
					"provider_error:"+sanitizeErrParam(ep))
			}
		}
		s.clearAttemptCookie(w)
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(ep)))
		return
	}
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}

	// 原子消费 state（防重放；未知/已消费/已失效 state 行为一致）。
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("link authorization request is unknown or already used"))
		return
	}
	if ar.Kind != "link_b" || !ar.LinkToken.Valid {
		writeAPIError(w, badRequest("state is not valid for account linking"))
		return
	}
	rawRecovery := recoveryCookieValue(r)
	attempt, err := s.store.AttemptMustBePending(r.Context(), ar.AttemptID)
	if err != nil {
		writeAPIError(w, badRequest("link authorization request is unknown or already used"))
		return
	}
	// 必须用发起关联时的同一个会话、同一个租户完成。
	if ar.SessionID == nil || *ar.SessionID != ac.session.ID {
		writeAPIError(w, authn("link must be completed in the same browser session that started it"))
		return
	}
	if ar.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("link crosses tenant boundary"))
		return
	}

	ls, err := s.store.LinkSession(r.Context(), ar.LinkToken.String)
	if err != nil {
		s.terminalizePolicyFailure(r, attempt, "link_gone")
		s.clearAttemptCookie(w)
		writeAPIError(w, conflict("link session not found or already used"))
		return
	}
	if ls.Status != "pending" {
		// 已完成/已消费：终态不回退。
		s.terminalizePolicyFailure(r, attempt, "link_status")
		s.clearAttemptCookie(w)
		writeAPIError(w, conflict("link session already completed or consumed"))
		return
	}
	if !ls.ExpiresAt.After(s.now()) {
		// 过期关联绝不重新打开。
		_ = s.store.RecordAttemptPermanentFailure(r.Context(), attempt.ID, "link_expired")
		s.clearAttemptCookie(w)
		writeAPIError(w, s.mapLinkError(store.ErrNotFound))
		return
	}
	if ls.AnchorMemberID != ac.member.ID {
		s.terminalizePolicyFailure(r, attempt, "link_member")
		s.clearAttemptCookie(w)
		writeAPIError(w, tenantForbidden("link session belongs to another member"))
		return
	}
	if ls.TargetIDPID != ar.IDPID {
		s.terminalizePolicyFailure(r, attempt, "link_idp")
		s.clearAttemptCookie(w)
		writeAPIError(w, badRequest("state was issued for a different target provider"))
		return
	}

	prov, aerr := s.callbackProvider(w, r, attempt, ar.TenantID, ar.IDPID)
	if aerr != nil {
		writeAPIError(w, aerr)
		return
	}
	redirectURI := s.redirectURLLink()
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
	claims, _, xerr := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if xerr != nil {
		s.classifyAttemptFailure(w, r, attempt, rawRecovery, xerr)
		return
	}

	// B 身份必须来自声明的 issuer，且在 provider 窗口内交互式重新认证过。
	if claims.Issuer != prov.Issuer {
		s.terminalizePolicyFailure(r, attempt, "issuer_mismatch")
		s.clearAttemptCookie(w)
		writeAPIError(w, authn("id token issuer does not match the configured provider"))
		return
	}
	maxAge := providerAuthMaxAge(prov)
	bAuthTime := claims.AuthTime
	if bAuthTime.IsZero() {
		// IdP 无法证明 auth_time：协议缺陷，永久不可恢复（重新发起链接）。
		_ = s.store.RecordAttemptPermanentFailure(r.Context(), attempt.ID, "no_auth_time")
		s.clearAttemptCookie(w)
		writeAPIError(w, reauthRequired(
			"provider did not report auth_time; cannot prove recent re-authentication"))
		return
	}
	if s.now().Sub(bAuthTime) > maxAge {
		// 重新认证不够新鲜：恢复会再次强制 prompt=login，但同一已完成 B 认证
		// 不能被重试；这里属于策略永久失败，需重新发起。
		_ = s.store.RecordAttemptPermanentFailure(r.Context(), attempt.ID, "stale_auth_time")
		s.clearAttemptCookie(w)
		writeAPIError(w, reauthRequired("second identity authentication is stale; re-authenticate"))
		return
	}

	// 原子写入 B leg（state 必须与创建/恢复时绑定值一致，防止替换/重放）。
	if err := s.store.AttachLinkLegB(r.Context(), ls.Token, state,
		claims.Issuer, claims.Subject, claims.Email, bAuthTime, prov.ID); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// 重复/乱序回调：尝试已可能被并发成功，按终态不回退处理。
			s.terminalizePolicyFailure(r, attempt, "leg_b_conflict")
			s.clearAttemptCookie(w)
			writeAPIError(w, conflict("link leg has already been recorded"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist link leg failed"))
		return
	}

	// 原子完成全部冲突检查与绑定；link token 随即消费，杜绝重放。
	if err := s.store.CompleteLink(r.Context(), ls.Token, s.now(), maxAge); err != nil {
		s.terminalizePolicyFailure(r, attempt, "complete_conflict")
		s.clearAttemptCookie(w)
		writeAPIError(w, s.mapLinkError(err))
		return
	}
	if err := s.store.ConsumeCompletedLink(r.Context(), ls.Token); err != nil {
		s.terminalizePolicyFailure(r, attempt, "consume_link")
		s.clearAttemptCookie(w)
		writeAPIError(w, conflict("link completed but the one-time token could not be consumed"))
		return
	}
	// 全部写入完成后才终态化意图；条件更新保证并发的迟到回调不能再影响结果。
	if !s.finishAttemptSuccess(w, r, attempt) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "linked",
		"link_token":   ls.Token,
		"new_identity": map[string]string{"issuer": claims.Issuer, "subject": claims.Subject},
	})
}

// GET /t/{slug}/api/links/{token}
// 查询关联会话状态。已消费 token 返回 409 binding_conflict，防止重放探测。
func (s *Server) linkFinalize(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	token := r.PathValue("token")
	ls, err := s.store.LinkSession(r.Context(), token)
	if err != nil {
		writeAPIError(w, conflict("link session not found"))
		return
	}
	if ls.AnchorMemberID != ac.member.ID || ls.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("link session belongs to another member or tenant"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"link_token": token,
		"status":     ls.Status,
	})
}

func (s *Server) mapLinkError(err error) *APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return conflict("link session expired or was not found")
	case errors.Is(err, store.ErrConflict):
		// 目标 (issuer,subject) 已属于别的成员、同身份自关联或会话状态非法。
		return conflict("target identity is already bound to another member")
	}
	if msg, ok := store.AsReauth(err); ok {
		return reauthRequired(msg)
	}
	s.logger.Printf("complete link failed: %v", err)
	return newAPIError(http.StatusInternalServerError, "internal_error", "complete link failed")
}

func providerAuthMaxAge(p *models.Provider) time.Duration {
	secs := p.AuthTimeMaxAge
	if secs <= 0 {
		secs = 300
	}
	return time.Duration(secs) * time.Second
}
