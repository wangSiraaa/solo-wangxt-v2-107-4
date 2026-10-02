package oidcx

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// VerifyKind 细分认证失败的原因（仅用于服务端日志/指标，不向客户端暴露细节）。
type VerifyKind string

const (
	KindSignature VerifyKind = "signature"
	KindIssuer    VerifyKind = "issuer"
	KindAudience  VerifyKind = "audience"
	KindExpired   VerifyKind = "expired"
	KindNonce     VerifyKind = "nonce"
	KindClaims    VerifyKind = "claims"
	KindNoIDToken VerifyKind = "no_id_token"
	KindExchange  VerifyKind = "token_exchange"
	KindDiscovery VerifyKind = "discovery"
	KindPKCE      VerifyKind = "pkce"
	KindMalformed VerifyKind = "malformed"
	// KindProviderUnavailable 表示提供方暂时性不可达（网络/超时/5xx/429）。
	KindProviderUnavailable VerifyKind = "provider_unavailable"
)

// VerifyError 是不包含任何敏感材料的认证失败错误。
type VerifyError struct {
	Kind VerifyKind
	Msg  string
	// Temporary 为 true 当且仅当该失败可归为“提供方暂时性错误”，
	// 调用方才允许从失败尝试派生新的具体请求；其余（签名/nonce/PKCE/
	// 受众/issuer/非法授权码等）一律永久失败，绝不允许恢复重试。
	Temporary bool
}

func (e *VerifyError) Error() string { return string(e.Kind) + ": " + e.Msg }

// NewVerifyError 构造一个认证失败错误。
func NewVerifyError(kind VerifyKind, msg string) *VerifyError {
	return &VerifyError{Kind: kind, Msg: msg}
}

// AsVerifyError 提取 VerifyError。
func AsVerifyError(err error) (*VerifyError, bool) {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// gooidc 的验证错误是固定的哨兵错误（errors.Is 可匹配），
// 同时部分库版本返回带文本的 error，这里两种方式都覆盖。
//
// 注意：JWKS 获取失败（未知 kid 时重取 JWKS 网络故障）会以底层网络错误
// 透传到这里。这是暂时性错误：密钥材料本身没问题，只是当前拿不到。
func classifyVerifyError(err error) error {
	if err == nil {
		return nil
	}
	if isTransientNetwork(err) {
		return NewVerifyError(KindProviderUnavailable,
			"temporary failure while obtaining provider keys").asTemporary()
	}

	msg := err.Error()

	var expiredErr *gooidc.TokenExpiredError
	if errors.As(err, &expiredErr) {
		return NewVerifyError(KindExpired, "id token is expired")
	}
	switch {
	case strings.Contains(msg, "oidc: id token signed with unsupported alg") ||
		strings.Contains(msg, "verify failed") ||
		strings.Contains(msg, "signature"):
		return NewVerifyError(KindSignature, "id token signature verification failed")
	case strings.Contains(msg, "issuer"):
		return NewVerifyError(KindIssuer, "id token issuer does not match discovery")
	case strings.Contains(msg, "audience") || strings.Contains(msg, "client"):
		return NewVerifyError(KindAudience, "id token audience does not match this client")
	case strings.Contains(msg, "expired") || strings.Contains(msg, "issued in the future") ||
		strings.Contains(msg, "before issued"):
		return NewVerifyError(KindExpired, "id token failed time validity checks")
	case strings.Contains(msg, "malformed") || strings.Contains(msg, "Unmarshal"):
		return NewVerifyError(KindMalformed, "id token is malformed")
	default:
		return NewVerifyError(KindClaims, "id token verification failed")
	}
}

func (e *VerifyError) asTemporary() *VerifyError {
	e.Temporary = true
	return e
}

// classifyExchangeError 判定令牌端点错误的性质。
//
// 只有明确的暂时性服务端错误才可恢复（5xx / 429 / 网络故障 /
// invalid_grant 之外的临时语义）；invalid_grant（授权码已消费、
// code_verifier/PKCE 不匹配等）与 4xx 协议/凭证错误都是永久失败。
func classifyExchangeError(err error) error {
	if err == nil {
		return nil
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		body := strings.ToLower(string(retrieveErr.Body))
		switch {
		case isTransientStatus(retrieveErr.Response):
			return NewVerifyError(KindProviderUnavailable,
				"token endpoint is temporarily unavailable").asTemporary()
		case strings.Contains(body, "invalid_grant") ||
			strings.Contains(body, "code_verifier") || strings.Contains(body, "pkce"):
			// 授权码重放 / PKCE 校验失败：永久失败，不可恢复。
			return NewVerifyError(KindPKCE,
				"authorization code rejected (replayed or PKCE verification mismatch)")
		}
		return NewVerifyError(KindExchange, "token endpoint rejected the authorization code")
	}
	if isTransientNetwork(err) {
		return NewVerifyError(KindProviderUnavailable,
			"temporary network failure during token exchange").asTemporary()
	}
	return NewVerifyError(KindExchange, "token exchange failed")
}

// ClassifyDiscoveryError 把发现文档拉取阶段的错误统一分类为
// “提供方暂时不可用”。发现文档只来自 IdP 的受信地址，拉不到意味着
// 提供方当前不可用而非用户提供了非法材料，因此允许恢复。
func ClassifyDiscoveryError(err error) error {
	if err == nil {
		return nil
	}
	return NewVerifyError(KindDiscovery, "oidc discovery is temporarily unavailable").
		asTemporary()
}

// isTransientStatus 判断 HTTP 响应是否为暂时性服务端状态。
func isTransientStatus(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	code := resp.StatusCode
	return code == http.StatusTooManyRequests || code >= 500
}

// isTransientNetwork 判断错误链中是否存在暂时性网络/超时故障。
// 主动取消（context.Canceled，如客户端断开）不算可恢复。
func isTransientNetwork(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}
	return false
}
