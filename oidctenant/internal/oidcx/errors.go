package oidcx

import (
	"errors"
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
	// KindProviderUnavailable 表示提供方暂时性不可用（网络错误 / 5xx /
	// 403 temporarily_unavailable / 429）。这是唯一允许安全重试的类别。
	KindProviderUnavailable VerifyKind = "provider_unavailable"
)

// VerifyError 是不包含任何敏感材料的认证失败错误。
type VerifyError struct {
	Kind VerifyKind
	Msg  string
	// Recoverable 表示该失败是“明确的暂时性提供方错误”，可以用全新的
	// state/nonce/PKCE 重新发起一次授权。签名/nonce/PKCE/受众等永久失败恒为 false。
	Recoverable bool
}

func (e *VerifyError) Error() string { return string(e.Kind) + ": " + e.Msg }

// NewVerifyError 构造一个认证失败错误。
func NewVerifyError(kind VerifyKind, msg string) *VerifyError {
	return &VerifyError{Kind: kind, Msg: msg}
}

func newRecoverableError(kind VerifyKind, msg string) *VerifyError {
	return &VerifyError{Kind: kind, Msg: msg, Recoverable: true}
}

// NewProviderUnavailable 构造一个明确可恢复的“提供方暂时不可用”错误，
// 供回调 error 参数（server_error / temporarily_unavailable）等场景使用。
func NewProviderUnavailable(msg string) *VerifyError {
	return newRecoverableError(KindProviderUnavailable, msg)
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
// 这里分类的每一种都是密码学/协议层面的永久失败：换一套 state/nonce/PKCE
// 重试不会让结果变好，且允许重试反而可能被用来把一次性材料多投一次。
func classifyVerifyError(err error) error {
	if err == nil {
		return nil
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

// classifyExchangeError 区分令牌端点返回的：
//   - 永久失败（invalid_grant：授权码已重放/过期、PKCE 校验不过；
//     invalid_client / invalid_request：配置或请求本身有误）—— 不可恢复；
//   - 暂时性失败（HTTP 5xx、429、403 temporarily_unavailable、网络错误）—— 可恢复。
func classifyExchangeError(err error) error {
	if err == nil {
		return nil
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		body := strings.ToLower(string(retrieveErr.Body))
		code := strings.ToLower(retrieveErr.ErrorCode)
		if strings.Contains(body, "invalid_grant") || code == "invalid_grant" ||
			strings.Contains(body, "code_verifier") || strings.Contains(body, "pkce") {
			// 授权码重放/错配、PKCE 不匹配：重试绝无可能成功。
			return NewVerifyError(KindPKCE,
				"authorization code rejected (replayed or PKCE verification mismatch)")
		}
		if isTemporaryProviderStatus(retrieveErr.Response) ||
			strings.Contains(body, "temporarily_unavailable") ||
			code == "temporarily_unavailable" ||
			strings.Contains(body, "slow down") {
			return newRecoverableError(KindProviderUnavailable,
				"token endpoint is temporarily unavailable")
		}
		if code == "invalid_client" || code == "invalid_request" ||
			strings.Contains(body, "unauthorized_client") || code == "invalid_scope" {
			return NewVerifyError(KindExchange, "token endpoint rejected the request")
		}
		// 其余带 HTTP 状态的响应按状态码判定（5xx/429 可恢复，其余不可恢复）。
		if isTemporaryProviderStatus(retrieveErr.Response) {
			return newRecoverableError(KindProviderUnavailable,
				"token endpoint responded with a temporary status")
		}
		return NewVerifyError(KindExchange, "token endpoint rejected the authorization code")
	}
	if isNetworkUnavailable(err) {
		return newRecoverableError(KindProviderUnavailable,
			"token endpoint could not be reached")
	}
	return NewVerifyError(KindExchange, "token exchange failed")
}

// isTemporaryProviderStatus 判断 HTTP 状态码是否明确表示“提供方暂时性故障”。
func isTemporaryProviderStatus(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusGatewayTimeout ||
		(resp.StatusCode >= 500 && resp.StatusCode < 600)
}

// ClassifyDiscoveryError 归类发现文档拉取失败：只有网络不可达/5xx 算暂时性。
func ClassifyDiscoveryError(err error) error {
	if err == nil {
		return nil
	}
	if isNetworkUnavailable(err) {
		return newRecoverableError(KindProviderUnavailable,
			"provider discovery could not be reached")
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) && retrieveErr.Response != nil &&
		retrieveErr.Response.StatusCode >= 500 && retrieveErr.Response.StatusCode < 600 {
		return newRecoverableError(KindProviderUnavailable,
			"provider discovery responded with a temporary status")
	}
	return NewVerifyError(KindDiscovery, "oidc provider discovery failed")
}

func isNetworkUnavailable(err error) bool {
	if err == nil {
		return false
	}
	// 连接被拒 / 超时 / DNS / EOF / 连接重置：对端稍后可能恢复。
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "temporarily unavailable"),
		strings.Contains(msg, "server misbehaving"),
		strings.Contains(msg, "eof"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "tls handshake timeout"):
		return true
	}
	return false
}
