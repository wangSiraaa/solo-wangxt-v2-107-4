package integration

// recoverable_helpers_test.go：假 IdP 驱动下的 HTTP 流程辅助。
//
// 与 browser_test.go 的区别：这里直接对应用发起的 URL 做“跟随到 IdP 再回跳”
// 的全自动流程（假 IdP 无需密码表单），并精确记录每一跳，便于断言代次/重放。

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

type flowClient struct {
	t    *testing.T
	http *http.Client
	// hops 记录每次最终请求的 URL（含应用回调），按时间顺序。
	hops []string
}

func newFlowClient(t *testing.T) *flowClient {
	jar, _ := cookiejar.New(nil)
	return &flowClient{
		t: t,
		http: &http.Client{
			Jar:     jar,
			Timeout: 0,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// doFollow 发起一个 GET，手动跟随所有 302（应用 <-> 假 IdP），
// 直到得到非 302 响应；过程中把每个请求 URL 记录到 hops。
func (c *flowClient) doFollow(raw string) *http.Response {
	c.t.Helper()
	current := raw
	for i := 0; i < 20; i++ {
		c.hops = append(c.hops, current)
		resp, err := c.http.Get(current)
		if err != nil {
			c.t.Fatalf("GET %s: %v", current, err)
		}
		if resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusSeeOther {
			loc := resp.Header.Get("Location")
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			current = resolveLocation(current, loc)
			continue
		}
		return resp
	}
	c.t.Fatalf("too many redirects from %s", raw)
	return nil
}

// doOnce 只发一次 GET，不跟随（用于观察 302 Location）。
func (c *flowClient) doOnce(raw string) *http.Response {
	c.t.Helper()
	resp, err := c.http.Get(raw)
	if err != nil {
		c.t.Fatalf("GET %s: %v", raw, err)
	}
	return resp
}

func (c *flowClient) cookie(name string) string {
	for _, ck := range c.allCookies() {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

func (c *flowClient) allCookies() []*http.Cookie {
	// jar 不暴露全部；按已知应用域取。
	u, _ := url.Parse("http://localhost")
	// 使用最后一跳的 host 更稳妥。
	if len(c.hops) > 0 {
		if pu, err := url.Parse(c.hops[0]); err == nil {
			u = pu
		}
	}
	return c.http.Jar.Cookies(u)
}

func resolveLocation(base, loc string) string {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	u, err := url.Parse(base)
	if err != nil {
		return loc
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return u.ResolveReference(ref).String()
}

// callbackURLFromHops 返回最后一跳（应用回调 URL，含 state/code）。
func (c *flowClient) callbackURLFromHops() string {
	if len(c.hops) == 0 {
		return ""
	}
	return c.hops[len(c.hops)-1]
}

// loginStartURL 构造应用登录启动地址。
func loginStartURL(base, slug, idpIssuer string) string {
	return base + "/t/" + slug + "/login?issuer=" + url.QueryEscape(idpIssuer)
}
