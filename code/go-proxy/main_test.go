package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newProxyForTest(t *testing.T, allow []string) *httptest.Server {
	t.Helper()
	cfg := config{
		insecure:   true,
		timeout:    5 * time.Second,
		maxBody:    1 << 20,
		allowHosts: allow,
	}
	s := &server{cfg: cfg, client: newHTTPClient(cfg)}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return ts
}

func TestForwardToUpstream(t *testing.T) {
	type captured struct {
		path       string
		method     string
		ct         string
		adminProto string
		ua         string
		body       string
	}
	var got captured

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = captured{
			path:       r.URL.Path,
			method:     r.Method,
			ct:         r.Header.Get("Content-Type"),
			adminProto: r.Header.Get("X-Admin-Protocol"),
			ua:         r.Header.Get("User-Agent"),
			body:       string(b),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	proxy := newProxyForTest(t, nil)
	host := strings.TrimPrefix(upstream.URL, "https://")
	payload := `{"pendingNotification":"QUJD"}`

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/esim_proxy", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Target-Host", host)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", resp.StatusCode)
	}
	if string(respBody) != `{"ok":true}` {
		t.Fatalf("响应体未透传: %q", string(respBody))
	}
	if got.path != es9HandleNotificationPath {
		t.Fatalf("上游路径 = %q, 期望 %q", got.path, es9HandleNotificationPath)
	}
	if got.method != http.MethodPost {
		t.Fatalf("上游方法 = %q", got.method)
	}
	if got.adminProto != headerAdminProtocol {
		t.Fatalf("X-Admin-Protocol = %q, 期望 %q", got.adminProto, headerAdminProtocol)
	}
	if got.ua != userAgentLPA {
		t.Fatalf("User-Agent = %q, 期望 %q", got.ua, userAgentLPA)
	}
	if got.body != payload {
		t.Fatalf("请求体未原样透传: %q", got.body)
	}
}

func TestRejectBadTargetHost(t *testing.T) {
	proxy := newProxyForTest(t, nil)

	cases := []struct {
		name string
		host string
	}{
		{"缺少头", ""},
		{"带协议", "https://smdp.example.com"},
		{"带路径", "smdp.example.com/evil"},
		{"带用户信息", "user@smdp.example.com"},
		{"端口越界", "smdp.example.com:99999"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/esim_proxy", strings.NewReader(`{}`))
			if tc.host != "" {
				req.Header.Set("X-Target-Host", tc.host)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("状态码 = %d, 期望 400", resp.StatusCode)
			}
		})
	}
}

func TestHostNotInAllowList(t *testing.T) {
	proxy := newProxyForTest(t, []string{"smdp.example.com"})

	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/esim_proxy", strings.NewReader(`{}`))
	req.Header.Set("X-Target-Host", "127.0.0.1:443")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("状态码 = %d, 期望 403", resp.StatusCode)
	}
}

func TestHealthPage(t *testing.T) {
	proxy := newProxyForTest(t, nil)

	resp, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, 期望 200", resp.StatusCode)
	}
	if !strings.Contains(string(b), "esim-proxy 运行正常") {
		t.Fatalf("健康页内容异常: %q", string(b))
	}
}

func TestMethodNotAllowed(t *testing.T) {
	proxy := newProxyForTest(t, nil)

	req, _ := http.NewRequest(http.MethodPut, proxy.URL+"/esim_proxy", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("状态码 = %d, 期望 405", resp.StatusCode)
	}
}

func TestEmptyBody(t *testing.T) {
	proxy := newProxyForTest(t, nil)

	req, _ := http.NewRequest(http.MethodPost, proxy.URL+"/esim_proxy", strings.NewReader("   "))
	req.Header.Set("X-Target-Host", "smdp.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, 期望 400", resp.StatusCode)
	}
}

func TestParseTargetHost(t *testing.T) {
	ok := []string{
		"smdp.example.com",
		"smdp.example.com:443",
		"127.0.0.1:8080",
		"a.b.c.example.com",
	}
	for _, host := range ok {
		if _, err := parseTargetHost(host); err != nil {
			t.Errorf("%q 应通过校验,却报错: %v", host, err)
		}
	}

	bad := []string{
		"",
		"https://smdp.example.com",
		"http://smdp.example.com",
		"smdp.example.com/path",
		"smdp.example.com?x=1",
		"smdp.example.com#frag",
		"user@smdp.example.com",
		"smdp.example.com:0",
		"smdp.example.com:abc",
		"with space.com",
	}
	for _, host := range bad {
		if _, err := parseTargetHost(host); err == nil {
			t.Errorf("%q 应被拒绝,却通过了", host)
		}
	}
}

func TestHostAllowedSuffixSafety(t *testing.T) {
	allow := []string{"smdp.example.com"}

	if !hostAllowed("smdp.example.com", allow) {
		t.Error("精确匹配应通过")
	}
	if !hostAllowed("eu.smdp.example.com:443", allow) {
		t.Error("子域应通过")
	}
	if hostAllowed("evilsmdp.example.com", allow) {
		t.Error("evilsmdp.example.com 不应匹配后缀白名单")
	}
	if hostAllowed("smdp.example.com.evil.net", allow) {
		t.Error("拼接到末尾的域名不应通过")
	}
	if !hostAllowed("anything.example", nil) {
		t.Error("白名单为空时应放行")
	}
}
