// esim-proxy 是 sms_forwarding 项目里 esim_proxy.php 的 Go 重写版本。
//
// 职责只有一个:接收 ESP32 上报的 eUICC PendingNotification,
// 原样转发到移动运营商 SM-DP+ 的 ES9+ HandleNotification 接口。
//
// 与 PHP 版的接口保持兼容:
//
//	POST /esim_proxy
//	X-Target-Host: smdp.example.com        // 由 ESP32 提供
//	Body: {"pendingNotification":"<base64>"}
//
// 转发目标固定为 https://<X-Target-Host>/gsma/rsp2/es9plus/handleNotification
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// ES9+ 通知上报接口路径,与 PHP 版写死的路径一致。
	es9HandleNotificationPath = "/gsma/rsp2/es9plus/handleNotification"

	// 运营商 SM-DP+ 用来识别 LPA 请求来源的两个头,PHP 版由 curl 补上。
	headerAdminProtocol = "gsma/rsp/v2.2.0"
	userAgentLPA        = "gsma-rsp-lpad"
)

const healthPage = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>esim-proxy</title></head>
<body style="font-family:system-ui,sans-serif;padding:24px">
<h2 style="color:#2e7d32">esim-proxy 运行正常</h2>
<p>请在 ESP32 后台把上报模式设为「自建」,并填入本服务地址,例如
<code>http://你的服务器IP:8080/esim_proxy</code></p>
<p style="color:#666">本服务只接受 POST;GET 仅用于健康检查。</p>
</body></html>`

type config struct {
	addr       string
	insecure   bool
	timeout    time.Duration
	allowHosts []string
	maxBody    int64
	certFile   string
	keyFile    string
}

type server struct {
	cfg    config
	client *http.Client
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("[esim-proxy] ")

	cfg := config{}
	var allowRaw string

	flag.StringVar(&cfg.addr, "addr", envOr("ESIM_PROXY_ADDR", ":8080"),
		"监听地址,例如 :8080 或 127.0.0.1:8080")
	flag.BoolVar(&cfg.insecure, "insecure", envBool("ESIM_PROXY_INSECURE"),
		"跳过 SM-DP+ 的 TLS 证书校验(PHP 版本默认就是不校验的)")
	flag.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "单次转发超时")
	flag.StringVar(&allowRaw, "allow-hosts", envOr("ESIM_PROXY_ALLOW_HOSTS", ""),
		"允许转发的 SM-DP+ 域名白名单,逗号分隔,支持后缀匹配;留空表示不限制")
	flag.Int64Var(&cfg.maxBody, "max-body", 1<<20, "请求体大小上限(字节)")
	flag.StringVar(&cfg.certFile, "cert", "", "TLS 证书文件;与 -key 同时提供时启用 HTTPS")
	flag.StringVar(&cfg.keyFile, "key", "", "TLS 私钥文件")
	flag.Parse()

	cfg.allowHosts = splitList(allowRaw)

	if cfg.insecure {
		log.Print("警告:已关闭上游证书校验(-insecure),仅建议在证书链异常时临时使用")
	}
	if len(cfg.allowHosts) == 0 {
		log.Print("提示:未配置 -allow-hosts,服务将接受任意目标域名;公网部署建议加白名单")
	}

	s := &server{cfg: cfg, client: newHTTPClient(cfg)}

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if cfg.certFile != "" && cfg.keyFile != "" {
			log.Printf("HTTPS 监听 %s", cfg.addr)
			errCh <- srv.ListenAndServeTLS(cfg.certFile, cfg.keyFile)
			return
		}
		log.Printf("HTTP 监听 %s", cfg.addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("启动失败: %v", err)
		}
	case <-ctx.Done():
		log.Print("收到退出信号,正在关闭...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("关闭异常: %v", err)
		}
	}
}

func newHTTPClient(cfg config) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		TLSClientConfig: &tls.Config{
			// 默认校验证书;PHP 版为了兼容性硬关了校验,
			// 这里做成开关,只有显式 -insecure 才跳过。
			InsecureSkipVerify: cfg.insecure,
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &http.Client{
		Timeout:   cfg.timeout + 5*time.Second,
		Transport: transport,
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	// 兼容任意路径的 POST,避免用户把 URL 填成 / 或别的路径时直接失败。
	mux.HandleFunc("/", s.handle)
	return mux
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	// 与 PHP 版保持一致,方便浏览器直接调试;ESP32 客户端本身不需要。
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, healthPage)
		}
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	started := time.Now()

	rawHost := r.Header.Get("X-Target-Host")
	host, err := parseTargetHost(rawHost)
	if err != nil {
		log.Printf("拒绝请求: %v (X-Target-Host=%q)", err, rawHost)
		http.Error(w, "bad X-Target-Host: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !hostAllowed(host, s.cfg.allowHosts) {
		log.Printf("域名不在白名单: %s", host)
		http.Error(w, "target host not allowed", http.StatusForbidden)
		return
	}

	body, err := readLimited(r.Body, s.cfg.maxBody)
	if err != nil {
		log.Printf("读取请求体失败: %v", err)
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	target := "https://" + host + es9HandleNotificationPath
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		log.Printf("构造上游请求失败: %v", err)
		http.Error(w, "build upstream request failed", http.StatusBadGateway)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Protocol", headerAdminProtocol)
	req.Header.Set("User-Agent", userAgentLPA)

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("转发失败 target=%s err=%v 耗时=%s", target, err, time.Since(started).Round(time.Millisecond))
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, s.cfg.maxBody))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	log.Printf("转发 target=%s status=%d req=%dB resp=%dB 耗时=%s",
		host, resp.StatusCode, len(body), len(respBody), time.Since(started).Round(time.Millisecond))
}

// parseTargetHost 校验并规范化 X-Target-Host。
// 只接受 host[:port],拒绝协议前缀、路径、查询串、用户信息等,
// 避免这个服务被当成任意 URL 的开放代理(SSRF)。
func parseTargetHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", fmt.Errorf("字段为空")
	}
	if len(h) > 253+6 {
		return "", fmt.Errorf("长度超限")
	}
	for _, bad := range []string{"://", "/", "\\", "?", "#", "@", " ", "\t", "\r", "\n"} {
		if strings.Contains(h, bad) {
			return "", fmt.Errorf("包含非法字符 %q", bad)
		}
	}

	u, err := url.Parse("https://" + h)
	if err != nil {
		return "", fmt.Errorf("无法解析")
	}
	if u.Host != h || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("只允许 host[:port] 形式")
	}

	// 带端口时校验端口范围;不带端口的纯域名/IP 直接放行。
	if strings.Contains(h, ":") || strings.HasPrefix(h, "[") {
		_, port, err := net.SplitHostPort(h)
		if err != nil {
			return "", fmt.Errorf("端口格式错误")
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("端口超出范围")
		}
	}
	return h, nil
}

// hostAllowed 做白名单匹配:精确相等或点号后缀匹配。
// 例如白名单 smdp.example.com 可匹配 a.smdp.example.com,但不会匹配 evilsmdp.example.com。
func hostAllowed(host string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.ToLower(strings.Trim(strings.TrimSuffix(name, "."), "[]"))

	for _, item := range allow {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if name == item || strings.HasSuffix(name, "."+item) {
			return true
		}
	}
	return false
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	lr := io.LimitReader(r, limit+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("请求体超过 %d 字节上限", limit)
	}
	return b, nil
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
