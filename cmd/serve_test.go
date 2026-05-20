package cmd

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"tailscale.com/types/key"
)

func TestGetTailscaleTarget(t *testing.T) {
	withProxyTestGlobals(t)

	tests := []struct {
		name   string
		path   string
		ua     string
		auth   string
		target string
	}{
		{name: "control protocol", path: "/ts2021", target: upstreamRoleControl},
		{name: "api route", path: "/api/v2/tailnet", target: upstreamRoleControl},
		{name: "machine route", path: "/machine/register", target: upstreamRoleControl},
		{name: "derp route", path: "/derp/map", target: upstreamRoleDERP},
		{name: "web login route", path: "/login", target: upstreamRoleLogin},
		{name: "tailscale auth request", path: "/auth", ua: "tailscale/1.0", target: upstreamRoleLogin},
		{name: "tailscale authenticated request", path: "/device", ua: "tailscale/1.0", auth: "Bearer token", target: upstreamRoleControl},
		{name: "default web route", path: "/", ua: "Mozilla/5.0", target: upstreamRoleLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.ua != "" {
				req.Header.Set("User-Agent", tt.ua)
			}
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			if got := getTailscaleTarget(req); got != tt.target {
				t.Fatalf("target = %q, want %q", got, tt.target)
			}
		})
	}
}

func TestRewriteTailscaleURL(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "login https",
			in:   "https://login.tailscale.com/welcome",
			want: "https://proxy.example.com/welcome",
		},
		{
			name: "controlplane http",
			in:   "http://controlplane.tailscale.com/key",
			want: "https://proxy.example.com/key",
		},
		{
			name: "protocol relative",
			in:   "//login.tailscale.com/bootstrap",
			want: "//proxy.example.com/bootstrap",
		},
		{
			name: "non tailscale unchanged",
			in:   "https://example.com/keep",
			want: "https://example.com/keep",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rewriteTailscaleURL(tt.in); got != tt.want {
				t.Fatalf("rewriteTailscaleURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRewriteTailscaleURLsInBody(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	body := strings.Join([]string{
		`{"login":"https://login.tailscale.com/start"}`,
		`"https://controlplane.tailscale.com/key"`,
		`//login.tailscale.com/bootstrap`,
		`https://example.com/unchanged`,
	}, "\n")

	got := rewriteTailscaleURLsInBody(body)
	for _, want := range []string{
		"https://proxy.example.com/start",
		"https://proxy.example.com/key",
		"//proxy.example.com/bootstrap",
		"https://example.com/unchanged",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten body missing %q: %s", want, got)
		}
	}
}

func TestRewriteTailscaleURLCustomUpstream(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://headscale.example.com"),
		control: mustParseURL(t, "https://headscale.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	if got := rewriteTailscaleURL("https://headscale.example.com/register"); got != "https://proxy.example.com/register" {
		t.Fatalf("rewriteTailscaleURL(custom) = %q", got)
	}
	if got := rewriteTailscaleURL("//headscale.example.com/login"); got != "//proxy.example.com/login" {
		t.Fatalf("rewriteTailscaleURL(protocol relative custom) = %q", got)
	}
	if got := rewriteTailscaleURL("https://proxy.example.com/register"); got != "https://proxy.example.com/register" {
		t.Fatalf("rewriteTailscaleURL(proxy) = %q", got)
	}
}

func TestParseUpstreamConfig(t *testing.T) {
	t.Run("custom control keeps default derp", func(t *testing.T) {
		cfg, err := parseUpstreamConfig("https://headscale.example.com", "")
		if err != nil {
			t.Fatalf("parseUpstreamConfig returned error: %v", err)
		}
		if got := cfg.control.String(); got != "https://headscale.example.com" {
			t.Fatalf("control upstream = %q", got)
		}
		if got := cfg.login.String(); got != "https://headscale.example.com" {
			t.Fatalf("login upstream = %q", got)
		}
		if got := cfg.derp.String(); got != "https://derp.tailscale.com" {
			t.Fatalf("derp upstream = %q", got)
		}
	})

	t.Run("custom derp override", func(t *testing.T) {
		cfg, err := parseUpstreamConfig("https://headscale.example.com", "https://derp.example.com:4443")
		if err != nil {
			t.Fatalf("parseUpstreamConfig returned error: %v", err)
		}
		if got := cfg.derp.String(); got != "https://derp.example.com:4443" {
			t.Fatalf("derp upstream = %q", got)
		}
	})

	t.Run("rejects invalid control upstream", func(t *testing.T) {
		if _, err := parseUpstreamConfig("http://headscale.example.com/path", ""); err == nil {
			t.Fatal("expected validation error")
		}
	})
}

func TestSetupXForwardedHeaders(t *testing.T) {
	t.Run("adds headers in http only mode", func(t *testing.T) {
		withProxyTestGlobals(t)
		httpOnly = true

		req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/key", nil)
		req.Host = "proxy.example.com"
		req.RemoteAddr = "203.0.113.10:12345"

		setupXForwardedHeaders(req)

		if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
			t.Fatalf("X-Forwarded-For = %q, want %q", got, "203.0.113.10")
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q, want https", got)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "proxy.example.com" {
			t.Fatalf("X-Forwarded-Host = %q, want proxy.example.com", got)
		}
	})

	t.Run("preserves preexisting forwarded headers", func(t *testing.T) {
		withProxyTestGlobals(t)
		httpOnly = true

		req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/key", nil)
		req.Host = "proxy.example.com"
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", "198.51.100.10")
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "existing.example.com")

		setupXForwardedHeaders(req)

		if got := req.Header.Get("X-Forwarded-For"); got != "198.51.100.10" {
			t.Fatalf("X-Forwarded-For = %q, want preserved value", got)
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
			t.Fatalf("X-Forwarded-Proto = %q, want preserved value", got)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "existing.example.com" {
			t.Fatalf("X-Forwarded-Host = %q, want preserved value", got)
		}
	})
}

func TestBuildMainHandlerRoutesRequests(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	httpOnly = true

	loginUpstream := newRecordedUpstream(t, "login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("login"))
	})
	controlplaneUpstream := newRecordedUpstream(t, "controlplane", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("controlplane"))
	})
	derpUpstream := newRecordedUpstream(t, "derp", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("derp"))
	})

	resolveProxyTarget = func(target string) *url.URL {
		switch target {
		case upstreamRoleLogin:
			return mustParseURL(t, loginUpstream.server.URL)
		case upstreamRoleControl:
			return mustParseURL(t, controlplaneUpstream.server.URL)
		case upstreamRoleDERP:
			return mustParseURL(t, derpUpstream.server.URL)
		default:
			t.Fatalf("unexpected target %q", target)
			return nil
		}
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	client := proxy.Client()

	resp, err := client.Get(proxy.URL + "/health")
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	body := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Tailscale Proxy is running") {
		t.Fatalf("unexpected health body %q", body)
	}
	if loginUpstream.count() != 0 || controlplaneUpstream.count() != 0 || derpUpstream.count() != 0 {
		t.Fatalf("health request should not hit upstreams")
	}

	assertProxyResponseBody(t, client, proxy.URL+"/key", "controlplane")
	assertProxyResponseBody(t, client, proxy.URL+"/login", "login")
	assertProxyResponseBody(t, client, proxy.URL+"/derp/map", "derp")
	assertProxyResponseBody(t, client, proxy.URL+"/docs", "login")

	controlReq := controlplaneUpstream.lastRequest()
	if controlReq.Path != "/key" {
		t.Fatalf("controlplane path = %q, want /key", controlReq.Path)
	}
	if controlReq.ForwardedProto != "https" {
		t.Fatalf("X-Forwarded-Proto = %q, want https", controlReq.ForwardedProto)
	}
	if controlReq.ForwardedHost == "" {
		t.Fatal("expected X-Forwarded-Host to be populated")
	}
	if controlReq.ForwardedFor == "" {
		t.Fatal("expected X-Forwarded-For to be populated")
	}
}

func TestBuildMainHandlerRoutesCustomControlButKeepsDefaultDERP(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	httpOnly = true
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://headscale.example.com"),
		control: mustParseURL(t, "https://headscale.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	controlplaneUpstream := newRecordedUpstream(t, "controlplane", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("controlplane"))
	})
	derpUpstream := newRecordedUpstream(t, "derp", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("derp"))
	})

	resolveProxyTarget = func(target string) *url.URL {
		switch target {
		case upstreamRoleLogin, upstreamRoleControl:
			return mustParseURL(t, controlplaneUpstream.server.URL)
		case upstreamRoleDERP:
			return mustParseURL(t, derpUpstream.server.URL)
		default:
			t.Fatalf("unexpected target %q", target)
			return nil
		}
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	assertProxyResponseBody(t, proxy.Client(), proxy.URL+"/login", "controlplane")
	assertProxyResponseBody(t, proxy.Client(), proxy.URL+"/key", "controlplane")
	assertProxyResponseBody(t, proxy.Client(), proxy.URL+"/derp/map", "derp")

	if got := activeUpstreams.derp.String(); got != "https://derp.tailscale.com" {
		t.Fatalf("derp upstream = %q", got)
	}
}

func TestBuildMainHandlerRewritesResponses(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	upstream := newRecordedUpstream(t, "controlplane", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "https://login.tailscale.com/welcome")
		_, _ = w.Write([]byte(`{"login":"https://controlplane.tailscale.com/key","bootstrap":"//login.tailscale.com/bootstrap"}`))
	})

	resolveProxyTarget = func(target string) *url.URL {
		return mustParseURL(t, upstream.server.URL)
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	resp, err := proxy.Client().Get(proxy.URL + "/key")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Location"); got != "https://proxy.example.com/welcome" {
		t.Fatalf("Location = %q, want rewritten location", got)
	}

	body := readBody(t, resp.Body)
	for _, want := range []string{
		"https://proxy.example.com/key",
		"//proxy.example.com/bootstrap",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rewritten body missing %q: %s", want, body)
		}
	}
}

func TestBuildMainHandlerRewritesCustomRegisterResponses(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://upstream.example.com"),
		control: mustParseURL(t, "https://upstream.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	const registerURL = "https://upstream.example.com/register/token-123?via=cli"
	upstream := newRecordedUpstream(t, "controlplane", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Location", registerURL)
		_, _ = w.Write([]byte("visit " + registerURL))
	})

	resolveProxyTarget = func(target string) *url.URL {
		return mustParseURL(t, upstream.server.URL)
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	resp, err := proxy.Client().Get(proxy.URL + "/register/token-123")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Location"); got != "https://proxy.example.com/register/token-123?via=cli" {
		t.Fatalf("Location = %q, want rewritten register URL", got)
	}
	if body := readBody(t, resp.Body); body != "visit https://proxy.example.com/register/token-123?via=cli" {
		t.Fatalf("body = %q, want rewritten register URL", body)
	}
}

func TestTS2021HandlerPreservesMethodAndUpgradeHeaders(t *testing.T) {
	withProxyTestGlobals(t)

	var receivedMethod string
	var receivedConnection string
	var receivedUpgrade string

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ts2021" {
			t.Fatalf("backend path = %q, want /ts2021", r.URL.Path)
		}
		receivedMethod = r.Method
		receivedConnection = r.Header.Get("Connection")
		receivedUpgrade = r.Header.Get("Upgrade")
		w.Header().Set("X-Upstream", "local-fake")
		_, _ = w.Write([]byte("controlplane ok"))
	}))
	t.Cleanup(backend.Close)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		if addr != "controlplane.tailscale.com:443" {
			t.Fatalf("dial addr = %q, want %q", addr, "controlplane.tailscale.com:443")
		}
		if config.ServerName != "controlplane.tailscale.com" {
			t.Fatalf("server name = %q", config.ServerName)
		}
		return tls.Dial(network, strings.TrimPrefix(backend.URL, "https://"), &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/ts2021", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tailscale-control-protocol")

	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("ts2021 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream"); got != "local-fake" {
		t.Fatalf("X-Upstream = %q, want local-fake", got)
	}
	if body := readBody(t, resp.Body); body != "controlplane ok" {
		t.Fatalf("body = %q, want controlplane ok", body)
	}
	if receivedMethod != http.MethodPost {
		t.Fatalf("backend method = %q, want POST", receivedMethod)
	}
	if receivedConnection != "upgrade" {
		t.Fatalf("backend Connection = %q, want upgrade", receivedConnection)
	}
	if receivedUpgrade != "tailscale-control-protocol" {
		t.Fatalf("backend Upgrade = %q, want tailscale-control-protocol", receivedUpgrade)
	}
}

func TestTS2021HandlerRewritesRegisterURLsInNonUpgradeResponse(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	const registerURL = "https://controlplane.tailscale.com/register/token-456?via=ts2021"
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ts2021" {
			t.Fatalf("backend path = %q, want /ts2021", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", registerURL)
		_, _ = w.Write([]byte(`{"register":"` + registerURL + `"}`))
	}))
	t.Cleanup(backend.Close)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		if addr != "controlplane.tailscale.com:443" {
			t.Fatalf("dial addr = %q, want controlplane.tailscale.com:443", addr)
		}
		if config.ServerName != "controlplane.tailscale.com" {
			t.Fatalf("server name = %q, want controlplane.tailscale.com", config.ServerName)
		}
		return tls.Dial(network, strings.TrimPrefix(backend.URL, "https://"), &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/ts2021", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tailscale-control-protocol")

	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("ts2021 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://proxy.example.com/register/token-456?via=ts2021" {
		t.Fatalf("Location = %q, want rewritten register URL", got)
	}
	if body := readBody(t, resp.Body); body != `{"register":"https://proxy.example.com/register/token-456?via=ts2021"}` {
		t.Fatalf("body = %q, want rewritten register URL", body)
	}
}

func TestTS2021HandlerDoesNotRewriteSwitchingProtocolsTrafficInTransparentMode(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	const streamPayload = "https://upstream.example.com/register/token-789?via=tunnel"
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("backend response writer does not support hijacking")
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("backend hijack: %v", err)
		}
		defer conn.Close()

		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		_, _ = rw.WriteString("Connection: Upgrade\r\n")
		_, _ = rw.WriteString("Upgrade: tailscale-control-protocol\r\n")
		_, _ = rw.WriteString("\r\n")
		if err := rw.Flush(); err != nil {
			t.Fatalf("backend flush: %v", err)
		}

		if _, err := io.WriteString(conn, streamPayload); err != nil {
			t.Fatalf("backend write payload: %v", err)
		}
	}))
	t.Cleanup(backend.Close)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return tls.Dial(network, strings.TrimPrefix(backend.URL, "https://"), &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); got != "tailscale-control-protocol" {
		t.Fatalf("Upgrade = %q, want tailscale-control-protocol", got)
	}

	payload := make([]byte, len(streamPayload))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("read tunneled payload: %v", err)
	}
	if got := string(payload); got != streamPayload {
		t.Fatalf("payload = %q, want %q", got, streamPayload)
	}
}

func TestControlPlaneDialAddressUsesConfiguredControlUpstream(t *testing.T) {
	withProxyTestGlobals(t)
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://headscale.example.com:8443"),
		control: mustParseURL(t, "https://headscale.example.com:8443"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	dialAddr, serverName := controlPlaneDialAddress()
	if dialAddr != "headscale.example.com:8443" {
		t.Fatalf("dial addr = %q", dialAddr)
	}
	if serverName != "headscale.example.com" {
		t.Fatalf("server name = %q", serverName)
	}
}

func TestTS2021HandlerReturnsBadGatewayOnDialFailure(t *testing.T) {
	withProxyTestGlobals(t)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return nil, errors.New("boom")
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	resp, err := proxy.Client().Get(proxy.URL + "/ts2021")
	if err != nil {
		t.Fatalf("ts2021 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func withProxyTestGlobals(t *testing.T) {
	t.Helper()

	oldDomain := domain
	oldPort := port
	oldHTTPSPort := httpsPort
	oldEmail := email
	oldCertDir := certDir
	oldIssueCerts := issueCerts
	oldDebug := debug
	oldHTTPOnly := httpOnly
	oldBindAddr := bindAddr
	oldUpstreamURL := upstreamURL
	oldUpstreamDERPURL := upstreamDERPURL
	oldTS2021KeyFile := ts2021KeyFile
	oldLogger := logger
	oldActiveUpstreams := activeUpstreams
	oldResolveProxyTarget := resolveProxyTarget
	oldDialControlPlane := dialControlPlane
	oldTS2021Proxy := activeTS2021Proxy

	ts2021ServerKeyOnce = sync.Once{}
	ts2021ServerKey = key.MachinePrivate{}
	ts2021ServerKeyErr = nil
	domain = "proxy.example.com"
	port = "80"
	httpsPort = "443"
	email = ""
	certDir = ""
	issueCerts = false
	debug = false
	httpOnly = false
	bindAddr = "127.0.0.1"
	upstreamURL = ""
	upstreamDERPURL = ""
	ts2021KeyFile = ""
	logger = nil
	activeUpstreams = defaultUpstreamConfig()
	resolveProxyTarget = oldResolveProxyTarget
	dialControlPlane = oldDialControlPlane
	activeTS2021Proxy = newTS2021Proxy()

	t.Cleanup(func() {
		domain = oldDomain
		port = oldPort
		httpsPort = oldHTTPSPort
		email = oldEmail
		certDir = oldCertDir
		issueCerts = oldIssueCerts
		debug = oldDebug
		httpOnly = oldHTTPOnly
		bindAddr = oldBindAddr
		upstreamURL = oldUpstreamURL
		upstreamDERPURL = oldUpstreamDERPURL
		ts2021KeyFile = oldTS2021KeyFile
		logger = oldLogger
		activeUpstreams = oldActiveUpstreams
		resolveProxyTarget = oldResolveProxyTarget
		dialControlPlane = oldDialControlPlane
		activeTS2021Proxy = oldTS2021Proxy
		ts2021ServerKeyOnce = sync.Once{}
		ts2021ServerKey = key.MachinePrivate{}
		ts2021ServerKeyErr = nil
	})
}

func assertProxyResponseBody(t *testing.T, client *http.Client, endpoint, want string) {
	t.Helper()

	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d, want 200", endpoint, resp.StatusCode)
	}
	if got := readBody(t, resp.Body); got != want {
		t.Fatalf("%s body = %q, want %q", endpoint, got, want)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}

	return parsed
}

func readBody(t *testing.T, body io.ReadCloser) string {
	t.Helper()

	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return string(payload)
}

type recordedUpstream struct {
	server *httptest.Server

	mu      sync.Mutex
	counts  int
	records []upstreamRequest
}

type upstreamRequest struct {
	Path           string
	Host           string
	ForwardedFor   string
	ForwardedHost  string
	ForwardedProto string
}

func newRecordedUpstream(t *testing.T, _ string, responder func(http.ResponseWriter, *http.Request)) *recordedUpstream {
	t.Helper()

	upstream := &recordedUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.mu.Lock()
		upstream.counts++
		upstream.records = append(upstream.records, upstreamRequest{
			Path:           r.URL.Path,
			Host:           r.Host,
			ForwardedFor:   r.Header.Get("X-Forwarded-For"),
			ForwardedHost:  r.Header.Get("X-Forwarded-Host"),
			ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
		})
		upstream.mu.Unlock()

		responder(w, r)
	}))
	t.Cleanup(upstream.server.Close)

	return upstream
}

func (u *recordedUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()

	return u.counts
}

func (u *recordedUpstream) lastRequest() upstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()

	if len(u.records) == 0 {
		return upstreamRequest{}
	}

	return u.records[len(u.records)-1]
}
