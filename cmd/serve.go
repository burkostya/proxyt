package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	log "github.com/jaxxstorm/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/acme/autocert"
)

var (
	domain             string
	port               string
	httpsPort          string
	email              string
	certDir            string
	issueCerts         bool
	debug              bool
	httpOnly           bool
	bindAddr           string
	upstreamURL        string
	upstreamDERPURL    string
	ts2021KeyFile      string
	logger             *log.Logger
	activeUpstreams    = defaultUpstreamConfig()
	resolveProxyTarget = func(target string) *url.URL {
		return activeUpstreams.resolve(target)
	}
	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return tls.Dial(network, addr, config)
	}
)

const (
	upstreamRoleLogin   = "login"
	upstreamRoleControl = "control"
	upstreamRoleDERP    = "derp"
)

type upstreamConfig struct {
	login   *url.URL
	control *url.URL
	derp    *url.URL
}

func defaultUpstreamConfig() upstreamConfig {
	return upstreamConfig{
		login:   mustParseUpstreamURL("https://login.tailscale.com"),
		control: mustParseUpstreamURL("https://controlplane.tailscale.com"),
		derp:    mustParseUpstreamURL("https://derp.tailscale.com"),
	}
}

func mustParseUpstreamURL(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return parsed
}

func (c upstreamConfig) resolve(role string) *url.URL {
	switch role {
	case upstreamRoleLogin:
		return cloneURL(c.login)
	case upstreamRoleControl:
		return cloneURL(c.control)
	case upstreamRoleDERP:
		return cloneURL(c.derp)
	default:
		return nil
	}
}

func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return nil
	}
	cloned := *in
	return &cloned
}

func parseUpstreamConfig(controlRaw, derpRaw string) (upstreamConfig, error) {
	cfg := defaultUpstreamConfig()

	if controlRaw != "" {
		parsedControl, err := parseUpstreamURL(controlRaw, "upstream-url")
		if err != nil {
			return upstreamConfig{}, err
		}
		cfg.login = parsedControl
		cfg.control = parsedControl
	}

	if derpRaw != "" {
		parsedDERP, err := parseUpstreamURL(derpRaw, "upstream-derp-url")
		if err != nil {
			return upstreamConfig{}, err
		}
		cfg.derp = parsedDERP
	}

	return cfg, nil
}

func parseUpstreamURL(raw, flagName string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be a valid URL: %w", flagName, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%s must use https", flagName)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%s must include a host", flagName)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%s must not include user info", flagName)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must not include a query string or fragment", flagName)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("%s must not include a path", flagName)
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return parsed, nil
}

func controlPlaneDialAddress() (addr string, serverName string) {
	control := activeUpstreams.control
	serverName = control.Hostname()
	addr = control.Host
	if control.Port() == "" {
		addr = net.JoinHostPort(serverName, "443")
	}
	return addr, serverName
}

func upstreamRewriteSources() []string {
	defaults := defaultUpstreamConfig()
	sources := []string{
		"https://login.tailscale.com",
		"http://login.tailscale.com",
		"https://controlplane.tailscale.com",
		"http://controlplane.tailscale.com",
		"//login.tailscale.com",
		"//controlplane.tailscale.com",
	}

	for _, upstream := range []*url.URL{activeUpstreams.login, activeUpstreams.control} {
		if upstream == nil {
			continue
		}
		sources = append(sources,
			upstreamOrigin(upstream, "https"),
			upstreamOrigin(upstream, "http"),
			"//"+upstream.Host,
		)
	}

	if activeUpstreams.derp != nil && activeUpstreams.derp.Host != defaults.derp.Host {
		sources = append(sources,
			upstreamOrigin(activeUpstreams.derp, "https"),
			upstreamOrigin(activeUpstreams.derp, "http"),
			"//"+activeUpstreams.derp.Host,
		)
	}

	return dedupeStrings(sources)
}

func upstreamOrigin(target *url.URL, scheme string) string {
	return scheme + "://" + target.Host
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Tailscale login server proxy",
	Long:  `A proxy server to use when Tailscale is blocked on your domain.`,
	Run: func(cmd *cobra.Command, args []string) {
		runProxy()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name for the proxy (required)")
	serveCmd.Flags().StringVarP(&port, "port", "p", "80", "HTTP port for Let's Encrypt challenges or main port in HTTP-only mode")
	serveCmd.Flags().StringVar(&httpsPort, "https-port", "443", "HTTPS port for the proxy")
	serveCmd.Flags().StringVarP(&email, "email", "e", "", "Email address for Let's Encrypt registration")
	serveCmd.Flags().StringVar(&certDir, "cert-dir", "", "Directory to store/read SSL certificates (required when not using --http-only)")
	serveCmd.Flags().BoolVar(&issueCerts, "issue", true, "Automatically issue Let's Encrypt certificates")
	serveCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging for all requests")
	serveCmd.Flags().BoolVar(&httpOnly, "http-only", false, "Run in HTTP-only mode (for use behind HTTPS proxy/load balancer)")
	serveCmd.Flags().StringVar(&bindAddr, "bind", "0.0.0.0", "Address to bind the server to")
	serveCmd.Flags().StringVar(&upstreamURL, "upstream-url", "", "Custom control/login upstream URL (for example https://headscale.example.com)")
	serveCmd.Flags().StringVar(&upstreamDERPURL, "upstream-derp-url", "", "Optional custom DERP upstream URL")
	serveCmd.Flags().StringVar(&ts2021KeyFile, "ts2021-key-file", "", "Path to a persistent TS2021 proxy private key file")

	// Bind environment variables
	viper.SetEnvPrefix("PROXYT")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.BindPFlag("domain", serveCmd.Flags().Lookup("domain"))
	viper.BindPFlag("port", serveCmd.Flags().Lookup("port"))
	viper.BindPFlag("https-port", serveCmd.Flags().Lookup("https-port"))
	viper.BindPFlag("email", serveCmd.Flags().Lookup("email"))
	viper.BindPFlag("cert-dir", serveCmd.Flags().Lookup("cert-dir"))
	viper.BindPFlag("issue", serveCmd.Flags().Lookup("issue"))
	viper.BindPFlag("debug", serveCmd.Flags().Lookup("debug"))
	viper.BindPFlag("http-only", serveCmd.Flags().Lookup("http-only"))
	viper.BindPFlag("bind", serveCmd.Flags().Lookup("bind"))
	viper.BindPFlag("upstream-url", serveCmd.Flags().Lookup("upstream-url"))
	viper.BindPFlag("upstream-derp-url", serveCmd.Flags().Lookup("upstream-derp-url"))
	viper.BindPFlag("ts2021-key-file", serveCmd.Flags().Lookup("ts2021-key-file"))
}

func runProxy() {
	// Read values from viper (supports both flags and environment variables)
	domain = viper.GetString("domain")
	port = viper.GetString("port")
	httpsPort = viper.GetString("https-port")
	email = viper.GetString("email")
	certDir = viper.GetString("cert-dir")
	issueCerts = viper.GetBool("issue")
	debug = viper.GetBool("debug")
	httpOnly = viper.GetBool("http-only")
	bindAddr = viper.GetString("bind")
	upstreamURL = viper.GetString("upstream-url")
	upstreamDERPURL = viper.GetString("upstream-derp-url")
	ts2021KeyFile = viper.GetString("ts2021-key-file")

	var err error
	logger, err = newRuntimeLogger(debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer closeRuntimeLogger(logger)

	// Validate required flags based on mode
	if domain == "" {
		logger.Fatal("domain is required")
	}
	if !httpOnly && certDir == "" {
		logger.Fatal("cert-dir is required when not using --http-only mode")
	}

	activeUpstreams, err = parseUpstreamConfig(upstreamURL, upstreamDERPURL)
	if err != nil {
		logger.Fatal("invalid upstream configuration", log.Error(err))
	}
	if err := requirePersistentTS2021KeyForCustomUpstream(); err != nil {
		logger.Fatal("invalid TS2021 proxy key configuration", log.Error(err))
	}

	logger.Info("Starting Tailscale proxy",
		log.String("domain", domain),
		log.Bool("http_only", httpOnly),
		log.String("control_upstream", activeUpstreams.control.String()),
		log.String("derp_upstream", activeUpstreams.derp.String()))

	if debug {
		logger.Info("Debug logging enabled")
	}

	var certManager *autocert.Manager
	var tlsConfig *tls.Config

	if !httpOnly && issueCerts {
		// Validate email is required for Let's Encrypt
		if email == "" {
			logger.Fatal("Email is required when --issue is true for Let's Encrypt registration")
		}

		// Set up Let's Encrypt certificate manager
		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(certDir),
			HostPolicy: autocert.HostWhitelist(domain),
			Email:      email,
		}

		tlsConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
		}

		logger.Info("Automatic certificate issuance enabled", log.String("domain", domain))
	} else if !httpOnly {
		// Check if certificates exist in cert-dir
		certFile := filepath.Join(certDir, domain+".crt")
		keyFile := filepath.Join(certDir, domain+".key")

		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			logger.Fatal("Certificate file not found (required when --issue=false)", log.String("file", certFile))
		}
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			logger.Fatal("Key file not found (required when --issue=false)", log.String("file", keyFile))
		}

		// Load existing certificates
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Fatal("Failed to load certificates", log.Error(err))
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		logger.Info("Using existing certificates", log.String("cert_dir", certDir))
	}

	mainHandler := buildMainHandler(nil)

	var servers []*http.Server

	if httpOnly {
		// HTTP-only mode for use behind HTTPS proxy/load balancer
		httpServer := &http.Server{
			Addr:    bindAddr + ":" + port,
			Handler: mainHandler,
		}
		servers = append(servers, httpServer)

		logger.Info("HTTP-only mode enabled - running behind HTTPS proxy",
			log.String("bind_addr", bindAddr),
			log.String("port", port))
	} else {
		// Full HTTPS mode with optional HTTP for Let's Encrypt

		// Create HTTPS server
		httpsServer := &http.Server{
			Addr:      bindAddr + ":" + httpsPort,
			Handler:   mainHandler,
			TLSConfig: tlsConfig,
		}
		servers = append(servers, httpsServer)

		var httpServer *http.Server

		if issueCerts {
			// Create HTTP server that handles Let's Encrypt challenges
			httpMux := http.NewServeMux()

			// Handle Let's Encrypt challenges
			httpMux.Handle("/.well-known/", certManager.HTTPHandler(nil))

			// Redirect all other HTTP requests to HTTPS
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// Don't redirect ACME challenges
				if strings.HasPrefix(r.URL.Path, "/.well-known/") {
					certManager.HTTPHandler(nil).ServeHTTP(w, r)
					return
				}

				// Redirect to HTTPS
				httpsURL := "https://" + r.Host + r.RequestURI
				if httpsPort != "443" {
					httpsURL = "https://" + domain + ":" + httpsPort + r.RequestURI
				}
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			})

			httpServer = &http.Server{
				Addr:    bindAddr + ":" + port,
				Handler: httpMux,
			}
		} else {
			// Simple HTTP server that redirects to HTTPS
			httpMux := http.NewServeMux()
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				httpsURL := "https://" + r.Host + r.RequestURI
				if httpsPort != "443" {
					httpsURL = "https://" + domain + ":" + httpsPort + r.RequestURI
				}
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			})

			httpServer = &http.Server{
				Addr:    bindAddr + ":" + port,
				Handler: httpMux,
			}
		}

		if httpServer != nil {
			servers = append(servers, httpServer)
		}
	}

	// Channel to listen for interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start all servers
	for _, server := range servers {
		go func(srv *http.Server) {
			if srv.TLSConfig != nil {
				// HTTPS server
				logger.Info("Starting HTTPS proxy server",
					log.String("addr", srv.Addr),
					log.String("domain", domain))
				if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					logger.Fatal("HTTPS server failed", log.Error(err))
				}
			} else {
				// HTTP server
				if httpOnly {
					logger.Info("Starting HTTP proxy server (behind HTTPS proxy)",
						log.String("addr", srv.Addr))
				} else if issueCerts {
					logger.Info("Starting HTTP server for Let's Encrypt challenges and redirects",
						log.String("addr", srv.Addr))
				} else {
					logger.Info("Starting HTTP server for HTTPS redirects",
						log.String("addr", srv.Addr))
				}
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal("HTTP server failed", log.Error(err))
				}
			}
		}(server)
	}

	// Wait for interrupt signal
	<-stop
	logger.Info("Shutting down servers...")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown all servers
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Server shutdown error", log.String("addr", server.Addr), log.Error(err))
		}
	}

	logger.Info("Servers stopped")
}

func buildMainHandler(transport http.RoundTripper) http.Handler {
	reverseProxy := buildReverseProxy(transport)
	mainHandler := http.NewServeMux()

	mainHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check request", log.String("remote_addr", r.RemoteAddr))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK - Tailscale Proxy is running"))
	})

	mainHandler.HandleFunc("/ts2021", handleTailscaleControlProtocol)

	mainHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			logger.Info("Health check request", log.String("remote_addr", r.RemoteAddr))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK - Tailscale Proxy is running"))
			return
		}

		if strings.HasPrefix(r.URL.Path, "/ts2021") {
			handleTailscaleControlProtocol(w, r)
			return
		}

		if debug {
			logDebugRequest("MAIN_HANDLER", r)
		}

		logger.Info("Request - proxying",
			log.String("remote_addr", r.RemoteAddr),
			log.String("host", r.Host),
			log.String("path", r.URL.Path))
		reverseProxy.ServeHTTP(w, r)
	})

	return mainHandler
}

func buildReverseProxy(transport http.RoundTripper) *httputil.ReverseProxy {
	reverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			setupXForwardedHeaders(req)

			target := getTailscaleTarget(req)
			upstream := resolveProxyTarget(target)
			if upstream == nil {
				upstream = &url.URL{
					Scheme: "https",
					Host:   target,
				}
			}

			if debug {
				logDebugRequest("DIRECTOR", req)
			}

			logger.Info("Reverse proxying request",
				log.String("host", req.Host),
				log.String("path", req.URL.Path),
				log.String("target", target))

			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			if upgrade := req.Header.Get("Upgrade"); upgrade != "" && debug {
				logger.Debug("Preserving Upgrade header", log.String("upgrade", upgrade))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("Reverse proxy error", log.String("url", r.URL.String()), log.Error(err))
			if debug {
				logDebugRequest("ERROR", r)
			}
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		},
		ModifyResponse: func(resp *http.Response) error {
			if debug {
				logger.Debug("Response received",
					log.String("method", resp.Request.Method),
					log.String("path", resp.Request.URL.Path),
					log.String("host", resp.Request.URL.Host),
					log.String("status", resp.Status))

				for name, values := range resp.Header {
					for _, value := range values {
						logger.Debug("Response header", log.String("name", name), log.String("value", value))
					}
				}
			}

			return rewriteProxyResponse(resp)
		},
	}

	if transport != nil {
		reverseProxy.Transport = transport
	}

	return reverseProxy
}

// logDebugRequest logs detailed information about a request when debug mode is enabled
func logDebugRequest(phase string, r *http.Request) {
	logger.Debug("Request details",
		log.String("phase", phase),
		log.String("method", r.Method),
		log.String("url", r.URL.String()),
		log.String("remote_addr", r.RemoteAddr),
		log.String("host", r.Host),
		log.String("proto", r.Proto))

	// Log all headers
	for name, values := range r.Header {
		for _, value := range values {
			logger.Debug("Request header",
				log.String("phase", phase),
				log.String("name", name),
				log.String("value", value))
		}
	}

	// Log query parameters
	if len(r.URL.RawQuery) > 0 {
		logger.Debug("Request query",
			log.String("phase", phase),
			log.String("query", r.URL.RawQuery))
	}
}

// getTailscaleTarget determines which upstream role to route to based on the request.
func getTailscaleTarget(r *http.Request) string {
	path := r.URL.Path
	userAgent := r.Header.Get("User-Agent")
	authHeader := r.Header.Get("Authorization")

	if debug {
		logger.Debug("Determining target",
			log.String("path", path),
			log.String("user_agent", userAgent))
		if authHeader != "" {
			logger.Debug("Authorization header present",
				log.String("auth_preview", authHeader[:min(len(authHeader), 20)]+"..."))
		}
	}

	// Route based on path patterns - prioritize API endpoints first
	switch {
	case strings.HasPrefix(path, "/ts2021"):
		logger.Info("Tailscale control protocol upgrade request detected, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/key"):
		logger.Info("Key exchange request detected, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/api/"):
		logger.Info("API request detected, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/machine/"):
		logger.Info("Machine API request detected, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/derp/"):
		logger.Info("DERP request detected, routing to derp")
		return upstreamRoleDERP
	case strings.HasPrefix(path, "/bootstrap-dns"):
		logger.Info("DNS bootstrap request detected, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/register"):
		logger.Info("Registration request detected, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/c/"):
		logger.Info("Control plane endpoint detected, routing to controlplane")
		return upstreamRoleControl
	case authHeader != "" && strings.Contains(userAgent, "tailscale"):
		logger.Info("Authenticated Tailscale client request, routing to controlplane")
		return upstreamRoleControl
	case strings.Contains(userAgent, "tailscale"):
		if strings.Contains(path, "login") || strings.Contains(path, "auth") {
			logger.Info("Tailscale client login/auth request, routing to login")
			return upstreamRoleLogin
		}
		logger.Info("Tailscale client request, routing to controlplane")
		return upstreamRoleControl
	case strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/auth") || strings.HasPrefix(path, "/a/"):
		logger.Info("Web login/auth request, routing to login")
		return upstreamRoleLogin
	default:
		if debug {
			logger.Debug("Default routing to login")
		}
		return upstreamRoleLogin
	}
}

// handleTailscaleControlProtocol handles the /ts2021 endpoint with custom protocol upgrade
func handleTailscaleControlProtocol(w http.ResponseWriter, r *http.Request) {
	if shouldProxyTS2021() {
		activeTS2021Proxy.ServeHTTP(w, r)
		return
	}

	transparentTunnelTS2021(w, r)
}

func shouldProxyTS2021() bool {
	return isCustomControlUpstream()
}

func isCustomControlUpstream() bool {
	defaults := defaultUpstreamConfig()
	return activeUpstreams.control.String() != defaults.control.String()
}

// transparentTunnelTS2021 preserves the historical raw tunnel behavior.
func transparentTunnelTS2021(w http.ResponseWriter, r *http.Request) {
	if debug {
		logDebugRequest("TS2021_HANDLER", r)
	}

	logger.Info("Handling Tailscale control protocol upgrade request",
		log.String("remote_addr", r.RemoteAddr),
		log.String("method", r.Method),
		log.String("host", r.Host),
		log.String("connection", r.Header.Get("Connection")),
		log.String("upgrade", r.Header.Get("Upgrade")))

	// Check if we can hijack the connection immediately
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Response writer doesn't support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Connect to the backend first
	controlPlaneAddr, controlPlaneServerName := controlPlaneDialAddress()
	backendConn, err := dialControlPlane("tcp", controlPlaneAddr, &tls.Config{
		ServerName: controlPlaneServerName,
	})
	if err != nil {
		logger.Error("Error connecting to backend",
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.String("connection", r.Header.Get("Connection")),
			log.String("upgrade", r.Header.Get("Upgrade")),
			log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Write the original request to the backend
	err = r.Write(backendConn)
	if err != nil {
		logger.Error("Error writing request to backend",
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the response from the backend
	reader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		logger.Error("Error reading response from backend",
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	logger.Info("Received control protocol response from upstream",
		log.String("method", r.Method),
		log.String("path", r.URL.Path),
		log.Int("status_code", resp.StatusCode),
		log.String("status", resp.Status),
		log.String("connection", resp.Header.Get("Connection")),
		log.String("upgrade", resp.Header.Get("Upgrade")))

	if resp.StatusCode != http.StatusSwitchingProtocols {
		if err := rewriteProxyResponse(resp); err != nil {
			logger.Error("Error rewriting control protocol response",
				log.String("method", r.Method),
				log.String("path", r.URL.Path),
				log.Error(err))
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
	}

	// Copy response headers to client
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Write the response status
	w.WriteHeader(resp.StatusCode)

	// If it's a protocol switching response, hijack and tunnel
	if resp.StatusCode == http.StatusSwitchingProtocols {
		logger.Info("Protocol switching response received, hijacking connection for tunneling")

		// Hijack the client connection
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			logger.Error("Error hijacking connection", log.Error(err))
			return
		}
		defer clientConn.Close()

		// Start bidirectional copying
		done := make(chan bool, 2)

		// Copy from client to backend
		go func() {
			defer func() { done <- true }()
			io.Copy(backendConn, clientConn)
			logger.Debug("Client to backend copy finished")
		}()

		// Copy from backend to client
		go func() {
			defer func() { done <- true }()
			io.Copy(clientConn, backendConn)
			logger.Debug("Backend to client copy finished")
		}()

		// Wait for either direction to finish
		<-done
		logger.Debug("Tunneling finished")
		return
	}

	logger.Error("Control protocol upgrade did not switch protocols",
		log.String("method", r.Method),
		log.String("path", r.URL.Path),
		log.Int("status_code", resp.StatusCode),
		log.String("status", resp.Status),
		log.String("connection", resp.Header.Get("Connection")),
		log.String("upgrade", resp.Header.Get("Upgrade")))

	// For non-upgrade responses, copy the body normally
	if resp.Body != nil {
		io.Copy(w, resp.Body)
		resp.Body.Close()
	}
}

func rewriteProxyResponse(resp *http.Response) error {
	if isCustomControlUpstream() && resp.Request != nil && resp.Request.URL.Path == "/key" {
		if err := rewriteControlKeyResponse(resp); err != nil {
			return err
		}
	}

	rewriteLocationHeader(resp.Header)

	if !shouldRewriteResponseBody(resp) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	rewrittenBody := rewriteTailscaleURLsInBody(string(body))
	if rewrittenBody != string(body) {
		logger.Info("Rewrote URLs in response body", log.Int("bytes", len(rewrittenBody)))
	}

	resp.Body = io.NopCloser(strings.NewReader(rewrittenBody))
	resp.ContentLength = int64(len(rewrittenBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewrittenBody)))

	return nil
}

func rewriteLocationHeader(header http.Header) {
	if location := header.Get("Location"); location != "" {
		if newLocation := rewriteTailscaleURL(location); newLocation != location {
			logger.Info("Rewriting Location header",
				log.String("from", location),
				log.String("to", newLocation))
			header.Set("Location", newLocation)
		}
	}
}

func shouldRewriteResponseBody(resp *http.Response) bool {
	if resp == nil || resp.Body == nil {
		return false
	}

	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "text/plain")
}

// rewriteTailscaleURL rewrites known upstream URLs to use the public proxy domain.
func rewriteTailscaleURL(raw string) string {
	rewritten := raw
	for _, source := range upstreamRewriteSources() {
		replacement := "https://" + domain
		if strings.HasPrefix(source, "//") {
			replacement = "//" + domain
		}
		rewritten = strings.ReplaceAll(rewritten, source, replacement)
	}
	return rewritten
}

// rewriteTailscaleURLsInBody rewrites upstream URLs in response body content.
func rewriteTailscaleURLsInBody(body string) string {
	for _, source := range upstreamRewriteSources() {
		replacement := "https://" + domain
		if strings.HasPrefix(source, "//") {
			replacement = "//" + domain
		}
		pattern := regexp.QuoteMeta(source)
		body = regexp.MustCompile(pattern).ReplaceAllString(body, replacement)
	}
	return body
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// setupXForwardedHeaders sets up X-Forwarded headers when running behind a proxy
func setupXForwardedHeaders(req *http.Request) {
	// If running behind a proxy, preserve the original client information
	if httpOnly {
		// Trust the X-Forwarded-For header if present, otherwise use RemoteAddr
		if xff := req.Header.Get("X-Forwarded-For"); xff == "" {
			// Extract IP from RemoteAddr (format: "IP:port")
			clientIP := req.RemoteAddr
			if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
				clientIP = clientIP[:idx]
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		}

		// Set X-Forwarded-Proto if not already present
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", "https")
		}

		// Set X-Forwarded-Host if not already present
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
	}
}
