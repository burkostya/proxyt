package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/jaxxstorm/log"
	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const earlyPayloadMagic = "\xff\xff\xffTS"

var (
	activeTS2021Proxy = newTS2021Proxy()

	ts2021ServerKeyOnce sync.Once
	ts2021ServerKey     key.MachinePrivate
	ts2021ServerKeyErr  error
)

type ts2021ClientSession interface {
	Serve(context.Context, ts2021RequestHandler) error
	Close() error
	Peer() key.MachinePublic
}

type ts2021UpstreamSession interface {
	RoundTrip(*http.Request) (*http.Response, error)
	Close() error
}

type ts2021RequestHandler interface {
	ProxyRegister(context.Context, *tailcfg.RegisterRequest) (*tailcfg.RegisterResponse, error)
	ProxyHTTPRequest(*http.Request) (*http.Response, error)
}

type ts2021Proxy struct {
	acceptClient func(http.ResponseWriter, *http.Request) (ts2021ClientSession, error)
	dialUpstream func(context.Context, *url.URL, int, key.MachinePublic) (ts2021UpstreamSession, error)
	fetchKey     func(context.Context, *url.URL, int) (key.MachinePublic, error)
}

func newTS2021Proxy() *ts2021Proxy {
	return &ts2021Proxy{
		acceptClient: acceptTS2021ClientSession,
		dialUpstream: dialTS2021UpstreamSession,
		fetchKey:     fetchTS2021ControlKey,
	}
}

func (p *ts2021Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	version := parseTS2021Version(r)
	clientSession, err := p.acceptClient(w, r)
	if err != nil {
		return
	}
	defer clientSession.Close()

	clientPeer := clientSession.Peer()
	upstreamSession, err := p.dialUpstream(r.Context(), activeUpstreams.control, version, clientPeer)
	if err != nil {
		logger.Error("Failed to establish upstream TS2021 session", log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamSession.Close()

	logger.Info("Established proxied TS2021 control-plane session",
		log.String("upstream", activeUpstreams.control.String()),
		log.String("client_peer", clientPeer.String()),
		log.Int("protocol_version", version))

	handler := &ts2021ProxyHandler{
		upstream:        upstreamSession,
		clientPeer:      clientPeer,
		protocolVersion: version,
	}
	started := time.Now()
	if err := clientSession.Serve(r.Context(), handler); err != nil {
		logger.Error("TS2021 client session failed",
			log.Error(err),
			log.String("client_peer", clientPeer.String()),
			log.Int("protocol_version", version),
			log.String("duration", time.Since(started).String()))
		return
	}
	logger.Info("TS2021 client session finished",
		log.String("client_peer", clientPeer.String()),
		log.Int("protocol_version", version),
		log.String("duration", time.Since(started).String()))
}

type ts2021ProxyHandler struct {
	upstream        ts2021UpstreamSession
	clientPeer      key.MachinePublic
	protocolVersion int
}

func (h *ts2021ProxyHandler) ProxyRegister(ctx context.Context, req *tailcfg.RegisterRequest) (*tailcfg.RegisterResponse, error) {
	started := time.Now()
	fields := registerRequestLogFields(req)
	fields = append(fields,
		log.String("client_peer", h.clientPeer.String()),
		log.Int("protocol_version", h.protocolVersion))

	logger.Info("Proxying TS2021 register request", fields...)

	body, err := json.Marshal(req)
	if err != nil {
		logger.Error("Failed to encode TS2021 register request",
			append(fields, log.Error(err))...)
		return nil, err
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamControlURL("/machine/register"), bytes.NewReader(body))
	if err != nil {
		logger.Error("Failed to build upstream TS2021 register request",
			append(fields, log.Error(err))...)
		return nil, err
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	resp, err := h.upstream.RoundTrip(upstreamReq)
	if err != nil {
		logger.Error("Upstream TS2021 register request failed",
			append(fields,
				log.Error(err),
				log.String("duration", time.Since(started).String()))...)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		bodyPreview := readResponseBodyPreview(resp.Body, 2048)
		err := fmt.Errorf("upstream register returned %s", resp.Status)
		logger.Error("Upstream TS2021 register returned error",
			append(fields,
				log.Error(err),
				log.Int("status_code", resp.StatusCode),
				log.String("status", resp.Status),
				log.String("body_preview", bodyPreview),
				log.String("duration", time.Since(started).String()))...)
		return nil, err
	}

	var registerResp tailcfg.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&registerResp); err != nil {
		logger.Error("Failed to decode upstream TS2021 register response",
			append(fields,
				log.Error(err),
				log.Int("status_code", resp.StatusCode),
				log.String("duration", time.Since(started).String()))...)
		return nil, err
	}

	rewritten := rewriteRegisterResponse(&registerResp)
	if rewritten.AuthURL != registerResp.AuthURL {
		logger.Info("Rewrote RegisterResponse.AuthURL",
			log.String("from", registerResp.AuthURL),
			log.String("to", rewritten.AuthURL))
	}
	logger.Info("Proxied TS2021 register response",
		append(fields,
			log.Int("status_code", resp.StatusCode),
			log.Bool("machine_authorized", rewritten.MachineAuthorized),
			log.Bool("node_key_expired", rewritten.NodeKeyExpired),
			log.Bool("has_auth_url", rewritten.AuthURL != ""),
			log.String("auth_url_host", urlHost(rewritten.AuthURL)),
			log.String("auth_url_path", urlPath(rewritten.AuthURL)),
			log.String("register_error", rewritten.Error),
			log.String("duration", time.Since(started).String()))...)
	return rewritten, nil
}

func (h *ts2021ProxyHandler) ProxyHTTPRequest(req *http.Request) (*http.Response, error) {
	started := time.Now()
	logger.Info("Proxying TS2021 in-session HTTP request",
		log.String("client_peer", h.clientPeer.String()),
		log.Int("protocol_version", h.protocolVersion),
		log.String("method", req.Method),
		log.String("path", req.URL.Path),
		log.String("query", req.URL.RawQuery))

	cloned := req.Clone(req.Context())
	cloned.URL = cloneURL(req.URL)
	cloned.URL.Scheme = "https"
	cloned.URL.Host = activeUpstreams.control.Host
	cloned.Host = activeUpstreams.control.Host
	cloned.RequestURI = ""
	resp, err := h.upstream.RoundTrip(cloned)
	if err != nil {
		logger.Error("Upstream TS2021 in-session HTTP request failed",
			log.Error(err),
			log.String("client_peer", h.clientPeer.String()),
			log.Int("protocol_version", h.protocolVersion),
			log.String("method", req.Method),
			log.String("path", req.URL.Path),
			log.String("duration", time.Since(started).String()))
		return nil, err
	}
	logger.Info("Received upstream TS2021 in-session HTTP response",
		log.String("client_peer", h.clientPeer.String()),
		log.Int("protocol_version", h.protocolVersion),
		log.String("method", req.Method),
		log.String("path", req.URL.Path),
		log.Int("status_code", resp.StatusCode),
		log.String("status", resp.Status),
		log.String("duration", time.Since(started).String()))
	return resp, nil
}

type realTS2021ClientSession struct {
	conn *controlbase.Conn
}

func acceptTS2021ClientSession(w http.ResponseWriter, r *http.Request) (ts2021ClientSession, error) {
	serverKey, err := proxyTS2021PrivateKey()
	if err != nil {
		return nil, err
	}

	challenge := key.NewChallenge()
	conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, serverKey, func(protocolVersion int, writer io.Writer) error {
		return writeEarlyNoise(protocolVersion, challenge.Public(), writer)
	})
	if err != nil {
		logTS2021AcceptFailure(r, err)
		return nil, err
	}

	logger.Info("Accepted client TS2021 session",
		log.String("peer", conn.Peer().String()),
		log.Int("protocol_version", conn.ProtocolVersion()))

	return &realTS2021ClientSession{conn: conn}, nil
}

func (s *realTS2021ClientSession) Close() error {
	return s.conn.Close()
}

func (s *realTS2021ClientSession) Peer() key.MachinePublic {
	return s.conn.Peer()
}

func (s *realTS2021ClientSession) Serve(ctx context.Context, handler ts2021RequestHandler) error {
	clientPeer := s.conn.Peer()
	protocolVersion := s.conn.ProtocolVersion()

	mux := http.NewServeMux()
	mux.HandleFunc("/machine/register", func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		logger.Info("Received TS2021 register request",
			log.String("client_peer", clientPeer.String()),
			log.Int("protocol_version", protocolVersion),
			log.String("method", r.Method),
			log.String("path", r.URL.Path))

		if r.Method != http.MethodPost {
			logger.Error("Rejected TS2021 register request with unsupported method",
				log.String("client_peer", clientPeer.String()),
				log.String("method", r.Method),
				log.String("path", r.URL.Path))
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var registerReq tailcfg.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&registerReq); err != nil {
			logger.Error("Failed to decode TS2021 register request",
				log.Error(err),
				log.String("client_peer", clientPeer.String()),
				log.Int("protocol_version", protocolVersion),
				log.String("duration", time.Since(started).String()))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		registerResp, err := handler.ProxyRegister(r.Context(), &registerReq)
		if err != nil {
			logger.Error("Failed to proxy TS2021 register request",
				append(registerRequestLogFields(&registerReq),
					log.Error(err),
					log.String("client_peer", clientPeer.String()),
					log.Int("protocol_version", protocolVersion),
					log.String("duration", time.Since(started).String()))...)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(registerResp); err != nil {
			logger.Error("Failed to write proxied register response", log.Error(err))
			return
		}
		logger.Info("Wrote TS2021 register response to client",
			append(registerRequestLogFields(&registerReq),
				log.String("client_peer", clientPeer.String()),
				log.Int("protocol_version", protocolVersion),
				log.Bool("machine_authorized", registerResp.MachineAuthorized),
				log.Bool("node_key_expired", registerResp.NodeKeyExpired),
				log.Bool("has_auth_url", registerResp.AuthURL != ""),
				log.String("auth_url_host", urlHost(registerResp.AuthURL)),
				log.String("auth_url_path", urlPath(registerResp.AuthURL)),
				log.String("register_error", registerResp.Error),
				log.String("duration", time.Since(started).String()))...)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		logger.Info("Received TS2021 in-session HTTP request",
			log.String("client_peer", clientPeer.String()),
			log.Int("protocol_version", protocolVersion),
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.String("query", r.URL.RawQuery))

		resp, err := handler.ProxyHTTPRequest(r)
		if err != nil {
			logger.Error("Failed to proxy TS2021 in-session HTTP request",
				log.Error(err),
				log.String("client_peer", clientPeer.String()),
				log.Int("protocol_version", protocolVersion),
				log.String("method", r.Method),
				log.String("path", r.URL.Path),
				log.String("duration", time.Since(started).String()))
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		written, copyErr := io.Copy(w, resp.Body)
		if copyErr != nil {
			logger.Error("Failed while copying TS2021 in-session HTTP response body",
				log.Error(copyErr),
				log.String("client_peer", clientPeer.String()),
				log.Int("protocol_version", protocolVersion),
				log.String("method", r.Method),
				log.String("path", r.URL.Path),
				log.Int("status_code", resp.StatusCode),
				log.String("bytes", strconv.FormatInt(written, 10)),
				log.String("duration", time.Since(started).String()))
			return
		}
		logger.Info("Wrote TS2021 in-session HTTP response to client",
			log.String("client_peer", clientPeer.String()),
			log.Int("protocol_version", protocolVersion),
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.Int("status_code", resp.StatusCode),
			log.String("bytes", strconv.FormatInt(written, 10)),
			log.String("duration", time.Since(started).String()))
	})

	server := &http2.Server{}
	server.ServeConn(s.conn, &http2.ServeConnOpts{
		BaseConfig: &http.Server{
			Handler: mux,
		},
	})
	return nil
}

type realTS2021UpstreamSession struct {
	conn      net.Conn
	closeConn func() error
	transport *http2.Transport
	once      sync.Once
}

func dialTS2021UpstreamSession(ctx context.Context, upstream *url.URL, version int, clientPeer key.MachinePublic) (ts2021UpstreamSession, error) {
	controlKey, err := fetchTS2021ControlKey(ctx, upstream, version)
	if err != nil {
		return nil, err
	}
	machineKey, err := upstreamTS2021PrivateKeyForClient(clientPeer)
	if err != nil {
		return nil, err
	}

	hostname := upstream.Hostname()
	httpsPort := upstream.Port()
	if httpsPort == "" {
		httpsPort = "443"
	}

	dialer := &controlhttp.Dialer{
		Hostname:        hostname,
		HTTPPort:        "80",
		HTTPSPort:       httpsPort,
		MachineKey:      machineKey,
		ControlKey:      controlKey,
		ProtocolVersion: uint16(version),
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}

	noiseConn, err := dialer.Dial(ctx)
	if err != nil {
		return nil, err
	}

	tsConn := ts2021.NewConn(noiseConn.Conn, func() {})
	var used bool
	var mu sync.Mutex
	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			if used {
				return nil, fmt.Errorf("TS2021 upstream connection already in use")
			}
			used = true
			return tsConn, nil
		},
	}

	logger.Info("Established upstream TS2021 session",
		log.String("upstream", upstream.String()),
		log.String("peer", noiseConn.Peer().String()),
		log.String("client_peer", clientPeer.String()),
		log.String("upstream_machine_key", machineKey.Public().String()))

	return &realTS2021UpstreamSession{
		conn:      noiseConn.Conn,
		closeConn: noiseConn.Close,
		transport: transport,
	}, nil
}

func (s *realTS2021UpstreamSession) RoundTrip(req *http.Request) (*http.Response, error) {
	return s.transport.RoundTrip(req)
}

func (s *realTS2021UpstreamSession) Close() error {
	var err error
	s.once.Do(func() {
		s.transport.CloseIdleConnections()
		if s.closeConn != nil {
			err = s.closeConn()
			return
		}
		err = s.conn.Close()
	})
	return err
}

func fetchTS2021ControlKey(ctx context.Context, upstream *url.URL, version int) (key.MachinePublic, error) {
	keyURL := cloneURL(upstream)
	keyURL.Path = "/key"
	query := keyURL.Query()
	query.Set("v", strconv.Itoa(version))
	keyURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL.String(), nil)
	if err != nil {
		return key.MachinePublic{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return key.MachinePublic{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return key.MachinePublic{}, fmt.Errorf("unexpected /key status: %s", resp.Status)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return key.MachinePublic{}, err
	}

	publicKeyText, _ := body["PublicKey"].(string)
	if publicKeyText == "" {
		publicKeyText, _ = body["publicKey"].(string)
	}
	if publicKeyText == "" {
		return key.MachinePublic{}, fmt.Errorf("upstream /key response missing PublicKey/publicKey")
	}

	var publicKey key.MachinePublic
	if err := publicKey.UnmarshalText([]byte(publicKeyText)); err != nil {
		return key.MachinePublic{}, err
	}
	return publicKey, nil
}

func parseTS2021Version(r *http.Request) int {
	if r == nil {
		return int(tailcfg.CurrentCapabilityVersion)
	}

	rawVersion := r.URL.Query().Get("v")
	if rawVersion == "" {
		return int(tailcfg.CurrentCapabilityVersion)
	}

	version, err := strconv.Atoi(rawVersion)
	if err != nil || version <= 0 {
		return int(tailcfg.CurrentCapabilityVersion)
	}
	return version
}

func upstreamControlURL(path string) string {
	target := cloneURL(activeUpstreams.control)
	target.Path = path
	target.RawPath = ""
	return target.String()
}

func rewriteRegisterResponse(resp *tailcfg.RegisterResponse) *tailcfg.RegisterResponse {
	if resp == nil {
		return nil
	}

	rewritten := *resp
	rewritten.AuthURL = rewriteTailscaleURL(rewritten.AuthURL)
	return &rewritten
}

func registerRequestLogFields(req *tailcfg.RegisterRequest) []log.Field {
	if req == nil {
		return []log.Field{
			log.Bool("register_request_nil", true),
		}
	}

	fields := []log.Field{
		log.Int("register_version", int(req.Version)),
		log.String("node_key", nodePublicShortString(req.NodeKey)),
		log.String("old_node_key", nodePublicShortString(req.OldNodeKey)),
		log.Bool("has_auth", req.Auth != nil),
		log.Bool("has_followup", req.Followup != ""),
		log.String("followup_host", urlHost(req.Followup)),
		log.String("followup_path", urlPath(req.Followup)),
		log.Bool("has_hostinfo", req.Hostinfo != nil),
		log.Bool("ephemeral", req.Ephemeral),
	}
	if !req.Expiry.IsZero() {
		fields = append(fields, log.String("expiry", req.Expiry.Format(time.RFC3339)))
	}
	if req.Hostinfo != nil {
		fields = append(fields,
			log.String("hostinfo_hostname", req.Hostinfo.Hostname),
			log.String("hostinfo_os", req.Hostinfo.OS),
			log.String("hostinfo_ipn_version", req.Hostinfo.IPNVersion),
			log.String("hostinfo_backend_log_id", req.Hostinfo.BackendLogID))
	}
	return fields
}

func nodePublicShortString(publicKey key.NodePublic) string {
	if publicKey.IsZero() {
		return ""
	}
	return publicKey.ShortString()
}

func urlHost(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func urlPath(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func readResponseBodyPreview(body io.Reader, limit int64) string {
	if body == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(body, limit))
	if err != nil {
		return "failed to read response body preview: " + err.Error()
	}
	return string(data)
}

func rewriteControlKeyResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	publicKeyText, err := proxyTS2021PublicKeyText()
	if err != nil {
		return err
	}
	payload["PublicKey"] = publicKeyText
	payload["publicKey"] = publicKeyText

	rewrittenBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp.Body = io.NopCloser(bytes.NewReader(rewrittenBody))
	resp.ContentLength = int64(len(rewrittenBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(rewrittenBody)))
	resp.Header.Set("Content-Type", "application/json")
	return nil
}

func requirePersistentTS2021KeyForCustomUpstream() error {
	if !shouldProxyTS2021() {
		return nil
	}

	if effectiveTS2021KeyFile() == "" {
		return fmt.Errorf("custom TS2021 proxy mode requires --ts2021-key-file, PROXYT_TS2021_KEY_FILE, STATE_DIRECTORY, or --cert-dir for stable control keys")
	}

	_, err := proxyTS2021PrivateKey()
	return err
}

func proxyTS2021PrivateKey() (key.MachinePrivate, error) {
	ts2021ServerKeyOnce.Do(func() {
		ts2021ServerKey, ts2021ServerKeyErr = loadOrCreateTS2021PrivateKey(effectiveTS2021KeyFile())
	})
	return ts2021ServerKey, ts2021ServerKeyErr
}

func loadOrCreateTS2021PrivateKey(path string) (key.MachinePrivate, error) {
	if path == "" {
		if logger != nil {
			logger.Warn("Using ephemeral TS2021 proxy key; configure --ts2021-key-file for stable custom-upstream control-plane proxying")
		}
		return key.NewMachine(), nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key.MachinePrivate{}, fmt.Errorf("creating TS2021 key directory: %w", err)
	}

	privateKey, err := os.ReadFile(path)
	if err == nil {
		var machineKey key.MachinePrivate
		if err := machineKey.UnmarshalText([]byte(strings.TrimSpace(string(privateKey)))); err != nil {
			return key.MachinePrivate{}, fmt.Errorf("parsing TS2021 private key %q: %w", path, err)
		}
		if machineKey.IsZero() {
			return key.MachinePrivate{}, fmt.Errorf("TS2021 private key %q is zero", path)
		}
		if logger != nil {
			logger.Info("Loaded persistent TS2021 proxy key", log.String("path", path))
		}
		return machineKey, nil
	}
	if !os.IsNotExist(err) {
		return key.MachinePrivate{}, fmt.Errorf("reading TS2021 private key %q: %w", path, err)
	}

	machineKey := key.NewMachine()
	text, err := machineKey.MarshalText()
	if err != nil {
		return key.MachinePrivate{}, fmt.Errorf("serializing TS2021 private key: %w", err)
	}
	text = append(text, '\n')
	if err := os.WriteFile(path, text, 0o600); err != nil {
		return key.MachinePrivate{}, fmt.Errorf("writing TS2021 private key %q: %w", path, err)
	}
	if logger != nil {
		logger.Info("Created persistent TS2021 proxy key", log.String("path", path))
	}
	return machineKey, nil
}

func upstreamTS2021PrivateKeyForClient(clientPeer key.MachinePublic) (key.MachinePrivate, error) {
	if clientPeer.IsZero() {
		return key.MachinePrivate{}, fmt.Errorf("client TS2021 peer machine key is zero")
	}

	baseKeyFile := effectiveTS2021KeyFile()
	if baseKeyFile == "" {
		if logger != nil {
			logger.Warn("Using ephemeral upstream TS2021 client key; configure persistent TS2021 key storage")
		}
		return key.NewMachine(), nil
	}

	fileComponent, err := machinePublicKeyFileComponent(clientPeer)
	if err != nil {
		return key.MachinePrivate{}, err
	}

	path := filepath.Join(filepath.Dir(baseKeyFile), "ts2021-upstream-clients", fileComponent+".key")
	return loadOrCreateTS2021PrivateKey(path)
}

func machinePublicKeyFileComponent(publicKey key.MachinePublic) (string, error) {
	text, err := publicKey.MarshalText()
	if err != nil {
		return "", fmt.Errorf("serializing client machine public key: %w", err)
	}

	value := strings.TrimPrefix(string(text), "mkey:")
	if value == "" || value == string(text) {
		return "", fmt.Errorf("unexpected client machine public key format %q", text)
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return "", fmt.Errorf("unexpected client machine public key format %q", text)
	}
	return value, nil
}

func effectiveTS2021KeyFile() string {
	if ts2021KeyFile != "" {
		return ts2021KeyFile
	}
	if stateDirectory := os.Getenv("STATE_DIRECTORY"); stateDirectory != "" {
		for _, dir := range strings.Split(stateDirectory, ":") {
			if dir != "" {
				return filepath.Join(dir, "ts2021-machine.key")
			}
		}
	}
	if certDir != "" {
		return filepath.Join(certDir, "ts2021-machine.key")
	}
	return ""
}

func proxyTS2021PublicKeyText() (string, error) {
	privateKey, err := proxyTS2021PrivateKey()
	if err != nil {
		return "", err
	}
	publicKey := privateKey.Public()
	text, err := publicKey.MarshalText()
	if err != nil {
		return "", err
	}
	return string(text), nil
}

func logTS2021AcceptFailure(r *http.Request, err error) {
	if logger == nil {
		return
	}

	publicKey, keyErr := proxyTS2021PublicKeyText()
	fields := []log.Field{
		log.Error(err),
		log.String("remote_addr", r.RemoteAddr),
		log.String("method", r.Method),
		log.String("host", r.Host),
		log.String("path", r.URL.Path),
		log.String("upgrade", r.Header.Get("Upgrade")),
		log.String("connection", r.Header.Get("Connection")),
		log.Bool("handshake_header_present", r.Header.Get(controlhttpcommon.HandshakeHeaderName) != ""),
		log.Int("protocol_version", parseTS2021Version(r)),
		log.String("key_file", effectiveTS2021KeyFile()),
	}
	if keyErr == nil {
		fields = append(fields, log.String("server_public_key", publicKey))
	} else {
		fields = append(fields, log.String("server_public_key_error", keyErr.Error()))
	}
	logger.Error("Failed to accept TS2021 client session", fields...)
}

func writeEarlyNoise(_ int, challenge key.ChallengePublic, writer io.Writer) error {
	earlyJSON, err := json.Marshal(&tailcfg.EarlyNoise{
		NodeKeyChallenge: challenge,
	})
	if err != nil {
		return err
	}

	var notH2Frame [5]byte
	copy(notH2Frame[:], earlyPayloadMagic)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(earlyJSON)))

	if _, err := writer.Write(notH2Frame[:]); err != nil {
		return err
	}
	if _, err := writer.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := writer.Write(earlyJSON); err != nil {
		return err
	}
	return nil
}
