package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRewriteRegisterResponse(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://upstream.example.com"),
		control: mustParseURL(t, "https://upstream.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	in := &tailcfg.RegisterResponse{
		AuthURL: "https://upstream.example.com/register/device-123",
		User:    tailcfg.User{DisplayName: "alice"},
	}

	got := rewriteRegisterResponse(in)
	if got.AuthURL != "https://proxy.example.com/register/device-123" {
		t.Fatalf("AuthURL = %q", got.AuthURL)
	}
	if got.User.DisplayName != "alice" {
		t.Fatalf("unexpected non-URL mutation: %+v", got.User)
	}
	if in.AuthURL != "https://upstream.example.com/register/device-123" {
		t.Fatal("rewriteRegisterResponse mutated input")
	}
}

func TestShouldProxyTS2021(t *testing.T) {
	withProxyTestGlobals(t)

	if shouldProxyTS2021() {
		t.Fatal("default upstream should not enable proxied TS2021 mode")
	}

	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://headscale.example.com"),
		control: mustParseURL(t, "https://headscale.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}
	if !shouldProxyTS2021() {
		t.Fatal("custom control upstream should enable proxied TS2021 mode")
	}
}

func TestRewriteControlKeyResponseCustomUpstream(t *testing.T) {
	withProxyTestGlobals(t)
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://headscale.example.com"),
		control: mustParseURL(t, "https://headscale.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	upstreamKeyText := marshalMachinePublicText(t, key.NewMachine().Public())
	resp := &http.Response{
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(bytes.NewBufferString(`{"PublicKey":"` + upstreamKeyText + `","publicKey":"` + upstreamKeyText + `","legacyPublicKey":"legacy"}`)),
		Request: &http.Request{
			URL: mustParseURL(t, "https://headscale.example.com/key"),
		},
	}

	if err := rewriteProxyResponse(resp); err != nil {
		t.Fatalf("rewriteProxyResponse: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	publicKeyText, ok := payload["PublicKey"].(string)
	if !ok {
		t.Fatalf("rewritten payload missing PublicKey: %s", body)
	}
	if publicKeyText == upstreamKeyText {
		t.Fatalf("PublicKey was not rewritten: %s", body)
	}
	if payload["publicKey"] != publicKeyText {
		t.Fatalf("publicKey was not rewritten consistently: %s", body)
	}
	if payload["legacyPublicKey"] != "legacy" {
		t.Fatalf("legacyPublicKey changed unexpectedly: %s", body)
	}
}

func TestFetchTS2021ControlKeyAcceptsLowercasePublicKey(t *testing.T) {
	withProxyTestGlobals(t)

	upstreamKeyText := marshalMachinePublicText(t, key.NewMachine().Public())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/key" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("v"); got != "77" {
			t.Fatalf("version query = %q, want 77", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"legacyPublicKey":"legacy","publicKey":"`+upstreamKeyText+`"}`)
	}))
	defer server.Close()

	upstream := mustParseURL(t, server.URL)
	publicKey, err := fetchTS2021ControlKey(context.Background(), upstream, 77)
	if err != nil {
		t.Fatalf("fetchTS2021ControlKey: %v", err)
	}
	if got := marshalMachinePublicText(t, publicKey); got != upstreamKeyText {
		t.Fatalf("public key = %q, want %q", got, upstreamKeyText)
	}
}

func TestWriteEarlyNoiseIncludesNodeKeyChallenge(t *testing.T) {
	challenge := key.NewChallenge()

	var buf bytes.Buffer
	if err := writeEarlyNoise(123, challenge.Public(), &buf); err != nil {
		t.Fatalf("writeEarlyNoise: %v", err)
	}

	raw := buf.Bytes()
	if len(raw) < len(earlyPayloadMagic)+4 {
		t.Fatalf("early payload too short: %d", len(raw))
	}
	if got := string(raw[:len(earlyPayloadMagic)]); got != earlyPayloadMagic {
		t.Fatalf("early payload magic = %q, want %q", got, earlyPayloadMagic)
	}

	payloadLen := binary.BigEndian.Uint32(raw[len(earlyPayloadMagic) : len(earlyPayloadMagic)+4])
	payload := raw[len(earlyPayloadMagic)+4:]
	if int(payloadLen) != len(payload) {
		t.Fatalf("payload length header = %d, want %d", payloadLen, len(payload))
	}

	var early tailcfg.EarlyNoise
	if err := json.Unmarshal(payload, &early); err != nil {
		t.Fatalf("unmarshal early noise: %v", err)
	}
	if early.NodeKeyChallenge != challenge.Public() {
		t.Fatalf("NodeKeyChallenge = %v, want %v", early.NodeKeyChallenge, challenge.Public())
	}
}

func TestAcceptTS2021ClientSessionWithRealDialer(t *testing.T) {
	withProxyTestGlobals(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := acceptTS2021ClientSession(w, r)
			if err != nil {
				serverErr <- err
				return
			}
			defer session.Close()
			serverErr <- nil
		}),
	}
	defer server.Close()
	go server.Serve(ln)

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	proxyKey, err := proxyTS2021PrivateKey()
	if err != nil {
		t.Fatalf("proxyTS2021PrivateKey: %v", err)
	}

	dialer := &controlhttp.Dialer{
		Hostname:        "127.0.0.1",
		HTTPPort:        port,
		HTTPSPort:       controlhttp.NoPort,
		MachineKey:      key.NewMachine(),
		ControlKey:      proxyKey.Public(),
		ProtocolVersion: uint16(88),
	}

	clientConn, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	tsConn := ts2021.NewConn(clientConn.Conn, nil)
	early, err := tsConn.GetEarlyPayload(context.Background())
	if err != nil {
		t.Fatalf("GetEarlyPayload: %v", err)
	}
	if early == nil {
		t.Fatal("expected early payload")
	}
	if early.NodeKeyChallenge.IsZero() {
		t.Fatal("expected NodeKeyChallenge in early payload")
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server accept: %v", err)
	}
}

func TestDialTS2021UpstreamSessionStripsEarlyNoiseBeforeHTTP2(t *testing.T) {
	withProxyTestGlobals(t)
	ts2021KeyFile = filepath.Join(t.TempDir(), "ts2021-machine.key")

	upstreamKey := key.NewMachine()
	upstreamKeyText := marshalMachinePublicText(t, upstreamKey.Public())

	upstreamServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"PublicKey":"`+upstreamKeyText+`"}`)
		case "/ts2021":
			conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, upstreamKey, func(protocolVersion int, writer io.Writer) error {
				return writeEarlyNoise(protocolVersion, key.NewChallenge().Public(), writer)
			})
			if err != nil {
				t.Errorf("AcceptHTTP: %v", err)
				return
			}
			defer conn.Close()

			mux := http.NewServeMux()
			mux.HandleFunc("/machine/register", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(&tailcfg.RegisterResponse{
					AuthURL: "https://upstream.example.com/register/token-123",
				})
			})

			server := &http2.Server{}
			server.ServeConn(conn, &http2.ServeConnOpts{
				BaseConfig: &http.Server{Handler: mux},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstreamServer.Close()

	oldDefaultClient := http.DefaultClient
	http.DefaultClient = upstreamServer.Client()
	t.Cleanup(func() {
		http.DefaultClient = oldDefaultClient
	})

	upstreamURL := mustParseURL(t, upstreamServer.URL)
	clientPeer := key.NewMachine().Public()
	session, err := dialTS2021UpstreamSession(context.Background(), upstreamURL, 133, clientPeer)
	if err != nil {
		t.Fatalf("dialTS2021UpstreamSession: %v", err)
	}
	defer session.Close()

	req, err := http.NewRequest(http.MethodPost, upstreamServer.URL+"/machine/register", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := session.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	var registerResp tailcfg.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&registerResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if registerResp.AuthURL != "https://upstream.example.com/register/token-123" {
		t.Fatalf("AuthURL = %q", registerResp.AuthURL)
	}
}

func TestLoadOrCreateTS2021PrivateKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ts2021-machine.key")

	first, err := loadOrCreateTS2021PrivateKey(path)
	if err != nil {
		t.Fatalf("first loadOrCreateTS2021PrivateKey: %v", err)
	}
	second, err := loadOrCreateTS2021PrivateKey(path)
	if err != nil {
		t.Fatalf("second loadOrCreateTS2021PrivateKey: %v", err)
	}
	if first.Public() != second.Public() {
		t.Fatalf("private key was not persisted: first=%v second=%v", first.Public(), second.Public())
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", got)
	}
}

func TestUpstreamTS2021PrivateKeyForClientPersistsPerClientPeer(t *testing.T) {
	withProxyTestGlobals(t)
	ts2021KeyFile = filepath.Join(t.TempDir(), "ts2021-machine.key")

	clientA := key.NewMachine().Public()
	clientB := key.NewMachine().Public()

	firstA, err := upstreamTS2021PrivateKeyForClient(clientA)
	if err != nil {
		t.Fatalf("first upstream key for client A: %v", err)
	}
	secondA, err := upstreamTS2021PrivateKeyForClient(clientA)
	if err != nil {
		t.Fatalf("second upstream key for client A: %v", err)
	}
	firstB, err := upstreamTS2021PrivateKeyForClient(clientB)
	if err != nil {
		t.Fatalf("first upstream key for client B: %v", err)
	}

	if firstA.Public() != secondA.Public() {
		t.Fatalf("upstream key for same client peer changed: first=%v second=%v", firstA.Public(), secondA.Public())
	}
	if firstA.Public() == firstB.Public() {
		t.Fatalf("different client peers got same upstream key: %v", firstA.Public())
	}

	component, err := machinePublicKeyFileComponent(clientA)
	if err != nil {
		t.Fatalf("machinePublicKeyFileComponent: %v", err)
	}
	keyPath := filepath.Join(filepath.Dir(ts2021KeyFile), "ts2021-upstream-clients", component+".key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected upstream key file to be created: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("upstream key file mode = %v, want 0600", got)
	}
}

func TestEffectiveTS2021KeyFileUsesStateDirectory(t *testing.T) {
	withProxyTestGlobals(t)

	stateDir := t.TempDir()
	t.Setenv("STATE_DIRECTORY", stateDir+":"+t.TempDir())

	want := filepath.Join(stateDir, "ts2021-machine.key")
	if got := effectiveTS2021KeyFile(); got != want {
		t.Fatalf("effectiveTS2021KeyFile = %q, want %q", got, want)
	}
}

func TestRequirePersistentTS2021KeyForCustomUpstream(t *testing.T) {
	withProxyTestGlobals(t)
	t.Setenv("STATE_DIRECTORY", "")
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://headscale.example.com"),
		control: mustParseURL(t, "https://headscale.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	if err := requirePersistentTS2021KeyForCustomUpstream(); err == nil {
		t.Fatal("expected custom TS2021 proxy mode to require a persistent key path")
	}

	ts2021KeyFile = filepath.Join(t.TempDir(), "ts2021-machine.key")
	ts2021ServerKeyOnce = sync.Once{}
	ts2021ServerKey = key.MachinePrivate{}
	ts2021ServerKeyErr = nil

	if err := requirePersistentTS2021KeyForCustomUpstream(); err != nil {
		t.Fatalf("requirePersistentTS2021KeyForCustomUpstream with key file: %v", err)
	}
	if _, err := os.Stat(ts2021KeyFile); err != nil {
		t.Fatalf("expected key file to be created: %v", err)
	}
}

func TestProxiedTS2021RegisterRewrite(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	activeUpstreams = upstreamConfig{
		login:   mustParseURL(t, "https://upstream.example.com"),
		control: mustParseURL(t, "https://upstream.example.com"),
		derp:    mustParseURL(t, "https://derp.tailscale.com"),
	}

	clientSession := &fakeTS2021ClientSession{
		registerRequest: &tailcfg.RegisterRequest{},
	}
	upstreamSession := &fakeTS2021UpstreamSession{
		registerResponse: &tailcfg.RegisterResponse{
			AuthURL: "https://upstream.example.com/register/token-123",
		},
	}

	proxy := &ts2021Proxy{
		acceptClient: func(http.ResponseWriter, *http.Request) (ts2021ClientSession, error) {
			return clientSession, nil
		},
		dialUpstream: func(context.Context, *url.URL, int, key.MachinePublic) (ts2021UpstreamSession, error) {
			return upstreamSession, nil
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://proxy.example.com/ts2021?v=99", nil)
	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	if clientSession.receivedRegisterResponse == nil {
		t.Fatal("client session did not receive a register response")
	}
	if got := clientSession.receivedRegisterResponse.AuthURL; got != "https://proxy.example.com/register/token-123" {
		t.Fatalf("AuthURL = %q", got)
	}
	if upstreamSession.roundTrips != 1 {
		t.Fatalf("upstream round trips = %d, want 1", upstreamSession.roundTrips)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

type fakeTS2021ClientSession struct {
	registerRequest          *tailcfg.RegisterRequest
	receivedRegisterResponse *tailcfg.RegisterResponse
	peer                     key.MachinePublic
}

func (s *fakeTS2021ClientSession) Serve(ctx context.Context, handler ts2021RequestHandler) error {
	resp, err := handler.ProxyRegister(ctx, s.registerRequest)
	if err != nil {
		return err
	}
	s.receivedRegisterResponse = resp
	return nil
}

func (s *fakeTS2021ClientSession) Close() error {
	return nil
}

func (s *fakeTS2021ClientSession) Peer() key.MachinePublic {
	if s.peer.IsZero() {
		s.peer = key.NewMachine().Public()
	}
	return s.peer
}

type fakeTS2021UpstreamSession struct {
	registerResponse *tailcfg.RegisterResponse
	roundTrips       int
}

func (s *fakeTS2021UpstreamSession) RoundTrip(req *http.Request) (*http.Response, error) {
	s.roundTrips++
	body, err := json.Marshal(s.registerResponse)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (s *fakeTS2021UpstreamSession) Close() error {
	return nil
}

func marshalMachinePublicText(t *testing.T, public key.MachinePublic) string {
	t.Helper()

	text, err := public.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	return string(text)
}
