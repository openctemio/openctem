package sensorrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
	"github.com/openctemio/openctem/api/pkg/sensorproto/sealed"
)

type fakeAPI struct {
	mu   sync.Mutex
	seen []*http.Request
	body [][]byte
	ts   *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{}
	f.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, r.Clone(context.Background()))
		f.body = append(f.body, b)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Internal-Trace", "internal")
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
	}))
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeAPI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

type relayedSensor struct {
	sensor
	enc   *sealed.PrivateKey
	route sealed.Route
}

func startConnector(t *testing.T, h *harness, apiURL string) (*sealed.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	ik, _ := sealed.GenerateKey()
	rpub, rpriv, _ := ed25519.GenerateKey(nil)
	pin := sha256.Sum256(h.server.Leaf.RawSubjectPublicKeyInfo)
	c, err := NewConnector(ConnectorConfig{RelayURL: h.ts.URL, RelayPin: pin[:], ClientCert: h.conn1, Realm: "realm-1",
		IngestKeys: []*sealed.PrivateKey{ik}, ResponseKey: rpriv, APIURL: apiURL, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ik, rpub
}

// send seals a request as a sensor does, posts it to the relay and waits
// for the answer on the sensor's mailbox (nil when none arrives).
func send(t *testing.T, h *harness, s relayedSensor, ingest *sealed.PublicKey, respKey ed25519.PublicKey, sealRoute sealed.Route, method, path string, hdr http.Header) *sealed.Response {
	t.Helper()
	req := &sealed.Request{RequestMeta: sealed.RequestMeta{Method: method, Path: path, Header: hdr, ReplyKey: s.enc.Public().Bytes()}, Body: []byte(`{"k":1}`)}
	env, err := sealed.SealRequest(ingest, sealRoute, req)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := h.do(s.cert, "POST", relay.PathSensorUp, s.ticket, env); code != http.StatusAccepted {
		t.Fatalf("up = %d", code)
	}
	code, body := h.do(s.cert, "GET", relay.PathSensorDown+"?wait=3", s.ticket, nil)
	if code == http.StatusNoContent {
		return nil
	}
	items, err := relay.ReadBatch(bytes.NewReader(body), 10, 1<<26)
	if err != nil || len(items) != 1 {
		t.Fatalf("down batch: %v %d", err, len(items))
	}
	resp, err := sealed.OpenResponse(s.enc, []ed25519.PublicKey{respKey}, s.route, sealed.Digest(env), items[0].Envelope, time.Now())
	if err != nil {
		t.Fatalf("answer does not open: %v", err)
	}
	return resp
}

func newRelayedSensor(h *harness, id string) relayedSensor {
	enc, _ := sealed.GenerateKey()
	return relayedSensor{sensor: h.sensor(id, "realm-1", nil), enc: enc, route: sealed.Route{Realm: "realm-1", SensorID: id}}
}

func TestConnectorEndToEnd(t *testing.T) {
	h := newHarness(t, Limits{})
	api := newFakeAPI(t)
	ik, rpub := startConnector(t, h, api.ts.URL)
	s := newRelayedSensor(h, "sensor-a")
	hdr := http.Header{"Signature": {"sig1=:abc:"}, "Signature-Input": {"sig1=()"}, "Content-Type": {"application/json"},
		"X-Forwarded-For": {"203.0.113.9"}, "Cookie": {"session=stolen"}, "X-Real-Ip": {"203.0.113.9"}}
	resp := send(t, h, s, ik.Public(), rpub, s.route, "POST", "/api/v2/sensor/heartbeat?x=1", hdr)
	if resp == nil || resp.Status != 200 || string(resp.Body) != `{"path":"/api/v2/sensor/heartbeat"}` {
		t.Fatalf("answer %+v", resp)
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Internal-Trace") != "" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("answer headers %v", resp.Header)
	}
	api.mu.Lock()
	got, body := api.seen[0], api.body[0]
	api.mu.Unlock()
	if got.URL.RawQuery != "x=1" || got.Header.Get("Signature") != "sig1=:abc:" || string(body) != `{"k":1}` {
		t.Fatalf("API saw %s %v %q", got.URL, got.Header, body)
	}
	for _, h := range []string{"X-Forwarded-For", "Cookie", "X-Real-Ip"} {
		if got.Header.Get(h) != "" {
			t.Errorf("%s forwarded to the API", h)
		}
	}
}

func TestConnectorRefusesPathsOutsideSensorRoutes(t *testing.T) {
	h := newHarness(t, Limits{})
	api := newFakeAPI(t)
	ik, rpub := startConnector(t, h, api.ts.URL)
	s := newRelayedSensor(h, "sensor-a")
	for _, p := range []string{"/api/v1/admin/users", "/api/v2/sensor/../../v1/users", "/api/v2/sensor/%2e%2e/x", "/api/v2/sensorx", "//evil.example.com/api/v2/sensor/x"} {
		resp := send(t, h, s, ik.Public(), rpub, s.route, "GET", p, nil)
		if resp == nil || resp.Status != http.StatusForbidden {
			t.Errorf("%s: answer %+v, want 403", p, resp)
		}
	}
	if n := api.calls(); n != 0 {
		t.Fatalf("API called %d times for refused paths", n)
	}
}

// TestConnectorRefusesMisroutedEnvelope: a sensor that seals an envelope
// for another sensor's route and posts it in its own mailbox gets nothing,
// and the API never sees it.
func TestConnectorRefusesMisroutedEnvelope(t *testing.T) {
	h := newHarness(t, Limits{})
	api := newFakeAPI(t)
	ik, rpub := startConnector(t, h, api.ts.URL)
	a := newRelayedSensor(h, "sensor-a")
	if resp := send(t, h, a, ik.Public(), rpub, sealed.Route{Realm: "realm-1", SensorID: "sensor-b"}, "GET", "/api/v2/sensor/commands", nil); resp != nil {
		t.Fatalf("misrouted envelope answered: %+v", resp)
	}
	// Sealed to another ingest key: nothing either.
	other, _ := sealed.GenerateKey()
	if resp := send(t, h, a, other.Public(), rpub, a.route, "GET", "/api/v2/sensor/commands", nil); resp != nil {
		t.Fatalf("envelope for another key answered: %+v", resp)
	}
	if n := api.calls(); n != 0 {
		t.Fatalf("API called %d times", n)
	}
}

func TestConnectorAPIUnavailable(t *testing.T) {
	h := newHarness(t, Limits{})
	ik, rpub := startConnector(t, h, "http://127.0.0.1:1")
	s := newRelayedSensor(h, "sensor-a")
	if resp := send(t, h, s, ik.Public(), rpub, s.route, "GET", "/api/v2/sensor/hello", nil); resp == nil || resp.Status != http.StatusBadGateway {
		t.Fatalf("answer %+v, want 502", resp)
	}
}

func TestAllowedPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/v2/sensor/heartbeat":                 true,
		"/api/v2/sensor/results/abc?x=1&y=2":       true,
		"/api/v2/sensor/commands/":                 true,
		"/api/v2/sensor":                           false,
		"/api/v2/sensor/../x":                      false,
		"/api/v2/sensor/./heartbeat":               false,
		"/api/v2/sensor//heartbeat":                false,
		"/api/v2/sensor/%2e%2e/x":                  false,
		"/api/v2/sensor/a%2Fb":                     false,
		"/api/v1/sensors":                          false,
		"https://evil.example.com/api/v2/sensor/x": false,
		"api/v2/sensor/x":                          false,
	} {
		if got := allowedPath(p); got != want {
			t.Errorf("allowedPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestConnectorConfigRefusals(t *testing.T) {
	ik, _ := sealed.GenerateKey()
	_, rk, _ := ed25519.GenerateKey(nil)
	h := newHarness(t, Limits{})
	good := ConnectorConfig{RelayURL: "https://relay.example.com", ClientCert: h.conn1, Realm: "realm-1",
		IngestKeys: []*sealed.PrivateKey{ik}, ResponseKey: rk, APIURL: "http://api:8080"}
	if _, err := NewConnector(good); err != nil {
		t.Fatalf("good: %v", err)
	}
	for name, mod := range map[string]func(*ConnectorConfig){
		"http relay":  func(c *ConnectorConfig) { c.RelayURL = "http://relay.example.com" },
		"bad api url": func(c *ConnectorConfig) { c.APIURL = "ftp://x" },
		"no realm":    func(c *ConnectorConfig) { c.Realm = "" },
		"no ingest":   func(c *ConnectorConfig) { c.IngestKeys = nil },
		"no resp key": func(c *ConnectorConfig) { c.ResponseKey = nil },
		"no cert":     func(c *ConnectorConfig) { c.ClientCert.Certificate = nil },
		"short pin":   func(c *ConnectorConfig) { c.RelayPin = []byte{1} },
	} {
		c := good
		mod(&c)
		if _, err := NewConnector(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The default API client never sends opened sensor requests through a proxy
// from the environment.
func TestConnectorAPIClientIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	tr, ok := newAPIClient().Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("the API client must not use a proxy")
	}
	if newAPIClient().CheckRedirect == nil {
		t.Fatal("the API client must not follow redirects")
	}
}
