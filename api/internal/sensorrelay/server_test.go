package sensorrelay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
)

func selfSigned(t *testing.T, pub crypto.PublicKey, priv crypto.Signer, dns string) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: dns},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{dns},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
}

type harness struct {
	t         *testing.T
	srv       *Server
	ts        *httptest.Server
	ticketKey ed25519.PrivateKey
	roots     *x509.CertPool
	conn1     tls.Certificate // connector of realm-1
	conn2     tls.Certificate // connector of realm-2
	server    tls.Certificate
	now       time.Time
	nowMu     sync.Mutex
}

func newHarness(t *testing.T, lim Limits) *harness {
	t.Helper()
	h := &harness{t: t, now: time.Now()}
	tkPub, tkPriv, _ := ed25519.GenerateKey(nil)
	h.ticketKey = tkPriv
	tk2Pub, _, _ := ed25519.GenerateKey(nil)
	ck1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ck2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.conn1 = selfSigned(t, &ck1.PublicKey, ck1, "connector-1")
	h.conn2 = selfSigned(t, &ck2.PublicKey, ck2, "connector-2")
	pin := func(c tls.Certificate) [32]byte { return sha256.Sum256(c.Leaf.RawSubjectPublicKeyInfo) }
	srv, err := New(Config{RelayID: "relay-1", Limits: lim, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Realms: []Realm{
			{Name: "realm-1", TicketKeys: []ed25519.PublicKey{tkPub}, ConnectorPins: [][32]byte{pin(h.conn1)}},
			{Name: "realm-2", TicketKeys: []ed25519.PublicKey{tk2Pub}, ConnectorPins: [][32]byte{pin(h.conn2)}},
		},
		now: func() time.Time { h.nowMu.Lock(); defer h.nowMu.Unlock(); return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverCert := selfSigned(t, &sk.PublicKey, sk, "relay.example.com")
	h.server = serverCert
	h.roots = x509.NewCertPool()
	h.roots.AddCert(serverCert.Leaf)
	h.ts = httptest.NewUnstartedServer(srv.Handler())
	h.ts.TLS = srv.TLSConfig(serverCert)
	h.ts.StartTLS()
	t.Cleanup(h.ts.Close)
	return h
}

// sensor is a sensor identity: an Ed25519 key, its certificate and a ticket.
type sensor struct {
	cert   tls.Certificate
	ticket string
}

func (h *harness) sensor(id, realm string, mod func(*relay.Ticket)) sensor {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tk := relay.Ticket{V: 1, Realm: realm, Tenant: "tenant-1", Sensor: id, Key: pub, Relay: "relay-1",
		IAT: h.now.Unix(), Exp: h.now.Add(time.Hour).Unix()}
	if mod != nil {
		mod(&tk)
	}
	tok, err := relay.SignTicket(h.ticketKey, tk)
	if err != nil {
		h.t.Fatal(err)
	}
	return sensor{cert: selfSigned(h.t, pub, priv, id), ticket: tok}
}

func (h *harness) client(cert tls.Certificate) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: h.roots, ServerName: "relay.example.com", Certificates: []tls.Certificate{cert}}}}
}

func (h *harness) do(cert tls.Certificate, method, path, ticket string, body []byte) (int, []byte) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.ts.URL+path, bytes.NewReader(body))
	if ticket != "" {
		req.Header.Set(relay.TicketHeader, ticket)
	}
	resp, err := h.client(cert).Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func batch(t *testing.T, b []byte) []relay.Item {
	t.Helper()
	items, err := relay.ReadBatch(bytes.NewReader(b), 100, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestRelayRoundTrip(t *testing.T) {
	h := newHarness(t, Limits{})
	a := h.sensor("sensor-a", "realm-1", nil)
	if code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("sealed-request")); code != http.StatusAccepted {
		t.Fatalf("sensor up = %d", code)
	}
	code, body := h.do(h.conn1, "GET", relay.PathConnectorUp+"?wait=1", "", nil)
	if code != http.StatusOK {
		t.Fatalf("connector up = %d", code)
	}
	items := batch(t, body)
	if len(items) != 1 || items[0].Sensor != "sensor-a" || string(items[0].Envelope) != "sealed-request" {
		t.Fatalf("connector got %+v", items)
	}
	if code, _ := h.do(h.conn1, "POST", relay.PathConnectorDown+"sensor-a", "", []byte("sealed-response")); code != http.StatusAccepted {
		t.Fatalf("connector down = %d", code)
	}
	code, body = h.do(a.cert, "GET", relay.PathSensorDown+"?wait=1", a.ticket, nil)
	if code != http.StatusOK {
		t.Fatalf("sensor down = %d", code)
	}
	if items := batch(t, body); len(items) != 1 || string(items[0].Envelope) != "sealed-response" || items[0].Sensor != "" {
		t.Fatalf("sensor got %+v", items)
	}
	// Empty mailbox after the wait: 204.
	if code, _ := h.do(a.cert, "GET", relay.PathSensorDown+"?wait=0", a.ticket, nil); code != http.StatusNoContent {
		t.Fatalf("empty poll = %d", code)
	}
}

func TestLongPollWakes(t *testing.T) {
	h := newHarness(t, Limits{})
	a := h.sensor("sensor-a", "realm-1", nil)
	done := make(chan []relay.Item, 1)
	go func() {
		code, body := h.do(a.cert, "GET", relay.PathSensorDown+"?wait=10", a.ticket, nil)
		if code != http.StatusOK {
			done <- nil
			return
		}
		done <- batch(t, body)
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	h.do(h.conn1, "POST", relay.PathConnectorDown+"sensor-a", "", []byte("wake"))
	select {
	case items := <-done:
		if len(items) != 1 || time.Since(start) > 5*time.Second {
			t.Fatalf("long poll: %+v after %s", items, time.Since(start))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("long poll not woken")
	}
}

// TestSensorIsolation: a sensor reaches only its own mailbox, and only with
// its own key; another realm's connector sees nothing of this realm.
func TestSensorIsolation(t *testing.T) {
	h := newHarness(t, Limits{})
	a := h.sensor("sensor-a", "realm-1", nil)
	b := h.sensor("sensor-b", "realm-1", nil)
	h.do(h.conn1, "POST", relay.PathConnectorDown+"sensor-a", "", []byte("for-a"))
	// b cannot use a's ticket with its own key.
	if code, _ := h.do(b.cert, "GET", relay.PathSensorDown+"?wait=0", a.ticket, nil); code != http.StatusUnauthorized {
		t.Fatalf("a's ticket over b's key = %d", code)
	}
	// b's own poll never returns a's envelope.
	if code, _ := h.do(b.cert, "GET", relay.PathSensorDown+"?wait=0", b.ticket, nil); code != http.StatusNoContent {
		t.Fatalf("b polled a's mailbox: %d", code)
	}
	// realm-2's connector sees none of realm-1's traffic, and what it posts
	// for "sensor-a" lands in realm-2's mailbox, not in realm-1's.
	h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("from-a"))
	if code, _ := h.do(h.conn2, "GET", relay.PathConnectorUp+"?wait=0", "", nil); code != http.StatusNoContent {
		t.Fatalf("realm-2 connector saw realm-1 traffic: %d", code)
	}
	h.do(h.conn2, "POST", relay.PathConnectorDown+"sensor-a", "", []byte("from-realm-2"))
	code, body := h.do(a.cert, "GET", relay.PathSensorDown+"?wait=0", a.ticket, nil)
	if code != http.StatusOK {
		t.Fatalf("a poll = %d", code)
	}
	for _, it := range batch(t, body) {
		if string(it.Envelope) == "from-realm-2" {
			t.Fatal("another realm's connector reached sensor-a")
		}
	}
}

func TestAuthRefusals(t *testing.T) {
	h := newHarness(t, Limits{})
	good := h.sensor("sensor-a", "realm-1", nil)
	expired := h.sensor("sensor-a", "realm-1", func(tk *relay.Ticket) {
		tk.IAT = h.now.Add(-3 * time.Hour).Unix()
		tk.Exp = h.now.Add(-2 * time.Hour).Unix()
	})
	otherRelay := h.sensor("sensor-a", "realm-1", func(tk *relay.Ticket) { tk.Relay = "relay-2" })
	// A ticket claiming realm-2 but signed with realm-1's key.
	wrongRealmKey := h.sensor("sensor-a", "realm-2", nil)
	unknownRealm := h.sensor("sensor-a", "realm-9", nil)
	for name, c := range map[string]struct {
		cert   tls.Certificate
		ticket string
	}{
		"no ticket":                {good.cert, ""},
		"expired":                  {expired.cert, expired.ticket},
		"other relay":              {otherRelay.cert, otherRelay.ticket},
		"wrong realm key":          {wrongRealmKey.cert, wrongRealmKey.ticket},
		"unknown realm":            {unknownRealm.cert, unknownRealm.ticket},
		"connector cert as sensor": {h.conn1, good.ticket},
	} {
		if code, _ := h.do(c.cert, "POST", relay.PathSensorUp, c.ticket, []byte("x")); code != http.StatusUnauthorized {
			t.Errorf("%s: up = %d", name, code)
		}
	}
	// A sensor certificate is not a connector.
	if code, _ := h.do(good.cert, "GET", relay.PathConnectorUp+"?wait=0", "", nil); code != http.StatusUnauthorized {
		t.Errorf("sensor as connector = %d", code)
	}
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stranger := selfSigned(t, &ck.PublicKey, ck, "stranger")
	if code, _ := h.do(stranger, "POST", relay.PathConnectorDown+"sensor-a", "", []byte("x")); code != http.StatusUnauthorized {
		t.Errorf("unpinned connector = %d", code)
	}
	// No client certificate at all: the handshake fails.
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: h.roots, ServerName: "relay.example.com"}}}
	noCertReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.ts.URL+relay.PathSensorDown, nil)
	if resp, err := cl.Do(noCertReq); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("no client certificate = %d", resp.StatusCode)
		}
	}
	// Bad sensor id in the connector path.
	if code, _ := h.do(h.conn1, "POST", relay.PathConnectorDown+"..x", "", []byte("x")); code != http.StatusBadRequest {
		t.Errorf("bad sensor id = %d", code)
	}
}

func TestQuotas(t *testing.T) {
	h := newHarness(t, Limits{MailboxItems: 2, SensorRate: 1000, SensorBurst: 1000})
	a := h.sensor("sensor-a", "realm-1", nil)
	for i := range 2 {
		if code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("x")); code != http.StatusAccepted {
			t.Fatalf("put %d = %d", i, code)
		}
	}
	if code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("x")); code != http.StatusTooManyRequests {
		t.Fatalf("over the mailbox cap = %d", code)
	}
	// Another sensor of the realm is not blocked by a's full mailbox.
	b := h.sensor("sensor-b", "realm-1", nil)
	if code, _ := h.do(b.cert, "POST", relay.PathSensorUp, b.ticket, []byte("x")); code != http.StatusAccepted {
		t.Fatalf("b blocked by a's quota: %d", code)
	}
	// Draining frees a's quota.
	h.do(h.conn1, "GET", relay.PathConnectorUp+"?wait=0", "", nil)
	if code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("x")); code != http.StatusAccepted {
		t.Fatalf("after drain = %d", code)
	}
	for range 3 {
		h.do(h.conn1, "POST", relay.PathConnectorDown+"sensor-c", "", []byte("x"))
	}
	if code, _ := h.do(h.conn1, "POST", relay.PathConnectorDown+"sensor-c", "", []byte("x")); code != http.StatusTooManyRequests {
		t.Fatalf("down over the cap = %d", code)
	}
}

func TestRateLimitAndPolls(t *testing.T) {
	h := newHarness(t, Limits{SensorRate: 1, SensorBurst: 2, MaxPollsPerSensor: 1})
	a := h.sensor("sensor-a", "realm-1", nil)
	codes := map[int]int{}
	for range 4 {
		code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("x"))
		codes[code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("no rate limit: %v", codes)
	}
	started := make(chan struct{})
	go func() {
		close(started)
		h.do(a.cert, "GET", relay.PathSensorDown+"?wait=3", a.ticket, nil)
	}()
	<-started
	time.Sleep(300 * time.Millisecond)
	if code, _ := h.do(a.cert, "GET", relay.PathSensorDown+"?wait=0", a.ticket, nil); code != http.StatusTooManyRequests {
		t.Fatalf("second concurrent poll = %d", code)
	}
}

func TestOversizeAndEmpty(t *testing.T) {
	h := newHarness(t, Limits{})
	a := h.sensor("sensor-a", "realm-1", nil)
	if code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, make([]byte, relay.MaxEnvelope+1)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize = %d", code)
	}
	if code, _ := h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, nil); code != http.StatusBadRequest {
		t.Fatalf("empty = %d", code)
	}
}

func TestExpiry(t *testing.T) {
	h := newHarness(t, Limits{TTL: time.Minute})
	a := h.sensor("sensor-a", "realm-1", nil)
	h.do(a.cert, "POST", relay.PathSensorUp, a.ticket, []byte("old"))
	h.do(h.conn1, "POST", relay.PathConnectorDown+"sensor-a", "", []byte("old"))
	h.nowMu.Lock()
	h.now = h.now.Add(2 * time.Minute)
	h.nowMu.Unlock()
	h.srv.sweep()
	if code, _ := h.do(h.conn1, "GET", relay.PathConnectorUp+"?wait=0", "", nil); code != http.StatusNoContent {
		t.Fatalf("expired up envelope delivered: %d", code)
	}
	if code, _ := h.do(a.cert, "GET", relay.PathSensorDown+"?wait=0", a.ticket, nil); code != http.StatusNoContent {
		t.Fatalf("expired down envelope delivered: %d", code)
	}
	if h.srv.boxes.held() != 0 {
		t.Fatalf("bytes held after expiry: %d", h.srv.boxes.held())
	}
}

func TestConfigRefusals(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pin := [32]byte{1}
	for name, cfg := range map[string]Config{
		"bad relay id":   {RelayID: "../r", Realms: []Realm{{Name: "r", TicketKeys: []ed25519.PublicKey{pub}, ConnectorPins: [][32]byte{pin}}}},
		"no realm":       {RelayID: "r"},
		"no ticket key":  {RelayID: "r", Realms: []Realm{{Name: "r", ConnectorPins: [][32]byte{pin}}}},
		"no pin":         {RelayID: "r", Realms: []Realm{{Name: "r", TicketKeys: []ed25519.PublicKey{pub}}}},
		"duplicate pin":  {RelayID: "r", Realms: []Realm{{Name: "a", TicketKeys: []ed25519.PublicKey{pub}, ConnectorPins: [][32]byte{pin}}, {Name: "b", TicketKeys: []ed25519.PublicKey{pub}, ConnectorPins: [][32]byte{pin}}}},
		"duplicate name": {RelayID: "r", Realms: []Realm{{Name: "a", TicketKeys: []ed25519.PublicKey{pub}, ConnectorPins: [][32]byte{pin}}, {Name: "a", TicketKeys: []ed25519.PublicKey{pub}, ConnectorPins: [][32]byte{{2}}}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParsePin("zz"); err == nil {
		t.Error("bad pin accepted")
	}
	if p, err := ParsePin("sha256:" + PinOf([]byte("spki"))); err != nil || p != sha256.Sum256([]byte("spki")) {
		t.Errorf("pin round trip: %v", err)
	}
}
