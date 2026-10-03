package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Session binding (RFC-045): a socket lives no longer than the credential and
// session it was opened with, and closes when the user's access changes.

// testIdentity is what the stand-in auth middleware puts in the context.
type testIdentity struct {
	user, tenant, session string
	expires               time.Time
}

// wsServer serves ServeWS behind a stand-in for the auth middleware that
// injects the identity named by the "id" query parameter.
type wsServer struct {
	t       *testing.T
	hub     *Hub
	handler *Handler
	srv     *httptest.Server
	mu      sync.Mutex
	ids     map[string]testIdentity
}

func newWSServer(t *testing.T, hub *Hub) *wsServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go hub.Run(ctx)

	s := &wsServer{t: t, hub: hub, handler: NewHandler(hub, logger.NewNop(), nil, ""), ids: map[string]testIdentity{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		id := s.ids[r.URL.Query().Get("id")]
		s.mu.Unlock()
		c := r.Context()
		c = context.WithValue(c, middleware.UserIDKey, id.user)
		c = context.WithValue(c, middleware.TenantIDKey, id.tenant)
		c = context.WithValue(c, middleware.SessionIDKey, id.session)
		c = context.WithValue(c, middleware.CredentialExpiresAtKey, id.expires)
		s.handler.ServeWS(w, r.WithContext(c))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// dial opens a socket as id and waits until the hub has registered it.
func (s *wsServer) dial(name string, id testIdentity) *websocket.Conn {
	s.t.Helper()
	if id.expires.IsZero() {
		id.expires = time.Now().Add(time.Hour)
	}
	s.mu.Lock()
	s.ids[name] = id
	s.mu.Unlock()
	before := s.live(id)
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.srv.URL, "http")+"/?id="+name, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		s.t.Fatalf("dial %s: %v", name, err)
	}
	s.t.Cleanup(func() { _ = conn.Close() })
	waitFor(s.t, func() bool { return s.live(id) > before })
	return conn
}

// live counts registered, open connections with id's user, tenant and session.
func (s *wsServer) live(id testIdentity) int {
	n := 0
	for _, c := range s.hub.GetClientsByTenant(id.tenant) {
		if c.UserID == id.user && c.SessionID == id.session && !c.isDone() {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// closeCode reads until the connection ends and returns the close code the
// server sent (0 if it ended without a close frame, -1 if still open).
func closeCode(t *testing.T, conn *websocket.Conn, within time.Duration) int {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				return ce.Code
			}
			var ne interface{ Timeout() bool }
			if errors.As(err, &ne) && ne.Timeout() {
				return -1
			}
			return 0
		}
	}
}

// stillOpen proves the socket still works: a ping gets its pong.
func stillOpen(t *testing.T, conn *websocket.Conn) bool {
	t.Helper()
	if err := conn.WriteJSON(Message{Type: MessageTypePing}); err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var m Message
		if err := conn.ReadJSON(&m); err != nil {
			return false
		}
		if m.Type == MessageTypePong {
			return true
		}
	}
}

func TestSocket_ClosesWhenItsSessionIsRevoked(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	revoked := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})
	sameUserOtherDevice := s.dial("b", testIdentity{user: "u1", tenant: "t1", session: "s2"})

	s.hub.RevokeSession(context.Background(), "s1")

	if code := closeCode(t, revoked, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("revoked session socket: close code %d, want %d", code, CloseUnauthorized)
	}
	if !stillOpen(t, sameUserOtherDevice) {
		t.Fatal("a socket of another session of the same user was closed")
	}
}

func TestSocket_ClosesWhenAccessChangesInItsTenant(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	changed := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})
	otherTenant := s.dial("b", testIdentity{user: "u1", tenant: "t2", session: "s1b"})
	otherUser := s.dial("c", testIdentity{user: "u2", tenant: "t1", session: "s3"})

	s.hub.RevokeAccess(context.Background(), "t1", "u1")

	if code := closeCode(t, changed, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("socket after access change: close code %d, want %d", code, CloseUnauthorized)
	}
	if !stillOpen(t, otherTenant) {
		t.Fatal("the same user's socket in another tenant was closed")
	}
	if !stillOpen(t, otherUser) {
		t.Fatal("another user's socket in the tenant was closed")
	}
}

func TestSocket_ClosesAtCredentialExpiry(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	conn := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1", expires: time.Now().Add(300 * time.Millisecond)})

	if code := closeCode(t, conn, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("close code at expiry %d, want %d", code, CloseUnauthorized)
	}
}

func TestHandler_ConnectionDeadlineIsCappedAndNeverUnbounded(t *testing.T) {
	h := NewHandler(NewHub(logger.NewNop()), logger.NewNop(), nil, "")
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	// No credential expiry known: the lifetime cap applies.
	d := h.connectionDeadline(time.Time{})
	if d.After(now.Add(maxConnectionLifetime)) || d.Before(now.Add(maxConnectionLifetime-maxLifetimeJitter)) {
		t.Fatalf("deadline without expiry = %v, want within the jittered cap", d.Sub(now))
	}
	// A long-lived credential is capped too.
	if d := h.connectionDeadline(now.Add(24 * time.Hour)); d.After(now.Add(maxConnectionLifetime)) {
		t.Fatalf("deadline for a 24h token = %v, want capped", d.Sub(now))
	}
	// A credential expiring sooner wins.
	if d := h.connectionDeadline(now.Add(time.Minute)); !d.Equal(now.Add(time.Minute)) {
		t.Fatalf("deadline = %v, want the credential expiry", d.Sub(now))
	}
}

func TestHandler_RefusesAlreadyExpiredCredential(t *testing.T) {
	hub := NewHub(logger.NewNop())
	h := NewHandler(hub, logger.NewNop(), nil, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c := context.WithValue(req.Context(), middleware.UserIDKey, "u1")
	c = context.WithValue(c, middleware.TenantIDKey, "t1")
	c = context.WithValue(c, middleware.CredentialExpiresAtKey, time.Now().Add(-time.Second))
	rec := httptest.NewRecorder()
	h.ServeWS(rec, req.WithContext(c))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

type fixedRevocationChecker struct{ revoked map[string]bool }

func (f fixedRevocationChecker) IsSessionRevoked(_ context.Context, sid string) (bool, error) {
	return f.revoked[sid], nil
}

// A session revoked while the upgrade was in flight (after the auth
// middleware passed it) is caught by the post-registration check.
func TestSocket_RevokedDuringUpgradeIsClosed(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	s.handler.SetSessionRevocationChecker(fixedRevocationChecker{revoked: map[string]bool{"gone": true}})

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.srv.URL, "http")+"/?id=x", nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	// Identity "x" is unset: make sure the request is refused, then retry
	// with the revoked session.
	if err == nil {
		_ = conn.Close()
		t.Fatal("upgrade without identity succeeded")
	}
	s.mu.Lock()
	s.ids["x"] = testIdentity{user: "u1", tenant: "t1", session: "gone", expires: time.Now().Add(time.Hour)}
	s.mu.Unlock()
	conn, resp, err = websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.srv.URL, "http")+"/?id=x", nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if code := closeCode(t, conn, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, CloseUnauthorized)
	}
}

func TestHub_ApplyRevocation_MalformedClosesNothing(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	conn := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})

	for _, r := range []Revocation{
		{Reason: RevocationSessionRevoked},                                   // names nothing
		{Reason: RevocationAccessChanged, TenantID: "t1"},                    // no user
		{Reason: RevocationAccessChanged, UserID: "u1"},                      // no tenant
		{Reason: "everything", SessionID: "s1"},                              // unknown reason
		{Reason: RevocationSessionRevoked, SessionID: "other"},               // no match
		{Reason: RevocationAccessChanged, TenantID: "t2", UserID: "u1"},      // other tenant
		{Reason: RevocationAccessChanged, TenantID: "t1", UserID: "someone"}, // other user
	} {
		if n := s.hub.ApplyRevocation(r); n != 0 {
			t.Fatalf("%+v closed %d connections, want 0", r, n)
		}
	}
	if !stillOpen(t, conn) {
		t.Fatal("socket closed by a revocation that does not name it")
	}
}

// memBus is an in-process stand-in for the Redis revocation channel: every
// hub on it applies every revocation, as each API instance does.
type memBus struct{ hubs []*Hub }

func (b *memBus) PublishRevocation(_ context.Context, r Revocation) error {
	for _, h := range b.hubs {
		h.ApplyRevocation(r)
	}
	return nil
}

func TestSocket_RevocationReachesEveryInstance(t *testing.T) {
	a, b := NewHub(logger.NewNop()), NewHub(logger.NewNop())
	bus := &memBus{hubs: []*Hub{a, b}}
	a.SetRevocationPublisher(bus)
	b.SetRevocationPublisher(bus)
	sa, sb := newWSServer(t, a), newWSServer(t, b)
	onA := sa.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})
	onB := sb.dial("b", testIdentity{user: "u1", tenant: "t1", session: "s1"})

	// The logout is handled by instance A; the socket on B must close too.
	a.RevokeSession(context.Background(), "s1")

	if code := closeCode(t, onA, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("instance A socket: close code %d, want %d", code, CloseUnauthorized)
	}
	if code := closeCode(t, onB, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("instance B socket: close code %d, want %d", code, CloseUnauthorized)
	}
}

type failingBus struct{}

func (failingBus) PublishRevocation(context.Context, Revocation) error {
	return errors.New("redis down")
}

// With the bus down, the instance that handled the revocation still closes
// its own sockets.
func TestSocket_RevocationFallsBackToLocalWhenBusFails(t *testing.T) {
	hub := NewHub(logger.NewNop())
	hub.SetRevocationPublisher(failingBus{})
	s := newWSServer(t, hub)
	conn := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})

	hub.RevokeSession(context.Background(), "s1")
	if code := closeCode(t, conn, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, CloseUnauthorized)
	}
}

func TestSessionRevocationNotifier_RecordsThenCloses(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	conn := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})
	store := &recordingStore{}

	n := SessionRevocationNotifier{Store: store, Hub: s.hub}
	if err := n.MarkSessionRevoked(context.Background(), "s1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(store.ids) != 1 || store.ids[0] != "s1" {
		t.Fatalf("store got %v, want [s1]", store.ids)
	}
	if code := closeCode(t, conn, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, CloseUnauthorized)
	}

	// Without a store (no Redis) the sockets are still closed.
	conn2 := s.dial("b", testIdentity{user: "u1", tenant: "t1", session: "s2"})
	if err := (SessionRevocationNotifier{Hub: s.hub}).MarkSessionRevoked(context.Background(), "s2", time.Minute); err != nil {
		t.Fatal(err)
	}
	if code := closeCode(t, conn2, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("no-store close code %d, want %d", code, CloseUnauthorized)
	}
}

type recordingStore struct{ ids []string }

func (r *recordingStore) MarkSessionRevoked(_ context.Context, sid string, _ time.Duration) error {
	r.ids = append(r.ids, sid)
	return nil
}

func TestBridge_HandleRevocation(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	conn := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})
	b := &RedisBridge{hub: s.hub, logger: logger.NewNop()}

	b.handleRevocation("{not json")
	b.handleRevocation(`{"reason":"access_changed"}`)
	if !stillOpen(t, conn) {
		t.Fatal("malformed revocation closed a socket")
	}
	payload, _ := json.Marshal(Revocation{Reason: RevocationAccessChanged, TenantID: "t1", UserID: "u1"})
	b.handleRevocation(string(payload))
	if code := closeCode(t, conn, 3*time.Second); code != CloseUnauthorized {
		t.Fatalf("close code %d, want %d", code, CloseUnauthorized)
	}
}

// Limits: a flood of client messages is throttled and then disconnected; a
// user over the per-instance connection cap gets a close code, not a silent
// drop.

func TestSocket_MessageFloodIsThrottledThenClosed(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	conn := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})

	go func() {
		for i := 0; i < messageBurst+maxThrottledMessages+50; i++ {
			if err := conn.WriteJSON(Message{Type: MessageTypePing}); err != nil {
				return
			}
		}
	}()

	// The close frame is written directly, so it can overtake RATE_LIMITED
	// errors still queued for the write pump; only the close is asserted
	// here (TestClient_AllowMessage covers the error reply).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			var ce *websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.ClosePolicyViolation {
				t.Fatalf("flood ended with %v, want close 1008", err)
			}
			return
		}
	}
}

func TestClient_AllowMessage(t *testing.T) {
	c := &Client{
		send:    make(chan []byte, 8),
		logger:  logger.NewNop(),
		limiter: rate.NewLimiter(0, 1), // one message, no refill
	}
	if !c.allowMessage() {
		t.Fatal("first message refused")
	}
	if c.allowMessage() {
		t.Fatal("message over the limit allowed")
	}
	var m Message
	if err := json.Unmarshal(<-c.send, &m); err != nil {
		t.Fatal(err)
	}
	if m.Type != MessageTypeError || !strings.Contains(string(m.Data), "RATE_LIMITED") {
		t.Fatalf("reply %s %s, want a RATE_LIMITED error", m.Type, m.Data)
	}
}

func TestSocket_OverConnectionCapGetsCloseCode(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	for i := 0; i < maxConnectionsPerUser; i++ {
		s.dial(string(rune('a'+i)), testIdentity{user: "u1", tenant: "t1", session: "s1"})
	}
	s.mu.Lock()
	s.ids["over"] = testIdentity{user: "u1", tenant: "t1", session: "s1", expires: time.Now().Add(time.Hour)}
	s.mu.Unlock()
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.srv.URL, "http")+"/?id=over", nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if code := closeCode(t, conn, 3*time.Second); code != CloseTooManyConnections {
		t.Fatalf("close code %d, want %d", code, CloseTooManyConnections)
	}
}
