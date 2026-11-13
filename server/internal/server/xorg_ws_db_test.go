package server

// The real-time channel across organizations, over the real /api/v1/ws route
// and the real hub: a socket bound to organization A receives nothing that is
// published for B, and cannot subscribe to B's topics, including after the
// person it belongs to has switched to B (their new B session is a different
// socket; the A socket stays an A socket).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"

	"github.com/openctemio/openctem/server/internal/infra/websocket"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// xoSocket reads its connection in one goroutine (a read that times out
// leaves a gorilla connection unusable) and hands over what arrives.
type xoSocket struct {
	conn    *gws.Conn
	msgs    chan websocket.Message
	pending []websocket.Message
}

func (h *xoStack) dialWS(token string) *xoSocket {
	h.t.Helper()
	u := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/api/v1/ws/"
	hdr := map[string][]string{"Authorization": {"Bearer " + token}}
	conn, resp, err := gws.DefaultDialer.Dial(u, hdr)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		h.t.Fatalf("dial /api/v1/ws: %v (status %d)", err, status)
	}
	s := &xoSocket{conn: conn, msgs: make(chan websocket.Message, 256)}
	h.t.Cleanup(func() { _ = conn.Close() })
	go func() {
		defer close(s.msgs)
		for {
			var msg websocket.Message
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			s.msgs <- msg
		}
	}()
	return s
}

// subscribe asks for a channel and returns the reply type; events that
// arrive meanwhile are kept for next.
func (s *xoSocket) subscribe(t *testing.T, channel string) websocket.MessageType {
	t.Helper()
	data, _ := json.Marshal(websocket.SubscribeRequest{Channel: channel, RequestID: channel})
	if err := s.conn.WriteJSON(websocket.Message{Type: websocket.MessageTypeSubscribe, Data: data}); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case msg, ok := <-s.msgs:
			if !ok {
				t.Fatalf("socket closed while subscribing to %s", channel)
			}
			switch msg.Type {
			case websocket.MessageTypeSubscribed, websocket.MessageTypeError:
				return msg.Type
			case websocket.MessageTypeEvent:
				s.pending = append(s.pending, msg)
			}
		case <-timeout:
			t.Fatalf("no reply for %s", channel)
		}
	}
}

// next returns the next event within wait, or nil.
func (s *xoSocket) next(wait time.Duration) *websocket.Message {
	if len(s.pending) > 0 {
		m := s.pending[0]
		s.pending = s.pending[1:]
		return &m
	}
	timeout := time.After(wait)
	for {
		select {
		case msg, ok := <-s.msgs:
			if !ok {
				return nil
			}
			if msg.Type == websocket.MessageTypeEvent {
				return &msg
			}
		case <-timeout:
			return nil
		}
	}
}

func TestCrossOrg_WebSocket_BoundToItsOrganization(t *testing.T) {
	h := newXOStack(t)
	hub := h.services.WebSocketHub

	// One person belongs to both organizations; each organization has its
	// own session and token, and the console opens one socket per session.
	person := shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'xo person')`, person.String(), person.String()+"@xo.test")
	for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'owner')`, person.String(), tn.String())
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, person.String(), tn.String(), xoOwnerRoleID)
	}
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, person.String())
	})
	sessA, sessB := h.seedSession(person), h.seedSession(person)
	tokA := h.mint(person, h.tenantA, h.slugA, sessA)
	tokB := h.mint(person, h.tenantB, h.slugB, sessB)

	findingB := h.seedFinding(h.tenantB, h.seedAsset(h.tenantB))
	runB := h.seedScanRun(h.tenantB, h.seedScan(h.tenantB))
	ownA, ownB := "tenant:"+h.tenantA.String(), "tenant:"+h.tenantB.String()

	sockA := h.dialWS(tokA)
	if got := sockA.subscribe(t, ownA); got != websocket.MessageTypeSubscribed {
		t.Fatalf("A's own tenant channel: %s, want subscribed", got)
	}
	if got := sockA.subscribe(t, "user:"+h.tenantA.String()+":"+person.String()); got != websocket.MessageTypeSubscribed {
		t.Fatalf("A's own user channel: %s, want subscribed", got)
	}

	// B's topics are refused to the socket bound to A, although the person
	// is an owner of B and the same person would be allowed on a B socket.
	refused := []string{
		ownB,
		"user:" + h.tenantB.String() + ":" + person.String(),
		"finding:" + findingB,
		"triage:" + findingB,
		"run:" + runB,
	}
	for _, ch := range refused {
		if got := sockA.subscribe(t, ch); got != websocket.MessageTypeError {
			t.Errorf("a socket bound to A subscribed to %s: %s, want error", ch, got)
		}
	}

	// Switching to B opens a B socket; B's events reach it and not A's.
	sockB := h.dialWS(tokB)
	if got := sockB.subscribe(t, ownB); got != websocket.MessageTypeSubscribed {
		t.Fatalf("B's own tenant channel on the B socket: %s, want subscribed", got)
	}
	if got := sockB.subscribe(t, ownA); got != websocket.MessageTypeError {
		t.Errorf("a socket bound to B subscribed to A's tenant channel: %s, want error", got)
	}
	hub.BroadcastEvent(ownB, map[string]string{"marker": xoMarker + "-for-b"}, h.tenantB.String())
	if msg := sockB.next(3 * time.Second); msg == nil {
		t.Error("the B socket did not receive B's event (the fixture is not live)")
	}
	if msg := sockA.next(700 * time.Millisecond); msg != nil {
		t.Errorf("the A socket received an event published for B: %s", msg.Data)
	}

	// A message that names B on a channel the A socket did subscribe to is
	// not delivered either (the tenant on the message is checked per socket).
	hub.BroadcastEvent(ownA, map[string]string{"marker": xoMarker + "-wrong-tenant"}, h.tenantB.String())
	if msg := sockA.next(700 * time.Millisecond); msg != nil {
		t.Errorf("the A socket received a message stamped for B on its own channel: %s", msg.Data)
	}
	// The same message stamped for A does arrive: the A socket is live.
	hub.BroadcastEvent(ownA, map[string]string{"marker": "for-a"}, h.tenantA.String())
	if msg := sockA.next(3 * time.Second); msg == nil {
		t.Error("the A socket did not receive A's event (the fixture is not live)")
	}

	// Channels that need only a permission (scan, group) accept any id for
	// a reader: B's id on them still delivers nothing, because delivery is
	// per tenant.
	scanB := "scan:" + h.seedScan(h.tenantB)
	groupB := "group:" + h.seedAccessGroup(h.tenantB)
	for _, ch := range []string{scanB, groupB} {
		_ = sockA.subscribe(t, ch) // accepted or refused: both are safe
		hub.BroadcastEvent(ch, map[string]string{"marker": xoMarker + "-" + ch}, h.tenantB.String())
		if msg := sockA.next(500 * time.Millisecond); msg != nil {
			t.Errorf("the A socket received B's event on %s: %s", ch, msg.Data)
		}
	}
}
