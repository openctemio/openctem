package websocket

import (
	"context"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// Suspending an organization closes every socket of that organization (any
// user, any session) and none of another's; a malformed organization
// revocation closes nothing.
func TestHub_RevokeOrganization(t *testing.T) {
	s := newWSServer(t, NewHub(logger.NewNop()))
	a := s.dial("a", testIdentity{user: "u1", tenant: "t1", session: "s1"})
	b := s.dial("b", testIdentity{user: "u2", tenant: "t1", session: "s2"})
	other := s.dial("c", testIdentity{user: "u1", tenant: "t2", session: "s1b"})

	for _, r := range []Revocation{
		{Reason: RevocationOrganizationSuspended},                                  // names nothing
		{Reason: RevocationOrganizationSuspended, TenantID: "t1", UserID: "u1"},    // names a user
		{Reason: RevocationOrganizationSuspended, TenantID: "t1", SessionID: "s1"}, // names a session
	} {
		if n := s.hub.ApplyRevocation(r); n != 0 {
			t.Fatalf("%+v closed %d, want 0", r, n)
		}
	}
	s.hub.RevokeOrganization(context.Background(), "t1")
	for name, c := range map[string]*websocket.Conn{"a": a, "b": b} {
		if code := closeCode(t, c, 3*time.Second); code != CloseUnauthorized {
			t.Fatalf("%s: close code %d, want %d", name, code, CloseUnauthorized)
		}
	}
	if !stillOpen(t, other) {
		t.Fatal("another organization's socket was closed")
	}
}
