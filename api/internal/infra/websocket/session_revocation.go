package websocket

import (
	"context"
	"time"
)

// SessionRevocationRecorder is the shared store that remembers revoked
// session ids (Redis); the HTTP auth middleware reads it on every request.
type SessionRevocationRecorder interface {
	MarkSessionRevoked(ctx context.Context, sessionID string, ttl time.Duration) error
}

// SessionRevocationNotifier is the session revocation store the auth services
// write to on logout, "sign out this device", "sign out everywhere", password
// change, 2FA enrolment, suspension and OIDC back-channel logout. It records
// the revocation in Store (nil without Redis), which stops the session's
// access tokens, and then closes the session's live WebSocket connections on
// every API instance through Hub (RFC-045).
//
// The order matters: a socket registering concurrently re-reads the store
// after it is registered (Handler.ServeWS), so it sees either the store entry
// or the broadcast.
type SessionRevocationNotifier struct {
	Store SessionRevocationRecorder
	Hub   *Hub
}

// MarkSessionRevoked implements the auth services' SessionRevocationStore.
func (n SessionRevocationNotifier) MarkSessionRevoked(ctx context.Context, sessionID string, ttl time.Duration) error {
	var err error
	if n.Store != nil {
		err = n.Store.MarkSessionRevoked(ctx, sessionID, ttl)
	}
	if n.Hub != nil {
		n.Hub.RevokeSession(ctx, sessionID)
	}
	return err
}
