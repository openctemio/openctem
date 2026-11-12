package redis

import (
	"context"
	"errors"
	"time"
)

// sessionRevocationPrefix namespaces revoked session ids inside the token
// blacklist so they cannot collide with a JWT id.
const sessionRevocationPrefix = "session:"

// SessionRevocationStore remembers revoked session ids for as long as an
// access token minted for them could still be valid. It is both the writer
// (auth.SessionRevocationStore, used when a session is signed out) and the
// reader (middleware.RevokedSessionChecker, used on every request).
//
// Entries are per session id, which is a random UUID unique across tenants,
// and carry a TTL, so the store never grows past the number of sessions
// revoked within one access-token lifetime.
type SessionRevocationStore struct {
	tokens *TokenStore
}

// NewSessionRevocationStore wraps the token blacklist.
func NewSessionRevocationStore(tokens *TokenStore) (*SessionRevocationStore, error) {
	if tokens == nil {
		return nil, errors.New("token store is required")
	}
	return &SessionRevocationStore{tokens: tokens}, nil
}

// MarkSessionRevoked records sessionID as revoked for ttl.
func (s *SessionRevocationStore) MarkSessionRevoked(ctx context.Context, sessionID string, ttl time.Duration) error {
	return s.tokens.BlacklistToken(ctx, sessionRevocationPrefix+sessionID, ttl)
}

// IsSessionRevoked reports whether sessionID was revoked recently.
func (s *SessionRevocationStore) IsSessionRevoked(ctx context.Context, sessionID string) (bool, error) {
	return s.tokens.IsBlacklisted(ctx, sessionRevocationPrefix+sessionID)
}
