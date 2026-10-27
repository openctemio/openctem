package auth

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SessionsRevokedHook runs after the sessions of an account were revoked
// because one of its credentials changed: a password reset or change, an
// administrator's two-step reset, enabling two-step verification, or a
// sign-out of every device. Two hooks are wired in production: the platform
// admin console ends the console sessions of the administrator linked to the
// account, and the MCP service revokes the person's connected applications in
// every organization, so a stolen session does not outlive the credential it
// was opened with and a connector approved with it does not either.
//
// A hook must touch only the one user it is given.
type SessionsRevokedHook func(ctx context.Context, userID shared.ID)

// APIKeyRevoker revokes the API keys a person owns (apikey.Service). It is
// optional: called only when the request asks for it.
type APIKeyRevoker interface {
	// RevokeAllForUser revokes every active key the user owns, in every
	// organization, and returns how many.
	RevokeAllForUser(ctx context.Context, userID shared.ID) (int, error)
	// CountActiveForUser counts the active keys the user owns.
	CountActiveForUser(ctx context.Context, userID shared.ID) (int, error)
}

// SessionsRevokedHooks is the ordered list of hooks plus the optional API key
// revoker. The zero value is ready to use; wire it at start-up, before
// requests are served.
type SessionsRevokedHooks struct {
	hooks []SessionsRevokedHook
	keys  APIKeyRevoker
}

// Add appends a hook (nil is ignored).
func (h *SessionsRevokedHooks) Add(fn SessionsRevokedHook) {
	if fn != nil {
		h.hooks = append(h.hooks, fn)
	}
}

// SetAPIKeyRevoker wires the API key revoker (nil: none).
func (h *SessionsRevokedHooks) SetAPIKeyRevoker(k APIKeyRevoker) { h.keys = k }

// Run calls every hook in order. A hook has no error to return: each one
// logs its own failure, and one failing must not stop the others.
func (h *SessionsRevokedHooks) Run(ctx context.Context, userID shared.ID) {
	for _, fn := range h.hooks {
		fn(ctx, userID)
	}
}

// RevokeAPIKeysIf revokes the user's API keys when asked and returns how many
// were revoked. A failure is returned as zero: the sessions are already gone,
// and the caller cannot undo that.
func (h *SessionsRevokedHooks) RevokeAPIKeysIf(ctx context.Context, ask bool, userID shared.ID) int {
	if !ask || h.keys == nil {
		return 0
	}
	n, err := h.keys.RevokeAllForUser(ctx, userID)
	if err != nil {
		return 0
	}
	return n
}

// CountActiveAPIKeys counts the user's active API keys (0 without a revoker).
func (h *SessionsRevokedHooks) CountActiveAPIKeys(ctx context.Context, userID shared.ID) int {
	if h.keys == nil {
		return 0
	}
	n, err := h.keys.CountActiveForUser(ctx, userID)
	if err != nil {
		return 0
	}
	return n
}

// SessionsRevoked returns the shared hook list, for services that revoke
// sessions outside AuthService (SessionService).
func (s *AuthService) SessionsRevoked() *SessionsRevokedHooks { return &s.sessionsRevoked }

// AddSessionsRevokedHook appends a hook run after the account's sessions
// were revoked.
func (s *AuthService) AddSessionsRevokedHook(h SessionsRevokedHook) { s.sessionsRevoked.Add(h) }

// SetAPIKeyRevoker wires the optional API key revocation.
func (s *AuthService) SetAPIKeyRevoker(k APIKeyRevoker) { s.sessionsRevoked.SetAPIKeyRevoker(k) }

func (s *AuthService) runSessionsRevokedHook(ctx context.Context, userID shared.ID) {
	s.sessionsRevoked.Run(ctx, userID)
}
