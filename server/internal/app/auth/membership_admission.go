package auth

// What each of a person's organizations asks of the current session before it
// admits it: docs/architecture/tenantless-account-space.md ("Memberships").

import (
	"context"
	"errors"
	"fmt"

	sessiondom "github.com/openctemio/openctem/server/pkg/domain/session"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ErrAdmissionSessionUnknown: the session named by the access token cannot be
// read (ended meanwhile, or not the caller's). The listing reports no
// admission for it.
var ErrAdmissionSessionUnknown = errors.New("session not found")

// MembershipAdmission runs, for each of the caller's organizations, the same
// rules the token exchange applies to this session (admitSession), without
// minting anything or spending a token, and returns the first refusal per
// organization (nil: the session would be admitted). The keys are the
// organizations the user is an active member of, read from the database by
// the user id of the access token; nothing in the request chooses them, so
// the answer names no organization the person does not belong to.
//
// It is read-only (admitCheck): it states what the person's own token request
// would answer, and records no break-glass sign-in and notifies nobody; only
// the token exchange and refresh do that.
func (s *AuthService) MembershipAdmission(ctx context.Context, userID, sessionID string) (map[string]error, error) {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return nil, ErrAdmissionSessionUnknown
	}
	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil || sess == nil || !sess.UserID().Equals(uid) {
		return nil, ErrAdmissionSessionUnknown
	}
	if !sess.IsActive() {
		return nil, sessiondom.ErrSessionExpired
	}
	u, err := s.userRepo.GetByID(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	out := make(map[string]error, len(memberships))
	for _, m := range memberships {
		out[m.TenantID] = s.admitSession(ctx, sess, u, m.TenantID, m.Role, admitCheck)
	}
	return out, nil
}
