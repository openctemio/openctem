package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EntryRefusal is the answer of CheckEntry when an organization's entry
// requirements are not met. The HTTP layer renders Status, Code and Message.
type EntryRefusal struct {
	Status  int
	Code    apierror.Code
	Message string
	cause   error
}

func (e *EntryRefusal) Error() string { return e.Message }
func (e *EntryRefusal) Unwrap() error { return e.cause }

// HTTPStatus, ErrorCode and PublicMessage let the middleware render the
// refusal without importing this package.
func (e *EntryRefusal) HTTPStatus() int       { return e.Status }
func (e *EntryRefusal) ErrorCode() string     { return string(e.Code) }
func (e *EntryRefusal) PublicMessage() string { return e.Message }

// CheckEntry re-applies, for the organization tenantID, the requirements that
// token issuance applies: SSO enforcement, the organization's two-factor
// rule, its personal-account policy and the outside-member privilege rule.
// It runs on every request of a route that names the organization in the URL
// (/api/v1/tenants/{tenant}/...): such a route accepts a token minted for
// another organization, and the requirements of the organization in the URL
// must hold there too. The session is the token's own session, so a social or
// other federated sign-in is judged exactly as it would be at token issuance.
// A refusal is an *EntryRefusal; any other error is a failure to decide and
// the caller must refuse the request.
func (s *AuthService) CheckEntry(ctx context.Context, sessionID, userID, tenantID string) error {
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return &EntryRefusal{Status: http.StatusUnauthorized, Code: apierror.CodeUnauthorized,
			Message: "Your session is no longer valid. Sign in again.", cause: sessiondom.ErrSessionNotFound}
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil {
		if errors.Is(err, sessiondom.ErrSessionNotFound) || shared.IsNotFound(err) {
			return &EntryRefusal{Status: http.StatusUnauthorized, Code: apierror.CodeUnauthorized,
				Message: "Your session is no longer valid. Sign in again.", cause: err}
		}
		return fmt.Errorf("failed to load session: %w", err)
	}
	if !sess.IsActive() || sess.UserID() != uid {
		return &EntryRefusal{Status: http.StatusUnauthorized, Code: apierror.CodeUnauthorized,
			Message: "Your session is no longer valid. Sign in again.", cause: sessiondom.ErrSessionExpired}
	}
	m, err := s.tenantRepo.GetMembership(ctx, uid, tid)
	if err != nil {
		return fmt.Errorf("failed to load membership: %w", err)
	}

	for _, check := range []func() error{
		func() error { return s.enforceSSOPolicy(ctx, sess, tenantID, m.Role().String()) },
		func() error { return s.enforceMFAPolicy(ctx, sess, uid, tenantID) },
		func() error { return s.enforcePersonalPolicy(ctx, sess, uid, tenantID) },
		func() error { return s.enforceOutsidePrivilegePolicy(ctx, sess, uid, tenantID) },
	} {
		if err := check(); err != nil {
			return entryRefusalFor(err)
		}
	}
	return nil
}

// entryRefusalFor maps a requirement failure to its refusal; anything that is
// not a known requirement is returned unchanged (a failure to decide).
func entryRefusalFor(err error) error {
	switch {
	case errors.Is(err, ErrSSORequired):
		return &EntryRefusal{Status: http.StatusForbidden, Code: apierror.CodeForbidden,
			Message: "This organization requires SSO sign-in. Please sign in through your identity provider.", cause: err}
	case errors.Is(err, ErrSSOMFAEvidenceRequired):
		return &EntryRefusal{Status: http.StatusForbidden, Code: apierror.CodeMFAEnrollmentRequired,
			Message: "This organization requires your identity provider to confirm a second factor. Sign in again through your identity provider with multi-factor authentication.", cause: err}
	case errors.Is(err, ErrMFAEnrollmentRequired):
		return &EntryRefusal{Status: http.StatusForbidden, Code: apierror.CodeMFAEnrollmentRequired,
			Message: "This organization requires two-factor authentication. Sign in again to complete it.", cause: err}
	case errors.Is(err, ErrPersonalAccountsBlocked):
		return &EntryRefusal{Status: http.StatusForbidden, Code: "PERSONAL_ACCOUNTS_BLOCKED",
			Message: "This organization does not accept personal email accounts.", cause: err}
	}
	return err
}
