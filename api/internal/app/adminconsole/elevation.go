package adminconsole

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Time-boxed elevation (RFC-022 revision 20): an administrator acts as
// read-only until they elevate their console session to a role no higher than
// their own, for 15 to 60 minutes, with a reason (and the route's step-up).
// Every elevation is audited at high severity.

// Elevation audit actions.
const (
	ActionElevated      = "console.elevated"
	ActionElevationEnds = "console.elevation_ended"
)

// Elevation errors.
var (
	ErrElevationRole     = fmt.Errorf("%w: the role must be ops_admin or super_admin and not above your own", shared.ErrValidation)
	ErrElevationDuration = fmt.Errorf("%w: elevate for 15 to 60 minutes", shared.ErrValidation)
	ErrElevationReason   = fmt.Errorf("%w: give a reason of 10 to 500 characters", shared.ErrValidation)
)

// Elevate sets the session's acting role until now+duration and returns the
// end time.
func (s *Service) Elevate(ctx context.Context, a *admin.AdminUser, sess *admin.Session, role admin.AdminRole, duration time.Duration, reason string, client ClientInfo) (time.Time, error) {
	if a == nil || sess == nil || !sess.MFAVerified || sess.AdminID != a.ID() {
		return time.Time{}, admin.ErrSessionNotFound
	}
	if role == admin.AdminRoleReadonly || !admin.RoleAtMost(role, a.MaxRole()) {
		return time.Time{}, ErrElevationRole
	}
	if duration < admin.ElevationMin || duration > admin.ElevationMax {
		return time.Time{}, ErrElevationDuration
	}
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < 10 || n > 500 {
		return time.Time{}, ErrElevationReason
	}
	until := s.now().Add(duration)
	// Never past the session itself.
	if until.After(sess.ExpiresAt) {
		until = sess.ExpiresAt
	}
	if err := s.console.SetSessionElevation(ctx, sess.ID, role, &until, reason); err != nil {
		return time.Time{}, err
	}
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(a, ActionElevated).
			Resource("admin_session", ptr(sess.ID), a.Email()).
			Context(client.IP, client.UserAgent).
			Request("", "", map[string]any{"role": string(role), "until": until.UTC().Format(time.RFC3339), "reason": reason}).
			High().
			Build()
		s.writeAudit(ctx, ActionElevated, entry)
	}
	return until, nil
}

// EndElevation returns the session to read-only at once.
func (s *Service) EndElevation(ctx context.Context, a *admin.AdminUser, sess *admin.Session, client ClientInfo) error {
	if a == nil || sess == nil || sess.AdminID != a.ID() {
		return admin.ErrSessionNotFound
	}
	if err := s.console.SetSessionElevation(ctx, sess.ID, "", nil, ""); err != nil {
		return err
	}
	s.recordNote(ctx, a, ActionElevationEnds, client, "")
	return nil
}
