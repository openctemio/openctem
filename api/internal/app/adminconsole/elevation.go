package adminconsole

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
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
	ErrElevationRole     = fmt.Errorf("%w: elevate as one of your platform roles (or ops_admin / super_admin), never above what you hold", shared.ErrValidation)
	ErrElevationDuration = fmt.Errorf("%w: elevate for 15 to 60 minutes", shared.ErrValidation)
	ErrAuditUnavailable  = errors.New("the administrators' audit log cannot be written")
	ErrElevationReason   = fmt.Errorf("%w: give a reason of 10 to 500 characters", shared.ErrValidation)
)

// Elevate makes the session act as one platform role (RFC-134) until
// now+duration and returns the end time. name is a role key, or the tier
// names super_admin / ops_admin (the owner and admin roles). The role's
// permissions must all be held by the administrator: never above their own.
func (s *Service) Elevate(ctx context.Context, a *admin.AdminUser, sess *admin.Session, name string, duration time.Duration, reason string, client ClientInfo) (time.Time, error) {
	if a == nil || sess == nil || !sess.MFAVerified || sess.AdminID != a.ID() {
		return time.Time{}, admin.ErrSessionNotFound
	}
	target, ok := platformauthz.ElevationTarget(name)
	held := a.PlatformRoles()
	if len(held) == 0 {
		held = []platformauthz.RoleKey{platformauthz.BaseRoleFor(platformauthz.Tier(a.MaxRole()))}
	}
	if !ok || !platformauthz.CanElevateTo(held, target) {
		return time.Time{}, ErrElevationRole
	}
	role := admin.AdminRole(target)
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
	// The audit row comes first and the elevation only follows a stored row:
	// with the audit log unavailable a session never becomes more powerful
	// without a record.
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(a, ActionElevated).
			Resource("admin_session", ptr(sess.ID), a.Email()).
			Context(client.IP, client.UserAgent).
			Request("", "", map[string]any{"role": string(role), "until": until.UTC().Format(time.RFC3339), "reason": reason}).
			High().
			Build()
		if err := s.audit.Create(ctx, entry); err != nil {
			s.log.Error("audit admin elevation; elevation refused", "error", err)
			return time.Time{}, ErrAuditUnavailable
		}
	}
	if err := s.console.SetSessionElevation(ctx, sess.ID, role, &until, reason); err != nil {
		return time.Time{}, err
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
