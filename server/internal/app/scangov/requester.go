package scangov

// Requester and time facts of the approval rules (RFC-073 §4.1): who asks
// for a scan or starts its run, through what (the caller the
// authentication middleware records), and when it runs.
//
// Threat model. The requester conditions read only the organization's own
// data for the authenticated caller (tenant from the principal): its roles,
// groups and whether it is one of the organization's service accounts. The
// origin comes from the authentication method, never from the request. A
// lookup that fails refuses the run (the gate fails closed); a caller the
// gate cannot place (no recorded origin, no user) is caught by every
// requester condition, and an unknown time by every hours condition. A
// trusted service account is exempt only when the directory says it is a
// service account of this organization.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// RequesterDirectory answers a member's roles, groups and kind in one
// organization (*postgres.ScanApprovalRepository). Someone who is not a
// member answers an empty profile.
type RequesterDirectory interface {
	RequesterProfile(ctx context.Context, tenantID shared.ID, userID string) (scangov.Requester, error)
}

// TimezoneSource reads the organization's settings for its timezone
// (*tenant.TenantService).
type TimezoneSource interface {
	GetTenantSettings(ctx context.Context, tenantID string) (*tenant.Settings, error)
}

// SetRequesters wires the requester directory and the organization's
// timezone. Without the directory a rule with requester conditions catches
// every scan (fail closed).
func (s *Service) SetRequesters(dir RequesterDirectory, tz TimezoneSource) {
	s.requesters, s.timezones = dir, tz
}

// originOf is how userID acts in ctx: the origin the authentication
// middleware recorded, else the system (the scheduler, an automation) for a
// known user; unknown otherwise.
func originOf(ctx context.Context, userID string) (scangov.Origin, bool) {
	if o, ok := scangov.OriginFrom(ctx); ok {
		return o, true
	}
	if userID != "" {
		return scangov.OriginSystem, true
	}
	return "", false
}

// withRequester fills the requester and time facts the rules read: userID
// acting through the origin of ctx, at, and the organization's timezone.
// Nothing is read when no enabled rule needs it.
func (s *Service) withRequester(ctx context.Context, tenantID shared.ID, rules []scangov.Rule, f scangov.Facts,
	userID string, at time.Time,
) (scangov.Facts, error) {
	if scangov.NeedsClock(rules) {
		f.At = at.UTC()
		if s.timezones != nil {
			st, err := s.timezones.GetTenantSettings(ctx, tenantID.String())
			if err != nil {
				return f, fmt.Errorf("read the organization timezone: %w", err)
			}
			if st != nil {
				f.Timezone = st.General.Timezone
			}
		}
	}
	if !scangov.NeedsRequester(rules) {
		return f, nil
	}
	origin, ok := originOf(ctx, userID)
	if !ok || s.requesters == nil {
		f.Requester = nil
		return f, nil
	}
	r := scangov.Requester{UserID: userID, Origin: origin}
	if userID != "" {
		p, err := s.requesters.RequesterProfile(ctx, tenantID, userID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return f, fmt.Errorf("read the requester: %w", err)
		}
		r.Roles, r.GroupIDs, r.ServiceAccount = p.Roles, p.GroupIDs, p.ServiceAccount
		// A service account's key is its only way in.
		if r.ServiceAccount && r.Origin == scangov.OriginAPIKey {
			r.Origin = scangov.OriginServiceAccount
		}
	}
	f.Requester = &r
	return f, nil
}

// plannedAt is when a scan's next run happens, for a request or a status:
// its next scheduled run when one is set in the future, else now.
func plannedAt(sc *scan.Scan, now time.Time) time.Time {
	if sc != nil && sc.NextRunAt != nil && sc.NextRunAt.After(now) && sc.ScheduleType != scan.ScheduleManual && sc.ScheduleType != "" {
		return *sc.NextRunAt
	}
	return now
}

// creatorOf is the scan's creator id ("" when unknown).
func creatorOf(sc *scan.Scan) string {
	if sc == nil || sc.CreatedBy == nil || sc.CreatedBy.IsZero() {
		return ""
	}
	return sc.CreatedBy.String()
}
