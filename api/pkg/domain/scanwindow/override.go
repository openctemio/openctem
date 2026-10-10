package scanwindow

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Override bounds.
const (
	MinOverrideDuration = 15 * time.Minute
	MaxOverrideDuration = 24 * time.Hour
	minReasonLen        = 10
	maxReasonLen        = 500
)

var (
	// ErrOverrideNotFound is returned for an override that is not the
	// tenant's.
	ErrOverrideNotFound = shared.NewDomainError("SCAN_WINDOW_OVERRIDE_NOT_FOUND", "scan window override not found", shared.ErrNotFound)
	// ErrOverrideNeedsTOTP: overriding needs an authenticator app on the
	// caller's account.
	ErrOverrideNeedsTOTP = shared.NewDomainError("WINDOW_OVERRIDE_NEEDS_TOTP",
		"overriding scan windows needs a code from an authenticator app; set one up in your account security settings", shared.ErrForbidden)
	// ErrOverrideBadCode: the authenticator code was missing, wrong or
	// already used.
	ErrOverrideBadCode = shared.NewDomainError("WINDOW_OVERRIDE_INVALID_CODE",
		"the authenticator code is not valid", shared.ErrForbidden)
	// ErrOverrideProgram: a program's testing windows are third-party terms
	// and are never overridden.
	ErrOverrideProgram = shared.NewDomainError("WINDOW_OVERRIDE_NOT_ALLOWED",
		"a bug-bounty program's testing windows cannot be overridden", shared.ErrValidation)
)

// Override suspends one policy, or every policy of the tenant (PolicyID
// nil), from StartsAt to EndsAt. Program windows are never suspended.
type Override struct {
	ID        shared.ID
	TenantID  shared.ID
	PolicyID  *shared.ID
	Reason    string
	StartsAt  time.Time
	EndsAt    time.Time
	CreatedBy *shared.ID
	CreatedAt time.Time
	RevokedAt *time.Time
	RevokedBy *shared.ID
	// PolicyName is filled on reads (empty for every policy, or a deleted
	// one).
	PolicyName string
}

// NewOverride validates and returns an override starting now.
func NewOverride(tenantID shared.ID, policyID *shared.ID, reason string, duration time.Duration, createdBy *shared.ID, now time.Time) (*Override, error) {
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < minReasonLen || n > maxReasonLen {
		return nil, invalidOverride(fmt.Sprintf("reason must be %d to %d characters", minReasonLen, maxReasonLen))
	}
	if duration < MinOverrideDuration || duration > MaxOverrideDuration {
		return nil, invalidOverride("an override lasts 15 minutes to 24 hours")
	}
	return &Override{
		ID: shared.NewID(), TenantID: tenantID, PolicyID: policyID, Reason: reason,
		StartsAt: now, EndsAt: now.Add(duration), CreatedBy: createdBy, CreatedAt: now,
	}, nil
}

// ActiveAt reports whether the override suspends policies at t.
func (o *Override) ActiveAt(t time.Time) bool {
	return o.RevokedAt == nil && !t.Before(o.StartsAt) && t.Before(o.EndsAt)
}

// Suspends reports whether the override, active at t, suspends source s.
// Program sources and sources that are not overridable never are.
func (o *Override) Suspends(s Source, t time.Time) bool {
	if !s.Overridable || s.Origin != OriginPolicy || !o.ActiveAt(t) {
		return false
	}
	return o.PolicyID == nil || o.PolicyID.String() == s.ID
}

// WithoutSuspended drops from sources those an active override suspends at t.
func WithoutSuspended(sources []Source, overrides []*Override, t time.Time) []Source {
	if len(overrides) == 0 {
		return sources
	}
	out := sources[:0:0]
	for _, s := range sources {
		suspended := false
		for _, o := range overrides {
			if o.Suspends(s, t) {
				suspended = true
				break
			}
		}
		if !suspended {
			out = append(out, s)
		}
	}
	return out
}

func invalidOverride(msg string) error {
	return shared.NewDomainError("INVALID_SCAN_WINDOW_OVERRIDE", msg, shared.ErrValidation)
}
