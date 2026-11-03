package limits

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Grants: things that are off unless granted, the other half of the
// entitlement answer next to limits and denies
// (docs/development/editions.md, RFC-145). The open core defines only the
// shape of the answer and asks it through entitlement.Service; it holds no
// grant keys, no license code and no license storage. A build that adds an
// extension registers a GrantProvider (internal/extension); the Community
// build has none, so every grant is GrantNone and nothing changes.
//
// A grant only ever adds: no Community feature, limit or security control
// depends on one, and sign-in, SSO, MFA and audit are never grants.

// GrantKey names something that is off unless granted. The keys are defined
// by the extension that checks them, never by Community code.
type GrantKey string

// GrantStatus is the state of one grant key for an organization.
type GrantStatus string

// Grant states, from least to most granting.
const (
	// GrantNone: never granted (always, in the Community build).
	GrantNone GrantStatus = "none"
	// GrantExpired: was granted and has ended. No new data; settings stay
	// read-only until ReadOnlyUntil; data is kept.
	GrantExpired GrantStatus = "expired"
	// GrantGrace: past its end, inside the grace window.
	GrantGrace GrantStatus = "grace"
	// GrantExpiring: in its last 30 days.
	GrantExpiring GrantStatus = "expiring"
	// GrantActive: granted.
	GrantActive GrantStatus = "active"
)

// GrantReadOnlyPeriod is how long the settings of an expired grant stay
// readable (read-only) before they are hidden; the data itself stays.
const GrantReadOnlyPeriod = GracePeriod

var grantRank = map[GrantStatus]int{GrantNone: 0, GrantExpired: 1, GrantGrace: 2, GrantExpiring: 3, GrantActive: 4}

// Granting reports whether the grant is on (active, expiring or grace). An
// unknown status is not granting.
func (s GrantStatus) Granting() bool { return grantRank[s] >= grantRank[GrantGrace] }

// Grant is the state of one grant key.
type Grant struct {
	Key    GrantKey
	Status GrantStatus
	// ExpiresAt and GraceEndsAt: when the grant ends (zero for none).
	ExpiresAt   time.Time
	GraceEndsAt time.Time
	// ReadOnlyUntil: for an expired grant, until when its settings stay
	// readable.
	ReadOnlyUntil time.Time
}

// Better reports whether g grants more than o.
func (g Grant) Better(o Grant) bool { return grantRank[g.Status] > grantRank[o.Status] }

// NoticeLevel is how prominent an installation notice is.
type NoticeLevel string

// Notice levels.
const (
	NoticeInfo    NoticeLevel = "info"
	NoticeWarning NoticeLevel = "warning"
	NoticeError   NoticeLevel = "error"
)

// Notice is an installation-wide notice for platform administrators (a
// console banner), named by a stable code the console translates. It carries
// no organization data.
type Notice struct {
	Code  string
	Level NoticeLevel
	// Until: the date the notice is about (for example an end date); zero
	// when none.
	Until time.Time
}

// GrantProvider answers for grant keys. The Community build has none
// (entitlement.Service then answers GrantNone for every key and no notices).
//
// Grant returns the state of key for the organization; an unknown key is
// GrantNone. An error means the answer could not be read: the caller treats
// the grant as off (fail-closed, for grants only). Notices returns the
// installation notices for platform administrators.
type GrantProvider interface {
	Grant(ctx context.Context, tenantID shared.ID, key GrantKey) (Grant, error)
	Notices(ctx context.Context) ([]Notice, error)
}

// Grant refusal codes.
const (
	CodeAddonNotLicensed    = "ADDON_NOT_LICENSED"
	CodeAddonLicenseExpired = "ADDON_LICENSE_EXPIRED"
)

// ErrGrantRequired refuses an action that needs a grant that is not on.
// Unavailable: the grant could not be read, so the action was refused.
type ErrGrantRequired struct {
	Key         GrantKey
	Expired     bool
	Unavailable bool
}

func (e *ErrGrantRequired) Error() string {
	return fmt.Sprintf("%s: %s", e.Code(), e.Key)
}

// Code is the stable API error code.
func (e *ErrGrantRequired) Code() string {
	if e.Expired {
		return CodeAddonLicenseExpired
	}
	return CodeAddonNotLicensed
}

// Unwrap makes the refusal a shared.ErrForbidden.
func (e *ErrGrantRequired) Unwrap() error { return shared.ErrForbidden }
