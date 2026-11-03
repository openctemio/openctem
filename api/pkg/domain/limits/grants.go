package limits

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Grant keys are the other half of the one entitlement key registry: things
// that are off unless granted (RFC-145 §5). A self-managed installation is
// granted them by its signed license (pkg/licensekey); a hosted service by
// its control plane. A grant only ever adds: no Community feature, limit or
// security control depends on one, and sign-in, SSO, MFA and audit are never
// grant keys (docs/development/editions.md).

// GrantKey names something a license can grant.
type GrantKey string

// GrantKind says how far a grant reaches.
type GrantKind string

const (
	// GrantKindInstance: one grant for the whole installation (every
	// organization gets it).
	GrantKindInstance GrantKind = "instance"
	// GrantKindTenant: granted per organization (a hosted control plane);
	// a license grants it to every organization of the installation.
	GrantKindTenant GrantKind = "tenant"
)

// Registered grant keys.
const (
	// GrantAssetCollector: the first-party asset collector component.
	GrantAssetCollector GrantKey = "asset_collector"
	// GrantAIWorker: the first-party AI worker component.
	GrantAIWorker GrantKey = "ai_worker"
)

// GrantInfo describes one grant key.
type GrantInfo struct {
	Kind GrantKind
	// Description says what the grant turns on.
	Description string
	// OnExpiry says what stops once the grant ends; data is always kept.
	OnExpiry string
}

// Grants is the registry of grant keys. A license naming a key that is not
// here is refused (pkg/licensekey), and tests/unit/license_guard_test.go
// keeps every key described and listed in docs/architecture/limits.md.
var Grants = map[GrantKey]GrantInfo{
	GrantAssetCollector: {
		Kind:        GrantKindInstance,
		Description: "pairing and ingest of the first-party asset collector component",
		OnExpiry:    "the collector stops sending new data; collected assets stay",
	},
	GrantAIWorker: {
		Kind:        GrantKindInstance,
		Description: "dispatch of AI agent runs to the first-party AI worker component",
		OnExpiry:    "no new runs are dispatched to it; earlier results stay",
	},
}

// GrantKeys lists the registered grant keys in order.
func GrantKeys() []GrantKey {
	out := make([]GrantKey, 0, len(Grants))
	for k := range Grants {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsGrantKey reports whether k is a registered grant key.
func IsGrantKey(k GrantKey) bool {
	_, ok := Grants[k]
	return ok
}

// GrantStatus is the state of one grant key for an organization.
type GrantStatus string

// Grant states, from least to most granting.
const (
	// GrantNone: never granted (Community).
	GrantNone GrantStatus = "none"
	// GrantExpired: was granted; its license ended or was removed. No new
	// data; settings stay read-only until ReadOnlyUntil; data is kept.
	GrantExpired GrantStatus = "expired"
	// GrantGrace: past the license's expiry, inside its grace window.
	GrantGrace GrantStatus = "grace"
	// GrantExpiring: in the last 30 days of the license.
	GrantExpiring GrantStatus = "expiring"
	// GrantActive: granted.
	GrantActive GrantStatus = "active"
)

// GrantReadOnlyPeriod is how long the settings of an expired grant stay
// readable (read-only) before they are hidden; the data itself stays.
const GrantReadOnlyPeriod = GracePeriod

var grantRank = map[GrantStatus]int{GrantNone: 0, GrantExpired: 1, GrantGrace: 2, GrantExpiring: 3, GrantActive: 4}

// Granting reports whether the grant is on (active, expiring or grace).
func (s GrantStatus) Granting() bool { return grantRank[s] >= grantRank[GrantGrace] }

// Grant is one grant key's state from one source.
type Grant struct {
	Key    GrantKey
	Status GrantStatus
	// ExpiresAt and GraceEndsAt: the license's dates (zero for none).
	ExpiresAt   time.Time
	GraceEndsAt time.Time
	// ReadOnlyUntil: for an expired grant, until when its settings stay
	// readable.
	ReadOnlyUntil time.Time
}

// Better reports whether g grants more than o (the higher state wins when
// several sources answer for one key).
func (g Grant) Better(o Grant) bool { return grantRank[g.Status] > grantRank[o.Status] }

// GrantSource yields the grant states of an organization: the installation
// license (the same for every organization) or a hosted control plane.
// Missing keys are GrantNone.
type GrantSource interface {
	Grants(ctx context.Context, tenantID shared.ID) (map[GrantKey]Grant, error)
}

// Grant refusal codes.
const (
	CodeAddonNotLicensed    = "ADDON_NOT_LICENSED"
	CodeAddonLicenseExpired = "ADDON_LICENSE_EXPIRED"
)

// ErrGrantRequired refuses an action that needs a grant key that is not on.
// Unavailable: the grant could not be read, so the action was refused
// (fail-closed; only granted extras ever depend on it).
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
