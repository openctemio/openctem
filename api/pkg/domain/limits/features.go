package limits

import (
	"context"
	"regexp"
	"sort"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A feature is something that can be denied to one organization: a
// top-level, non-core module (by its module id) or a named feature below
// module level (NamedFeatures). Every feature is allowed unless denied.
// Core modules can never be denied.

// NamedFeatures are the deniable features below module level, each checked
// with entitlement.Service.Allowed at its own seam. Add a key here, check it
// at the seam, and list it in docs/architecture/limits.md (a test compares
// them). None exist yet: every module-level feature is a module id.
var NamedFeatures = []string{}

var featurePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,99}$`)

// Features lists every deniable feature, sorted: the non-core top-level
// modules of the registry and NamedFeatures.
func Features() []string {
	out := append([]string{}, NamedFeatures...)
	for _, d := range moduledom.Registry {
		if d.Parent == "" && !d.Core {
			out = append(out, d.ID)
		}
	}
	sort.Strings(out)
	return out
}

// IsFeature reports whether f can be denied.
func IsFeature(f string) bool {
	if !featurePattern.MatchString(f) {
		return false
	}
	for _, x := range NamedFeatures {
		if x == f {
			return true
		}
	}
	d, ok := moduledom.Lookup(f)
	return ok && d.Parent == "" && !d.Core
}

// FeatureDeny is one feature denied to one organization.
type FeatureDeny struct {
	TenantID  shared.ID
	Feature   string
	Origin    Origin
	Reason    string
	ExpiresAt *time.Time
	SetBy     *shared.ID
	SetAt     time.Time
}

// Active reports whether the deny applies at t.
func (d FeatureDeny) Active(t time.Time) bool { return d.ExpiresAt == nil || t.Before(*d.ExpiresAt) }

// GracePeriod is how long an organization keeps read access to a feature it
// lost (a deny, a lowered entitlement, a future license expiry): it can read
// and export its data, but writes are refused and the feature's jobs stop
// at once. Nothing is deleted.
const GracePeriod = 30 * 24 * time.Hour

// Source supplies limits and feature denies from outside the instance
// operator. The entitlement service merges every configured source with the
// operator's own rows; the operator's limit wins for a key, and a deny from
// any of them denies.
//
// Implementations: none (self-hosted default: nothing), the control plane
// of a hosted service (rows it wrote through the internal API). A signed
// offline license file is a planned third source (see the architecture
// doc); it must only ever produce limits and denies, never bypass this
// service.
type Source interface {
	Name() string
	Limits(ctx context.Context, tenantID shared.ID) ([]Limit, error)
	Denies(ctx context.Context, tenantID shared.ID) ([]FeatureDeny, error)
}

// NoneSource adds nothing: every organization is unlimited unless the
// operator set a limit.
type NoneSource struct{}

// Name implements Source.
func (NoneSource) Name() string { return "none" }

// Limits implements Source.
func (NoneSource) Limits(context.Context, shared.ID) ([]Limit, error) { return nil, nil }

// Denies implements Source.
func (NoneSource) Denies(context.Context, shared.ID) ([]FeatureDeny, error) { return nil, nil }

// Repository persists limits, denies, the self-service defaults and the
// read-only grace. Every per-organization query is scoped by tenant_id.
type Repository interface {
	// GetSelfServiceDefaults returns the stored defaults and their version,
	// or shared.ErrNotFound when nothing is stored.
	GetSelfServiceDefaults(ctx context.Context) (Limits, int, error)
	// SaveSelfServiceDefaults stores the defaults when the stored version is
	// expected (0: nothing stored yet); shared.ErrConflict otherwise.
	SaveSelfServiceDefaults(ctx context.Context, l Limits, expectedVersion int, by shared.ID, at time.Time) (int, error)

	ListLimits(ctx context.Context, tenantID shared.ID, origin Origin) ([]Limit, error)
	SetLimit(ctx context.Context, l Limit) error
	DeleteLimit(ctx context.Context, tenantID shared.ID, key Key, origin Origin) error

	ListDenies(ctx context.Context, tenantID shared.ID, origin Origin) ([]FeatureDeny, error)
	SetDeny(ctx context.Context, d FeatureDeny) error
	DeleteDeny(ctx context.Context, tenantID shared.ID, feature string, origin Origin) error

	// ReplaceOrigin replaces every limit and deny of one origin for the
	// organization in one transaction (the control plane's write).
	ReplaceOrigin(ctx context.Context, tenantID shared.ID, origin Origin, limits []Limit, denies []FeatureDeny) error

	// Usage counts what the organization uses for each countable key (one
	// query). Findings are counted only when withFindings is set.
	Usage(ctx context.Context, tenantID shared.ID, withFindings bool) (map[Key]int, error)
	// CountOwnedTenants counts the active organizations a person owns.
	CountOwnedTenants(ctx context.Context, userID shared.ID) (int, error)

	// ListGrace returns the organization's read-only grace per feature.
	ListGrace(ctx context.Context, tenantID shared.ID) (map[string]time.Time, error)
	// StartGrace starts read-only grace until `until` for features the
	// organization just lost (a grace already running is kept).
	StartGrace(ctx context.Context, tenantID shared.ID, features []string, until time.Time) error
	// EndGrace ends the grace of features the organization has again.
	EndGrace(ctx context.Context, tenantID shared.ID, features []string) error
}
