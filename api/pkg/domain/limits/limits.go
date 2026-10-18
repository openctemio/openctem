// Package limits holds per-organization limits and feature denies
// (docs/architecture/limits.md).
//
// The core knows no plans. An organization is unlimited and may use every
// feature unless someone set a limit or a deny for it: the instance operator
// (an administrator of this installation) or a Source plugged into the
// entitlement service (on a hosted service, the control plane). Every limit
// and every sellable feature check goes through internal/app/entitlement with
// a key from this package; tests/unit/entitlement_keys_test.go fails on an
// ad-hoc plan or tier check anywhere else.
//
// Over a limit, only ADDITIONS are refused. Lowering a limit never removes
// anything: existing members, assets and keys stay, and work already running
// keeps running. A denied feature keeps read access for a grace period.
package limits

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Key names a numeric limit.
type Key string

const (
	Seats                   Key = "seats"
	Assets                  Key = "assets"
	Sensors                 Key = "sensors"
	APIKeys                 Key = "api_keys"
	CITrusts                Key = "ci_trusts"
	InvitesPerDay           Key = "invites_per_day"
	PlatformScansPerDay     Key = "platform_scans_per_day"
	PlatformScansConcurrent Key = "platform_scans_concurrent"
	// Findings caps the findings an organization stores (new fingerprints;
	// a re-sighting of an existing finding counts nothing). Counting
	// findings is costly on a large table, so their usage is counted only
	// while a findings limit applies.
	Findings Key = "findings"
	// LifecycleSubStatuses caps an organization's finding sub-statuses
	// (live ones; RFC-110).
	LifecycleSubStatuses Key = "lifecycle_sub_statuses"
	// LifecycleSchemes caps its finding lifecycle schemes (live ones).
	LifecycleSchemes Key = "lifecycle_schemes"
	// StorageMB caps the MiB an organization's uploaded files (evidence,
	// attachments) may hold. Without it the platform's default storage
	// quota applies (Settings > Limits, or STORAGE_TENANT_QUOTA_MB).
	StorageMB Key = "storage_mb"
	// OrgsPerUser caps how many organizations one person may own when they
	// create one themselves (self-service). It is an instance setting (the
	// self-service defaults), never a per-organization limit.
	OrgsPerUser Key = "orgs_per_user"
	// DashboardRefreshFloorMinutes is the shortest refresh cadence, in
	// minutes, an organization's dashboards may use (docs/architecture/dashboards.md).
	// Unlike the other keys it is a floor, not a cap: nothing is counted
	// against it, and without it the installation's base floor (5 minutes)
	// applies. The hosting plan or the operator raises it.
	DashboardRefreshFloorMinutes Key = "dashboard_refresh_floor_minutes"
)

// Keys lists every limit key in display order.
var Keys = []Key{Seats, Assets, Sensors, APIKeys, CITrusts, InvitesPerDay, PlatformScansPerDay, PlatformScansConcurrent, Findings, LifecycleSubStatuses, LifecycleSchemes, StorageMB, OrgsPerUser, DashboardRefreshFloorMinutes}

// IsValid reports whether k is a known key.
func (k Key) IsValid() bool {
	for _, x := range Keys {
		if x == k {
			return true
		}
	}
	return false
}

// IsFloor reports whether k is a floor (a minimum the organization must
// respect) rather than a cap on what it adds: no usage is counted for it.
func (k Key) IsFloor() bool { return k == DashboardRefreshFloorMinutes }

// PerOrganization reports whether k can be set for one organization.
func (k Key) PerOrganization() bool { return k.IsValid() && k != OrgsPerUser }

// Unlimited is the value of a limit that does not apply.
const Unlimited = -1

// Limits maps keys to values. An absent key is Unlimited.
type Limits map[Key]int

// Get returns the value of k; an absent key is Unlimited.
func (l Limits) Get(k Key) int {
	if v, ok := l[k]; ok {
		return v
	}
	return Unlimited
}

// ErrInvalid is returned for an unknown key or feature, a value below
// Unlimited, a missing reason or a past expiry.
var ErrInvalid = fmt.Errorf("%w: invalid limit settings", shared.ErrValidation)

// Validate checks known keys and values >= Unlimited.
func (l Limits) Validate() error {
	for k, v := range l {
		if !k.IsValid() || v < Unlimited {
			return ErrInvalid
		}
	}
	return nil
}

// Encode serializes the limits for platform_settings.
func (l Limits) Encode() ([]byte, error) { return json.Marshal(l) }

// DecodeLimits parses stored limits.
func DecodeLimits(raw []byte) (Limits, error) {
	var l Limits
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("decode limits: %w", err)
	}
	if l == nil {
		l = Limits{}
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return l, nil
}

// SelfServiceDefaultsKey is the platform_settings key of the limits a new
// self-service organization starts with (and the per-person cap). Empty or
// absent: no limits, the default of every installation.
const SelfServiceDefaultsKey = "self_service_default_limits"

// SelfServiceReason is the reason stored on the limits a self-service
// organization starts with.
const SelfServiceReason = "instance default for self-service organizations"

// Rows returns one row per per-organization key of lims that is not
// Unlimited, for the organization, origin and reason given.
func Rows(tenantID shared.ID, origin Origin, reason string, lims Limits, at time.Time) []Limit {
	out := []Limit{}
	for _, k := range Keys {
		if v, ok := lims[k]; ok && k.PerOrganization() && v != Unlimited {
			out = append(out, Limit{TenantID: tenantID, Key: k, Value: v, Origin: origin, Reason: reason, SetAt: at})
		}
	}
	return out
}

// SelfServiceRows returns the operator rows a new self-service organization
// starts with: one per per-organization key of the defaults that is not
// Unlimited (none for empty defaults).
func SelfServiceRows(tenantID shared.ID, defaults Limits, at time.Time) []Limit {
	return Rows(tenantID, OriginOperator, SelfServiceReason, defaults, at)
}

// Origin says who set a limit or a deny.
type Origin string

const (
	// OriginOperator: an administrator of this installation.
	OriginOperator Origin = "operator"
	// OriginControlPlane: a hosted service's control plane, through the
	// internal API.
	OriginControlPlane Origin = "control_plane"
)

// IsValid reports whether o is a known origin.
func (o Origin) IsValid() bool { return o == OriginOperator || o == OriginControlPlane }

// Limit is one per-organization limit.
type Limit struct {
	TenantID  shared.ID
	Key       Key
	Value     int
	Origin    Origin
	Reason    string
	ExpiresAt *time.Time
	SetBy     *shared.ID // administrator id (operator rows)
	SetAt     time.Time
}

// Active reports whether the limit applies at t.
func (l Limit) Active(t time.Time) bool { return l.ExpiresAt == nil || t.Before(*l.ExpiresAt) }

// Effective is one limit as it applies to an organization, with its usage.
type Effective struct {
	Key   Key `json:"key"`
	Limit int `json:"limit"`
	// Origin is who set it; empty when no limit applies.
	Origin    Origin     `json:"origin,omitempty"`
	Used      int        `json:"used"`
	OverLimit bool       `json:"over_limit"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	// Uncounted: the usage was not counted (findings while no findings
	// limit applies), so Used is 0 and means nothing.
	Uncounted bool `json:"uncounted,omitempty"`
}

// AllowAddition is the one over-limit rule: adding delta is allowed while
// the result stays within the limit. Unlimited always allows. Nothing ever
// computes a removal from a limit.
func AllowAddition(limit, used, delta int) bool {
	return limit == Unlimited || delta <= 0 || used+delta <= limit
}

// ErrLimitReached is returned when an addition would exceed a limit.
type ErrLimitReached struct {
	Key   Key
	Limit int
	Used  int
	// Unavailable: the limit could not be read, so the addition was refused
	// (fail-closed).
	Unavailable bool
}

func (e *ErrLimitReached) Error() string {
	if e.Unavailable {
		return fmt.Sprintf("limit could not be checked: %s", e.Key)
	}
	return fmt.Sprintf("limit reached: %s (limit %d, used %d)", e.Key, e.Limit, e.Used)
}

// Unwrap lets errors.Is(err, shared.ErrForbidden) match.
func (e *ErrLimitReached) Unwrap() error { return shared.ErrForbidden }

// Checker refuses an addition of delta to key over the organization's limit
// (*ErrLimitReached; fail-closed). entitlement.Service implements it.
type Checker interface {
	Check(ctx context.Context, tenantID shared.ID, key Key, delta int) error
	// Headroom returns how many more of key may be added (Unlimited when no
	// limit applies, without counting usage), for a batch that admits part
	// of its additions. A read error is *ErrLimitReached (fail-closed).
	Headroom(ctx context.Context, tenantID shared.ID, key Key) (int, error)
	// RecordRefusals counts n additions refused after Headroom.
	RecordRefusals(key Key, n int)
}
