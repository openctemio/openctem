// Package plan holds plans (Free, Pro, Enterprise), their limits and the
// per-organization overrides a platform administrator grants
// (docs/architecture/plans-and-limits.md).
//
// A limit caps what an organization may ADD. Lowering one never removes
// anything: existing members, assets and keys stay, and only new additions
// are refused until usage is under the limit again.
package plan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Plan is an organization's plan.
type Plan string

const (
	Free       Plan = "free"
	Pro        Plan = "pro"
	Enterprise Plan = "enterprise"
)

// All lists the plans in display order.
var All = []Plan{Free, Pro, Enterprise}

// IsValid reports whether p is a known plan.
func (p Plan) IsValid() bool { return p == Free || p == Pro || p == Enterprise }

// Key names a limit.
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
	// FreeTeamsPerUser caps how many Free organizations one person may own
	// (a property of the Free plan, checked when an organization is created).
	FreeTeamsPerUser Key = "free_teams_per_user"
)

// Keys lists every limit in display order.
var Keys = []Key{Seats, Assets, Sensors, APIKeys, CITrusts, InvitesPerDay, PlatformScansPerDay, PlatformScansConcurrent, FreeTeamsPerUser}

// IsValid reports whether k is a known limit.
func (k Key) IsValid() bool {
	for _, x := range Keys {
		if x == k {
			return true
		}
	}
	return false
}

// Unlimited is the value of a limit that does not apply.
const Unlimited = -1

// Limits maps each limit to its value (Unlimited for none).
type Limits map[Key]int

// Get returns the value of k; an absent key is Unlimited.
func (l Limits) Get(k Key) int {
	if v, ok := l[k]; ok {
		return v
	}
	return Unlimited
}

// Defaults are the limits of each plan.
type Defaults map[Plan]Limits

// BuiltinDefaults are the plan limits before an administrator edits them
// (owner decision 2026-10-08): Free is capped, Pro and Enterprise are not.
func BuiltinDefaults() Defaults {
	return Defaults{
		Free: {
			Seats: 5, Assets: 500, Sensors: 2, APIKeys: 5, CITrusts: 2, InvitesPerDay: 20,
			PlatformScansPerDay: 10, PlatformScansConcurrent: 1, FreeTeamsPerUser: 1,
		},
		Pro:        {},
		Enterprise: {},
	}
}

// ErrInvalid is returned for an unknown plan or key, or a limit below Unlimited.
var ErrInvalid = fmt.Errorf("%w: invalid plan settings", shared.ErrValidation)

// Validate checks the defaults: known plans and keys, values >= Unlimited.
func (d Defaults) Validate() error {
	for p, l := range d {
		if !p.IsValid() {
			return ErrInvalid
		}
		for k, v := range l {
			if !k.IsValid() || v < Unlimited {
				return ErrInvalid
			}
		}
	}
	return nil
}

// For returns the limits of a plan; an unknown plan gets none (Unlimited).
func (d Defaults) For(p Plan) Limits {
	if l, ok := d[p]; ok && l != nil {
		return l
	}
	return Limits{}
}

// Encode serializes the defaults for platform_settings.
func (d Defaults) Encode() ([]byte, error) { return json.Marshal(d) }

// DecodeDefaults parses stored defaults.
func DecodeDefaults(raw []byte) (Defaults, error) {
	var d Defaults
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("decode plan defaults: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// SettingKey is the platform_settings key of the plan defaults.
const SettingKey = "plan_limits"

// Override is one per-organization limit a platform administrator set.
type Override struct {
	TenantID  shared.ID
	Key       Key
	Value     int
	Reason    string
	ExpiresAt *time.Time
	SetBy     *shared.ID // administrator id
	SetAt     time.Time
}

// Active reports whether the override applies at t.
func (o Override) Active(t time.Time) bool { return o.ExpiresAt == nil || t.Before(*o.ExpiresAt) }

// Source says where an effective limit comes from.
type Source string

const (
	SourcePlan     Source = "plan"
	SourceOverride Source = "override"
)

// Effective is one limit as it applies to an organization.
type Effective struct {
	Key       Key        `json:"key"`
	Limit     int        `json:"limit"`
	Source    Source     `json:"source"`
	Used      int        `json:"used"`
	OverLimit bool       `json:"over_limit"`
	ExpiresAt *time.Time `json:"override_expires_at,omitempty"`
	Reason    string     `json:"override_reason,omitempty"`
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
		return fmt.Sprintf("plan limit could not be checked: %s", e.Key)
	}
	return fmt.Sprintf("plan limit reached: %s (limit %d, used %d)", e.Key, e.Limit, e.Used)
}

// Unwrap lets errors.Is(err, shared.ErrForbidden) match.
func (e *ErrLimitReached) Unwrap() error { return shared.ErrForbidden }

// Repository persists plans and overrides.
type Repository interface {
	// GetDefaults returns the stored defaults and their version, or
	// shared.ErrNotFound when nothing is stored.
	GetDefaults(ctx context.Context) (Defaults, int, error)
	// SaveDefaults stores the defaults when the stored version is expected
	// (0: nothing stored yet); shared.ErrConflict otherwise.
	SaveDefaults(ctx context.Context, d Defaults, expectedVersion int, by shared.ID, at time.Time) (int, error)
	// TenantPlan returns the organization's plan; ok is false when it has
	// none stored (an organization created before plans: Enterprise).
	TenantPlan(ctx context.Context, tenantID shared.ID) (Plan, bool, error)
	SetTenantPlan(ctx context.Context, tenantID shared.ID, p Plan, by *shared.ID, at time.Time) error
	ListOverrides(ctx context.Context, tenantID shared.ID) ([]Override, error)
	SetOverride(ctx context.Context, o Override) error
	DeleteOverride(ctx context.Context, tenantID shared.ID, key Key) error
	// Usage counts what the organization uses for each countable key.
	Usage(ctx context.Context, tenantID shared.ID) (map[Key]int, error)
	// CountOwnedFreeTenants counts the Free organizations a user owns.
	CountOwnedFreeTenants(ctx context.Context, userID shared.ID) (int, error)
}
