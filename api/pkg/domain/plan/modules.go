package plan

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Module entitlements (RFC-064): which modules an organization may use. The
// plan decides first (PlanModules); a platform administrator's grant adds a
// module beyond the plan (a trial, an add-on) and a deny removes one (a
// regional or contractual restriction). Core modules are always entitled.
// What the organization then switches on or off is its preference
// (tenant_modules), within this set.

// ModulesSettingKey is the platform_settings key of the plan to module map.
const ModulesSettingKey = "plan_modules"

// AllModules entitles a plan to every module.
const AllModules = "*"

// PlanModules maps each plan to the non-core modules it includes, or to
// AllModules.
type PlanModules map[Plan][]string

// BuiltinPlanModules entitles every plan to every module until an
// administrator narrows it: storing nothing changes nothing.
func BuiltinPlanModules() PlanModules {
	return PlanModules{Free: {AllModules}, Pro: {AllModules}, Enterprise: {AllModules}}
}

// Includes reports whether the plan includes the module (core modules are
// always included).
func (m PlanModules) Includes(p Plan, moduleID string) bool {
	if moduledom.IsCoreModule(moduleID) {
		return true
	}
	for _, id := range m[p] {
		if id == AllModules || id == moduleID {
			return true
		}
	}
	return false
}

// Validate refuses an unknown plan, an unknown or core module, or "*" mixed
// with module ids.
func (m PlanModules) Validate() error {
	for p, ids := range m {
		if !p.IsValid() {
			return ErrInvalid
		}
		for _, id := range ids {
			if id == AllModules {
				if len(ids) != 1 {
					return ErrInvalid
				}
				continue
			}
			d, ok := moduledom.Lookup(id)
			if !ok || d.Core {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Normalized returns a copy with every plan present and ids sorted and
// unique (a plan missing from the input includes nothing).
func (m PlanModules) Normalized() PlanModules {
	out := PlanModules{}
	for _, p := range All {
		seen := map[string]bool{}
		ids := []string{}
		for _, id := range m[p] {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		out[p] = ids
	}
	return out
}

// Encode serializes the map for platform_settings.
func (m PlanModules) Encode() ([]byte, error) { return json.Marshal(m) }

// DecodePlanModules reads a stored map and validates it.
func DecodePlanModules(raw []byte) (PlanModules, error) {
	var m PlanModules
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode plan modules: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// GrantKind is a per-organization entitlement change.
type GrantKind string

const (
	// GrantAdd entitles the organization to a module its plan does not include.
	GrantAdd GrantKind = "grant"
	// GrantDeny removes a module its plan includes.
	GrantDeny GrantKind = "deny"
)

// IsValid reports whether k is a known kind.
func (k GrantKind) IsValid() bool { return k == GrantAdd || k == GrantDeny }

// ModuleGrant is one per-organization entitlement change, set by a platform
// administrator with a reason and an optional expiry.
type ModuleGrant struct {
	TenantID  shared.ID
	ModuleID  string
	Kind      GrantKind
	Reason    string
	ExpiresAt *time.Time
	SetBy     *shared.ID
	SetAt     time.Time
}

// Active reports whether the grant applies at t.
func (g ModuleGrant) Active(t time.Time) bool { return g.ExpiresAt == nil || t.Before(*g.ExpiresAt) }

// ModuleRepository persists the plan to module map and the grants.
type ModuleRepository interface {
	// GetPlanModules returns the stored map and its version, or
	// shared.ErrNotFound when nothing is stored.
	GetPlanModules(ctx context.Context) (PlanModules, int, error)
	// SavePlanModules stores the map when the stored version is expected
	// (0: nothing stored yet); shared.ErrConflict otherwise.
	SavePlanModules(ctx context.Context, m PlanModules, expectedVersion int, by shared.ID, at time.Time) (int, error)
	ListModuleGrants(ctx context.Context, tenantID shared.ID) ([]ModuleGrant, error)
	SetModuleGrant(ctx context.Context, g ModuleGrant) error
	DeleteModuleGrant(ctx context.Context, tenantID shared.ID, moduleID string) error
}
