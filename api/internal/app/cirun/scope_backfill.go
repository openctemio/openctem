package cirun

// The dry run for CI trusts saved before trusts managed scope
// (docs/rfcs/RFC-054-scope-model.md, "Repository entries and CI trusts").
// Such a trust keeps manage_scope off until an administrator who may change
// scope turns it on (the trust card offers it): that change is audited and
// creates the entries as that administrator, under the organization's scope
// approval rules. Nothing adds them automatically. PlanScope tells the
// operator, tenant by tenant, what turning it on would do, and what the
// trusts that already manage scope would change; it writes nothing.

import (
	"context"
	"fmt"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// scopePlanner is the dry-run part of the scope service.
type scopePlanner interface {
	PlanCITrust(ctx context.Context, tenantID shared.ID, in scopeapp.CITrustScope) ([]scopedom.CITrustSyncOutcome, error)
}

// trustTenantLister lists the tenants that have trust configurations
// (*postgres.CIRunRepository).
type trustTenantLister interface {
	TrustConfigTenants(ctx context.Context) ([]shared.ID, error)
}

// ScopePlanTenant is one tenant's dry run. Managed counts, per action, what
// the trusts that manage scope would change now; Adoptable counts, per
// action, what turning manage_scope on would do for the enabled trusts that
// do not (created entries then follow the approval rules of whoever turns it
// on). Refused lists the patterns the platform would refuse, with why.
type ScopePlanTenant struct {
	TenantID       shared.ID      `json:"tenant_id"`
	Trusts         int            `json:"trusts"`
	ManagedTrusts  int            `json:"managed_trusts"`
	AdoptableTrust int            `json:"adoptable_trusts"`
	Managed        map[string]int `json:"managed"`
	Adoptable      map[string]int `json:"adoptable"`
	Refused        []string       `json:"refused,omitempty"`
}

// PlanScope runs the dry run for these tenants (every tenant with a trust
// when empty).
func (s *Service) PlanScope(ctx context.Context, tenants []shared.ID) ([]ScopePlanTenant, error) {
	p, ok := s.scope.(scopePlanner)
	if !ok {
		return nil, fmt.Errorf("the scope service cannot plan CI trust scope")
	}
	if len(tenants) == 0 {
		l, ok := s.repo.(trustTenantLister)
		if !ok {
			return nil, fmt.Errorf("the CI repository cannot list tenants")
		}
		var err error
		if tenants, err = l.TrustConfigTenants(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]ScopePlanTenant, 0, len(tenants))
	for _, tenantID := range tenants {
		configs, err := s.repo.ListTrustConfigs(ctx, tenantID)
		if err != nil {
			return out, fmt.Errorf("tenant %s: list trust configurations: %w", tenantID, err)
		}
		rep := ScopePlanTenant{TenantID: tenantID, Managed: map[string]int{}, Adoptable: map[string]int{}}
		for i := range configs {
			c := configs[i]
			if !c.TenantID.Equals(tenantID) {
				continue
			}
			rep.Trusts++
			counts := rep.Managed
			if c.ManageScope {
				rep.ManagedTrusts++
			} else {
				c.ManageScope = true // what turning it on would do
				if len(cirun.ScopePatterns(&c)) == 0 {
					continue // disabled, or a provider that names no code host
				}
				rep.AdoptableTrust++
				counts = rep.Adoptable
			}
			outcomes, err := p.PlanCITrust(ctx, tenantID, scopeapp.CITrustScope{TrustID: c.ID, TrustName: c.Name,
				Patterns: cirun.ScopePatterns(&c), MayCreate: true})
			if err != nil {
				return out, fmt.Errorf("tenant %s: trust %s: %w", tenantID, c.ID, err)
			}
			for _, o := range outcomes {
				counts[o.Action]++
				if o.Action == scopedom.CITrustRefused {
					rep.Refused = append(rep.Refused, fmt.Sprintf("%s: %s", o.Pattern, refusalText(o.Err)))
				}
			}
		}
		out = append(out, rep)
	}
	return out, nil
}
