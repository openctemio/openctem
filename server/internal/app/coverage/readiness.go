package coverage

import (
	"context"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReadinessChecker answers, per capability, why it cannot run for the
// tenant now ("" = ready as far as it knows). Satisfied by scan.Service.
type ReadinessChecker interface {
	CoverageReadiness(ctx context.Context, tenantID shared.ID, capabilities []string) map[string]string
}

// EnableReadiness wires the readiness check before runs. Without it only
// the tenant's scope entries are checked; the trigger's refusals still
// pause a capability.
func (s *Service) EnableReadiness(r ReadinessChecker) { s.readiness = r }

// readinessPass computes readiness at most once per tenant pass, and only
// when a capability has due or paused pairs.
type readinessPass struct {
	s            *Service
	tenantID     shared.ID
	capabilities []string
	pausedBy     map[string]string
	reasons      map[string]string
}

func (s *Service) newReadinessPass(tenantID shared.ID, capabilities []string) *readinessPass {
	return &readinessPass{s: s, tenantID: tenantID, capabilities: capabilities}
}

// paused returns the readiness reason the capability's paused pairs carry.
func (p *readinessPass) paused(ctx context.Context, capability string) (string, error) {
	if p.pausedBy == nil {
		m, err := p.s.planner.PausedForReadiness(ctx, p.tenantID)
		if err != nil {
			return "", err
		}
		p.pausedBy = m
	}
	return p.pausedBy[capability], nil
}

// reason returns the readiness reason of the capability ("" = ready). A
// policy that switches the capability off comes first, then the tenant's
// scope (no entry at all refuses every target), then the sensors and tools.
func (p *readinessPass) reason(ctx context.Context, capability string) (string, error) {
	if p.reasons == nil {
		p.reasons = map[string]string{}
		if p.s.readiness != nil {
			for c, r := range p.s.readiness.CoverageReadiness(ctx, p.tenantID, p.capabilities) {
				if covdom.IsReadinessReason(r) {
					p.reasons[c] = r
				}
			}
		}
		hasScope, err := p.s.planner.HasScopeEntries(ctx, p.tenantID)
		if err != nil {
			p.reasons = nil
			return "", err
		}
		if !hasScope {
			for _, c := range p.capabilities {
				if p.reasons[c] != covdom.ReadyPolicyDisabled {
					p.reasons[c] = covdom.ReadyNoScope
				}
			}
		}
	}
	return p.reasons[capability], nil
}
