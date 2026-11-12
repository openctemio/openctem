package coverage

import (
	"context"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// ReadinessChecker answers, per capability, why it cannot run for the
// tenant now ("" = ready as far as it knows). Satisfied by scan.Service.
type ReadinessChecker interface {
	CoverageReadiness(ctx context.Context, tenantID shared.ID, capabilities []string) map[string]string
}

// UnclassifiedMode answers the tenant's unclassified-scans mode as the scope
// gate applies it ("off", "low_impact" or "full"; RFC-054 §16). Satisfied by
// (*easm.ActiveGate).UnclassifiedMode.
type UnclassifiedMode func(ctx context.Context, tenantID shared.ID) (string, error)

// EnableUnclassified wires the tenant's unclassified-scans mode. With a mode
// other than "off", a tenant without any scope entry is not paused as
// no_scope: everything found is in scope unless excluded, and the gate
// decides per target (low-impact checks of unclassified assets, tier and
// guardrail refusals unchanged). Without it, or when the mode cannot be
// read, no scope entry pauses every capability (fail closed).
func (s *Service) EnableUnclassified(m UnclassifiedMode) { s.unclassified = m }

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
// scope (no entry at all refuses every target, but only when unclassified
// assets are not scanned), then the sensors and tools.
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
		if !hasScope && !p.scansUnclassified(ctx) {
			for _, c := range p.capabilities {
				if p.reasons[c] != covdom.ReadyPolicyDisabled {
					p.reasons[c] = covdom.ReadyNoScope
				}
			}
		}
	}
	return p.reasons[capability], nil
}

// scansUnclassified reports whether the gate admits assets no scope entry
// covers (mode low_impact or full). Unwired or unreadable is false: the
// capability pauses as no_scope, as before.
func (p *readinessPass) scansUnclassified(ctx context.Context) bool {
	if p.s.unclassified == nil {
		return false
	}
	mode, err := p.s.unclassified(ctx, p.tenantID)
	if err != nil {
		p.s.logger.Warn("unclassified mode unreadable; coverage without a scope entry stays paused",
			"tenant_id", p.tenantID.String(), "error", logger.SanitizeError(err))
		return false
	}
	return mode == "low_impact" || mode == "full"
}
