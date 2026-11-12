package command

// Scope limits in signed jobs (RFC-065 §16.8, docs/architecture/job-signing.md).
//
// A target that only port- or path-limited scope entries cover may go to a
// crawler, a template scanner or a top-ports scan only on a sensor that
// enforces the limits: it advertises jobsign.CapabilityScopeLimits and the
// job is signed, with the limits in the signed statement (the sensor's
// task forwarder refuses other ports and requests outside the path). For
// any other sensor the claim-time re-check keeps refusing such a job, and
// withholds it so an enforcing sensor can take it.

import (
	"context"
	"slices"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// ScopeLimitSource computes the scope limits of a job's targets
// (*easm.ActiveGate).
type ScopeLimitSource interface {
	StatementLimits(ctx context.Context, tenantID shared.ID, targets []string, tier scopedom.Tier) ([]jobsign.Limit, error)
}

// SetScopeLimits wires the limit source (the active gate is built after
// the command service). Without it, or without a job signer, no job
// carries limits and limited targets keep their tool restrictions.
func (s *Service) SetScopeLimits(src ScopeLimitSource) { s.limits = src }

// enforcesLimits reports whether jobs for sensorID may carry scope limits:
// they are signed, the limits can be computed, and the sensor (in the
// tenant) advertises the capability. Any lookup failure is false.
func (s *Service) enforcesLimits(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) bool {
	if s.jobs == nil || s.limits == nil || s.sensors == nil || sensorID == nil || sensorID.IsZero() {
		return false
	}
	sn, err := s.sensors.GetByTenantAndID(ctx, tenantID, *sensorID)
	if err != nil || sn == nil {
		return false
	}
	// What the sensor reports it does, not the administrator's list of work
	// it may take: an administrator cannot grant enforcement.
	return slices.Contains(sn.Reported.Capabilities, jobsign.CapabilityScopeLimits)
}

// statementLimits are the limits of c's targets at the tier its dispatch
// gate records (active for a command without one).
func (s *Service) statementLimits(ctx context.Context, c *commanddom.Command, targets []string) ([]jobsign.Limit, error) {
	tier := scopedom.TierActive
	if g, ok := recheckGateOf(c); ok && scopedom.Tier(g.Tier) > tier {
		tier = scopedom.Tier(g.Tier)
	}
	return s.limits.StatementLimits(ctx, c.TenantID, targets, tier)
}

// enforcesLimitsFor is enforcesLimits for a sensor id in text form.
func (s *Service) enforcesLimitsFor(ctx context.Context, tenantID shared.ID, sensorID string) bool {
	sid, err := shared.IDFromString(sensorID)
	if err != nil {
		return false
	}
	return s.enforcesLimits(ctx, tenantID, &sid)
}
