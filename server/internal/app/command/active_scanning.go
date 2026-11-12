package command

// Passive only: an organization whose entitlements deny the named feature
// limits.FeatureActiveScanning never has a probe above tier 0 handed to any
// sensor, the platform's shared ones or its own (docs/architecture/limits.md,
// "Passive only"). Two checks, both on the claim paths every command
// passes through (the poll, the claim by id, the claim-N poll and the shared
// claim):
//   - the claim-time re-check (recheck) fails the job with
//     FailureActiveScanningNotEntitled; the tier is computed here from the
//     stored dispatch record and the command's type and tool, never from a
//     request;
//   - the sensor-side gate (dispatchGate) withholds a job whose tier on this
//     sensor (its tool contract only raises it) is above passive.
// A lookup error refuses tier above 0 and leaves tier 0 alone.

import (
	"context"
	"fmt"

	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/limits"
	scanrundom "github.com/openctemio/openctem/server/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// FeatureAllower reads whether an organization may use a named feature
// (*entitlement.Service). A read error is returned with false.
type FeatureAllower interface {
	Allowed(ctx context.Context, tenantID shared.ID, feature string) (bool, error)
}

// WithActiveScanningGate wires the entitlement read of active scanning.
// WithSharedLimits wires it too when its source is a FeatureAllower, so the
// one entitlement service the server already passes there also gates active
// scanning. Without it nothing is denied (an instance without entitlements
// allows every feature).
func WithActiveScanningGate(f FeatureAllower) Option {
	return func(s *Service) { s.activeScan = f }
}

// RefusalLayerEntitlement names the organization's entitlements in a refusal.
const RefusalLayerEntitlement = "entitlement"

// RuleActiveScanning is the refusal rule of a probe above passive for an
// organization without active scanning.
const RuleActiveScanning = "active_scanning"

// FailureActiveScanningNotEntitled is the failure code of such a job.
const FailureActiveScanningNotEntitled = scanrundom.FailureActiveScanningNotEntitled

// activeScanningMessage is the error recorded on such a job.
const activeScanningMessage = FailureActiveScanningNotEntitled +
	": active scanning is not available for this organization, so this job is never sent to a sensor"

// activeScanState is one organization's active scanning entitlement as read
// now: Denied, or Unknown when the read failed (treated as denied for tier
// above 0).
type activeScanState struct {
	denied  bool
	unknown bool
}

// blocks reports whether a job of tier cannot go out.
func (a activeScanState) blocks(tier int) bool {
	return tier > 0 && (a.denied || a.unknown)
}

// activeScanning reads tenantID's entitlement. An unwired gate allows.
func (s *Service) activeScanning(ctx context.Context, tenantID shared.ID) activeScanState {
	if s.activeScan == nil {
		return activeScanState{}
	}
	ok, err := s.activeScan.Allowed(ctx, tenantID, limits.FeatureActiveScanning)
	if err != nil {
		s.logger.Warn("cannot read the active scanning entitlement; refusing probes above passive",
			"tenant_id", tenantID.String(), "error", err)
		return activeScanState{unknown: true}
	}
	return activeScanState{denied: !ok}
}

// probeTier is the tier of c computed on the server: the tier of its
// stored dispatch record (the strict record of its type without one) or the
// tier its type and tool give it, whichever is higher. contract is the
// claiming sensor's contract for the tool (nil: the platform's catalog).
func probeTier(c *commanddom.Command, contract *sensordom.ToolContract) int {
	tier := 0
	if g, ok := recheckGateOf(c); ok {
		tier = g.Tier
	}
	job := sensordom.JobOf(string(c.Type), c.Payload)
	return max(tier, sensordom.CommandTierFor(string(c.Type), job, contract))
}

// activeScanningRecheck is the re-check's decision for c given the state
// read for its organization: recheckKeep, or the outcome of failing it
// (a lookup error keeps it queued).
func (s *Service) activeScanningRecheck(ctx context.Context, c *commanddom.Command, st activeScanState) recheckOutcome {
	if !st.blocks(probeTier(c, nil)) {
		return recheckKeep
	}
	if st.unknown {
		return recheckWithheld
	}
	s.logger.Info("probe refused: the organization is passive only",
		"tenant_id", c.TenantID.String(), "command_id", c.ID.String(), "type", string(c.Type))
	return s.failAtClaim(ctx, c, activeScanningMessage, FailureActiveScanningNotEntitled)
}

// activeScanningRefusal is the gate's refusal of c on this sensor, or nil.
func (g *dispatchGate) activeScanningRefusal(c *commanddom.Command) *sensordom.DispatchRefusal {
	if g == nil || (!g.activeDenied && !g.activeUnknown) {
		return nil
	}
	job := sensordom.JobOf(string(c.Type), c.Payload)
	var contract *sensordom.ToolContract
	if g.manifest != nil {
		contract = g.manifest.ToolContract(job.Tool)
	}
	t := probeTier(c, contract)
	if t == 0 {
		return nil
	}
	return &sensordom.DispatchRefusal{Layer: RefusalLayerEntitlement, Rule: RuleActiveScanning,
		Detail: fmt.Sprintf("tier T%d: active scanning is not available for this organization", t)}
}
