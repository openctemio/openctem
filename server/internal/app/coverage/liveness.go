package coverage

// What a settled run says about whether each target is still there, handed
// to the asset liveness recorder (docs/architecture/asset-liveness.md).
// Only per-target verdicts count: a target no task carried, a stalled run,
// a platform-side failure (the check did not run) and a task whose every
// target failed the same target-side way (treated as the sensor's failure)
// say nothing about the target.

import (
	"context"

	"github.com/openctemio/contract/outcome"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/liveness"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// LivenessRecorder records liveness observations (*liveness.Service).
type LivenessRecorder interface {
	Record(ctx context.Context, tenantID shared.ID, obs []liveness.AssetObservation)
}

// WithLiveness hands every settled run's per-target verdicts to r.
func (s *Service) WithLiveness(r LivenessRecorder) { s.liveness = r }

// reachCapabilities are the active checks whose answer (or its absence)
// says the target is there: a probe, a port scan, template checks, a crawl
// or a web scan. Passive lookups and enumerations say nothing.
var reachCapabilities = map[string]bool{
	"probe.http": true, "scan.ports": true, "vuln.templates": true, "crawl.web": true, "dast.web": true,
}

// livenessKind maps one verdict of a capability to an observation kind.
func livenessKind(capability string, v covdom.Verdict) (liveness.Kind, bool) {
	switch {
	case v.Kind == covdom.VerdictUnresolved && v.Outcome == covdom.ReasonResolverFailed:
		return liveness.KindResolverFailed, true
	case v.Kind == covdom.VerdictUnresolved && v.Outcome == covdom.OutcomeNoAnswer:
		// Only an explicit "no such name" from the sensor's resolver.
		return liveness.KindNXDomain, true
	case v.Kind == covdom.VerdictUnresolved:
		// The sensor did not say why the name did not resolve (an older
		// sensor): no evidence either way. It neither advances nor resets
		// the gone streak.
		return "", false
	case capability == covdom.CapabilityResolveDNS && v.Kind == covdom.VerdictCovered:
		return liveness.KindResolved, true
	case !reachCapabilities[capability]:
		return "", false
	case v.Kind == covdom.VerdictCovered:
		return liveness.KindAnswered, true
	case v.Kind == covdom.VerdictFailed && (v.Outcome == string(outcome.EdgeBlocked) || v.Outcome == string(outcome.EdgeChallenged)):
		// An edge protection answered for the name: something is there.
		return liveness.KindAnswered, true
	case v.Kind == covdom.VerdictFailed && covdom.IsTargetSide(v.Outcome):
		return liveness.KindNoAnswer, true
	}
	return "", false
}

// livenessObservations reads the verdicts of a run's queued pairs.
func livenessObservations(capability string, queued []covdom.DueTarget, verdicts map[string]covdom.Verdict) []liveness.AssetObservation {
	out := make([]liveness.AssetObservation, 0, len(queued))
	for _, d := range queued {
		v, ok := verdicts[covdom.TargetKey(d.Target())]
		if !ok {
			continue
		}
		kind, ok := livenessKind(capability, v)
		if !ok {
			continue
		}
		result := v.Outcome
		if result == "" {
			result = v.Kind
		}
		out = append(out, liveness.AssetObservation{AssetID: d.AssetID, Observation: liveness.Observation{
			Kind: kind, Observer: v.Observer, Capability: capability, Outcome: result,
		}})
	}
	return out
}
