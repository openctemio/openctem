package scan

// Ownership proof for active probes (RFC-054 §8.1, owner decision S2): the
// operator's SCOPE_ACTIVE_PROOF decides when a target must sit at or under a
// verified domain of the tenant. Platform sensors send packets from the
// platform's own addresses, so in SaaS (platform_sensors) a job goes to them
// only when every target is proven; intrusive (T2) scans need proof always.
// No tenant setting changes this.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Active-proof modes (config.ScopeProof*).
const (
	ActiveProofOff             = "off"
	ActiveProofPlatformSensors = "platform_sensors"
	ActiveProofAll             = "all"
)

// ProofVerifier lists the targets that are not at or under a verified
// domain of the tenant (*easm.ActiveGate). Private and internal targets are
// never listed (scan zones gate them).
type ProofVerifier interface {
	UnverifiedTargets(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error)
}

// WithActiveProof sets the operator's active-proof mode ("" = off).
func WithActiveProof(mode string) ServiceOption {
	return func(s *Service) { s.activeProof = mode }
}

// codeProofRequired refuses a probe that needs a verified domain.
const codeProofRequired = "PROOF_REQUIRED"

// unverified asks the gate which targets lack proof. Without a verifier
// every target counts as unverified (fail closed).
func (s *Service) unverified(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	pv, ok := s.attributionGate.(ProofVerifier)
	if !ok || pv == nil {
		return targets, nil
	}
	return pv.UnverifiedTargets(ctx, tenantID, targets)
}

// platformNeedsProof reports whether the operator requires proof for jobs on
// platform sensors.
func (s *Service) platformNeedsProof() bool {
	return s.activeProof == ActiveProofPlatformSensors || s.activeProof == ActiveProofAll
}

// isIntrusiveTool reports whether every stage the scanner implements is
// intrusive (T2). An unknown tool is not judged here (the sensor grant's
// tier ceiling and the stage catalog decide elsewhere).
func isIntrusiveTool(tool string) bool {
	stages := stage.ForTool(tool)
	if len(stages) == 0 {
		return false
	}
	for _, st := range stages {
		if st.Tier < stage.TierIntrusive {
			return false
		}
	}
	return true
}

// refuseUnprovenIntrusive refuses an intrusive (T2) scan when any target is
// not at or under a verified domain (RFC-054 §8.1): intrusive probes always
// need proof, whatever the mode.
func (s *Service) refuseUnprovenIntrusive(ctx context.Context, tenantID shared.ID, scanner string, targets []string) error {
	if !isIntrusiveTool(scanner) || len(targets) == 0 {
		return nil
	}
	missing, err := s.unverified(ctx, tenantID, targets)
	if err != nil {
		return fmt.Errorf("proof check failed, nothing dispatched: %w", err)
	}
	return proofError(fmt.Sprintf("%s runs intrusive checks; intrusive probes need a verified domain", scanner), missing)
}

// proofError lists the unproven targets (bounded, sorted); nil for none.
func proofError(why string, missing []string) error {
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	listed := missing[:min(len(missing), maxListedRefusals)]
	msg := fmt.Sprintf("%s: verify the domain of %s in Scoping > Verified domains", why, strings.Join(listed, ", "))
	if len(missing) > len(listed) {
		msg += fmt.Sprintf(" and %d more", len(missing)-len(listed))
	}
	return shared.NewDomainError(codeProofRequired, msg, shared.ErrValidation)
}

// ProgramTargetChecker lists the targets only program entries cover
// (*easm.ActiveGate, RFC-065 §8).
type ProgramTargetChecker interface {
	ProgramOnlyTargets(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error)
}

// codePlatformRefused refuses a job for platform sensors.
const codePlatformRefused = "PLATFORM_SENSOR_REFUSED"

// programOnly lists the targets that only program entries cover. The
// production gate (*easm.ActiveGate) is a checker (asserted in cmd/server);
// with no gate at all nothing dispatches anyway (the dispatch gate fails
// closed), and a gate without the check has no program entries to judge.
func (s *Service) programOnly(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	pc, ok := s.attributionGate.(ProgramTargetChecker)
	if !ok || pc == nil {
		return nil, nil
	}
	return pc.ProgramOnlyTargets(ctx, tenantID, targets)
}

// programRefusal refuses platform sensors for program-only targets (bounded
// list); nil for none.
func programRefusal(targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	sort.Strings(targets)
	listed := targets[:min(len(targets), maxListedRefusals)]
	msg := fmt.Sprintf("platform sensors never probe bug-bounty program targets; run the scan on your own sensors (sensor_preference 'tenant' or 'auto'): %s",
		strings.Join(listed, ", "))
	if len(targets) > len(listed) {
		msg += fmt.Sprintf(" and %d more", len(targets)-len(listed))
	}
	return shared.NewDomainError(codePlatformRefused, msg, shared.ErrValidation)
}
