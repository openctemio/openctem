package scan

// Ownership of what an active scan touches (RFC-036 §6.3 active_allowed;
// architecture: docs/architecture/active-probe-gate.md). Every active-scan
// entry point asks the AttributionGate about the targets it names: scan
// create, update, clone and import, quick scan and POST /commands refuse
// the request as a whole; a scan run (manual, scheduled, retry, workflow)
// skips the target with a run warning; the dispatch gate (scan workflows,
// coverage, validation, retests, simulations, connector scans) refuses it.
//
// The reason the caller sees is generic. The specific state (rejected,
// needs_review, unattributed, ...) is logged server-side with the path.

import (
	"context"
	"fmt"
	"sort"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ReasonOwnershipNotConfirmed is the reason shown for any target the
// ownership gate refuses.
const ReasonOwnershipNotConfirmed = "it is not authorized for active scanning: its ownership is not confirmed, or no scope target, seed or verified domain covers it; check the asset's Ownership tab and Scoping > Targets"

// refuseUnownedTargets refuses a target list (scan create, update, clone,
// import, quick scan, a scan command) when any target is one the tenant has
// not authorized for active scanning. A failed check refuses (fail closed).
// takeoverOnly (IsTakeoverOnlyProbe) lets the gate admit dependency assets
// with an open dangling_cname (research/22 E13).
func (s *Service) refuseUnownedTargets(ctx context.Context, tenantID shared.ID, path string, targets []string, takeoverOnly bool) error {
	if s.attributionGate == nil || len(targets) == 0 {
		return nil
	}
	blocked, err := s.attributionGate.BlockedTargets(ctx, tenantID, targets)
	if err == nil && takeoverOnly {
		err = s.admitTakeoverTargets(ctx, tenantID, blocked, false)
	}
	if err != nil {
		s.logger.Warn("ownership check failed, request refused", "tenant_id", tenantID.String(), "path", path,
			"error", logger.SanitizeError(err))
		return shared.NewDomainError("OWNERSHIP_CHECK_FAILED",
			"The targets could not be checked for ownership; nothing was saved or dispatched. Try again.", shared.ErrValidation)
	}
	if len(blocked) == 0 {
		return nil
	}
	refusals := make([]scopedom.Refusal, 0, len(blocked))
	for t, state := range blocked {
		s.logRefusedTarget(ctx, tenantID, path, t, state)
		refusals = append(refusals, scopedom.NewRefusal(t, RefusalCodeForState(state), nil, 0))
	}
	s.auditRefusedTargets(ctx, tenantID, path, blocked)
	return refusalError(refusals)
}

// maxAuditedRefusals bounds how many refused targets one audit entry lists;
// the count is always exact.
const maxAuditedRefusals = 50

// auditRefusedTargets writes one audit entry for a refused request, so the
// tenant's administrators can see who tried to scan what (research/22 §4.0).
// Unlike the caller's error it keeps the refusing state per target; the
// audit log is readable only by members with audit access in this tenant.
func (s *Service) auditRefusedTargets(ctx context.Context, tenantID shared.ID, path string,
	blocked map[string]attribution.State,
) {
	targets := make([]string, 0, len(blocked))
	for t := range blocked {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	listed := make([]map[string]string, 0, min(len(targets), maxAuditedRefusals))
	for _, t := range targets[:min(len(targets), maxAuditedRefusals)] {
		listed = append(listed, map[string]string{
			"target":      logger.SanitizeValue(t),
			"attribution": string(blocked[t]),
		})
	}
	s.logAudit(ctx, AuditContext{TenantID: tenantID.String()},
		NewFailureEvent(audit.ActionScanTargetRefused, audit.ResourceTypeScan, "", nil).
			WithMessage(fmt.Sprintf("%d active-scan target(s) refused: ownership not confirmed", len(targets))).
			WithMetadata("path", path).
			WithMetadata("refused_count", len(targets)).
			WithMetadata("refused", listed))
}

// blockedCandidates asks the gate about a run's candidates that scope
// exclusions left in: group members by asset id, direct targets by name.
// It returns the blocked candidates keyed by candidate id.
func (s *Service) blockedCandidates(ctx context.Context, tenantID shared.ID, candidates []scope.ExclusionCandidate,
	names map[shared.ID]string, memberIDs, excluded map[shared.ID]bool, takeoverOnly bool,
) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	if s.attributionGate == nil || len(candidates) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(candidates))
	typed := make([]string, 0, len(candidates))
	typedID := map[string]shared.ID{}
	for _, c := range candidates {
		if excluded[c.ID] {
			continue
		}
		if memberIDs[c.ID] {
			ids = append(ids, c.ID.String())
			continue
		}
		typed = append(typed, names[c.ID])
		typedID[names[c.ID]] = c.ID
	}
	if len(ids) > 0 {
		blocked, err := s.attributionGate.ActiveCheckBlocked(ctx, tenantID, ids)
		if err == nil && takeoverOnly {
			err = s.admitTakeoverTargets(ctx, tenantID, blocked, true)
		}
		if err != nil {
			return nil, attributionCheckFailed(err)
		}
		for id, st := range blocked {
			out[id] = st
		}
	}
	if len(typed) > 0 {
		blocked, err := s.attributionGate.BlockedTargets(ctx, tenantID, typed)
		if err == nil && takeoverOnly {
			err = s.admitTakeoverTargets(ctx, tenantID, blocked, false)
		}
		if err != nil {
			return nil, attributionCheckFailed(err)
		}
		for t, st := range blocked {
			if id, ok := typedID[t]; ok {
				out[id.String()] = st
			}
		}
	}
	return out, nil
}

func attributionCheckFailed(err error) error {
	return fmt.Errorf("attribution check failed, scan not dispatched: %w", err)
}

// logRefusedTarget records why the gate refused a target. The target is
// sanitized; the state says which rule refused it.
func (s *Service) logRefusedTarget(_ context.Context, tenantID shared.ID, path, target string, state attribution.State) {
	if s.logger == nil {
		return
	}
	s.logger.Info("active scan target refused: ownership not confirmed",
		"tenant_id", tenantID.String(), "path", path,
		"target", logger.SanitizeValue(target), "attribution", string(state))
}
