package scan

// Start when scope is approved (RFC-054 §7; docs/architecture/active-probe-gate.md).
// A scan whose direct targets are refused only because the scope entries
// covering them wait for approval may be saved with start_when_scope_approved:
// it is stored, nothing is dispatched, and a wait row is kept. When an entry
// of the tenant comes into effect, every waiting scan whose targets now all
// pass the ownership gate is claimed (deleted, so it starts once) and
// triggered as the person who asked; the trigger runs every gate again (act
// scope, ownership, tier, proof, zones, freeze windows). A wait expires
// unused after ScopeWaitTTL. Nothing here authorizes a target: only the
// approval of the entry does, through the normal approval rules.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeWaitTTL is how long a scan waits for its scope before the wait lapses.
const ScopeWaitTTL = 30 * 24 * time.Hour

// maxScopeWaitsPerPass bounds the scans one entry approval starts.
const maxScopeWaitsPerPass = 100

// ScopeWait and ScopeWaitStore are the domain wait and its store
// (postgres.ScanScopeWaitRepository).
type (
	ScopeWait      = scan.ScopeWait
	ScopeWaitStore = scan.ScopeWaitRepository
)

// PendingScope says which targets only a pending scope entry covers
// (*scope.Service).
type PendingScope interface {
	PendingCovered(ctx context.Context, tenantID shared.ID, targets []string) (map[string]bool, error)
}

// WithScopeWaits enables start_when_scope_approved.
func WithScopeWaits(store ScopeWaitStore, pending PendingScope) ServiceOption {
	return func(s *Service) {
		s.scopeWaits = store
		s.pendingScope = pending
	}
}

// awaitingScopeTargets returns the targets the ownership gate refuses when
// some are refused and every refused one is covered by a pending scope
// entry, so the scan may be saved to start when the entries are approved;
// nil otherwise. Any other refusal (a rejected asset, no entry at all, the
// deny list) or a failed check answers nil and the normal refusal follows.
func (s *Service) awaitingScopeTargets(ctx context.Context, tenantID shared.ID, targets []string) map[string]bool {
	if s.scopeWaits == nil || s.pendingScope == nil || s.attributionGate == nil || len(targets) == 0 {
		return nil
	}
	blocked, err := s.attributionGate.BlockedTargets(ctx, tenantID, targets)
	if err != nil || len(blocked) == 0 {
		return nil
	}
	refused := make([]string, 0, len(blocked))
	for t, state := range blocked {
		if RefusalCodeForState(state) != scopedom.RefusalNoEntry || state == attribution.StatePlatformDenied {
			return nil
		}
		refused = append(refused, t)
	}
	pending, err := s.pendingScope.PendingCovered(ctx, tenantID, refused)
	if err != nil {
		s.logger.Warn("scope wait: pending check failed", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return nil
	}
	out := make(map[string]bool, len(refused))
	for _, t := range refused {
		if !pending[t] {
			return nil
		}
		out[t] = true
	}
	return out
}

// WaitsForScope reports whether the scan is saved to start when its scope is
// approved.
func (s *Service) WaitsForScope(ctx context.Context, tenantID, scanID shared.ID) bool {
	if s.scopeWaits == nil {
		return false
	}
	ok, err := s.scopeWaits.Exists(ctx, tenantID, scanID)
	if err != nil {
		s.logger.Warn("scope wait: lookup failed", "scan_id", scanID.String(), "error", logger.SanitizeError(err))
		return false
	}
	return ok
}

// StartScansAwaitingScope starts the tenant's waiting scans whose targets now
// all pass the ownership gate (called after a scope entry came into effect).
// Each is claimed first, so concurrent passes start it once; a scan still
// refused keeps waiting. Errors are logged: the approval itself succeeded.
func (s *Service) StartScansAwaitingScope(ctx context.Context, tenantID shared.ID) {
	if s.scopeWaits == nil || s.attributionGate == nil {
		return
	}
	waits, err := s.scopeWaits.ListByTenant(ctx, tenantID, maxScopeWaitsPerPass)
	if err != nil {
		s.logger.Warn("scope wait: list failed", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return
	}
	for _, w := range waits {
		if err := s.startAwaitingScan(ctx, w); err != nil {
			s.logger.Warn("scope wait: start failed", "tenant_id", tenantID.String(), "scan_id", w.ScanID.String(),
				"error", logger.SanitizeError(err))
		}
	}
}

func (s *Service) startAwaitingScan(ctx context.Context, w ScopeWait) error {
	sc, err := s.GetScan(ctx, w.TenantID.String(), w.ScanID.String())
	if err != nil {
		return fmt.Errorf("load scan: %w", err)
	}
	// Run by hand since it was saved: nothing left to wait for.
	if sc.LastRunAt != nil && sc.LastRunAt.After(w.CreatedAt) {
		_, err := s.scopeWaits.Claim(ctx, w.TenantID, w.ScanID)
		return err
	}
	blocked, err := s.attributionGate.BlockedTargets(ctx, w.TenantID, sc.Targets)
	if err != nil {
		return fmt.Errorf("ownership check: %w", err)
	}
	if len(blocked) > 0 {
		return nil // still waiting (another entry, or the approval is not complete)
	}
	claimed, err := s.scopeWaits.Claim(ctx, w.TenantID, w.ScanID)
	if err != nil || !claimed {
		return err
	}
	in := TriggerScanExecInput{
		TenantID: w.TenantID.String(),
		ScanID:   w.ScanID.String(),
		Context:  map[string]any{"triggered_by": "scope_approved"},
	}
	if w.RequestedBy != nil {
		in.TriggeredBy = w.RequestedBy.String()
	}
	trigger := s.TriggerScan
	if s.scopeWaitTrigger != nil {
		trigger = s.scopeWaitTrigger
	}
	if _, err := trigger(ctx, in); err != nil {
		return fmt.Errorf("trigger: %w", err)
	}
	s.logger.Info("scope wait: scan started after its scope was approved",
		"tenant_id", w.TenantID.String(), "scan_id", w.ScanID.String())
	return nil
}
