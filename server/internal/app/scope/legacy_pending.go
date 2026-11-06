package scope

// Leftover pending scope rows (RFC-073 §6): approvals of scope entries and
// exclusions apply only in the Strict scan approval mode. Rows still
// pending in an organization that no longer requires approvals (created
// before RFC-073, or before the organization left Strict) are put into
// effect by this job, one row at a time, through the job signer's ledger
// hook (commitEntry / commitExclusion: the signer accepts the widening
// before it is saved) and audited as a system decision. Organizations in
// Strict keep their pending rows; an unreadable mode counts as Strict.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// pendingStore lists the tenants with pending scope rows
// (*postgres.ScopeTargetRepository).
type pendingStore interface {
	TenantsWithPending(ctx context.Context) ([]shared.ID, error)
}

// settleBatch bounds the rows of each kind one run settles per tenant; the
// next run takes the rest.
const settleBatch = 100

// ActivateLeftoverPending puts into effect the pending scope entries and
// exclusions of every organization whose scan approval mode no longer
// requires approvals for them. Idempotent; one tenant's failure is logged
// and does not stop the others. It returns the rows put into effect.
func (s *Service) ActivateLeftoverPending(ctx context.Context) (int, error) {
	store, ok := s.targetRepo.(pendingStore)
	if !ok {
		return 0, nil
	}
	tenants, err := store.TenantsWithPending(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, tid := range tenants {
		if s.entriesNeedApproval(ctx, tid) {
			continue // Strict (or unreadable): the rows wait for approvers
		}
		n, err := s.settleTenantPending(ctx, tid)
		total += n
		if err != nil {
			s.logger.Warn("scope pending settle: tenant", "tenant_id", tid.String(), "error", logger.SanitizeError(err))
		}
		if n > 0 {
			s.NotifyAdmins(ctx, tid, "Scope changes waiting for approval are now in effect",
				fmt.Sprintf("%d scope change(s) submitted while your organization required approvals are now in effect: it no longer requires approvals for scope changes.", n))
			s.scheduleJoin(tid)
		}
	}
	return total, nil
}

func (s *Service) settleTenantPending(ctx context.Context, tid shared.ID) (int, error) {
	tenant := tid.String()
	page := pagination.New(1, settleBatch)
	targets, err := s.targetRepo.List(ctx, scopedom.TargetFilter{TenantID: &tenant, Statuses: []scopedom.Status{scopedom.StatusPending}}, page)
	if err != nil {
		return 0, fmt.Errorf("list pending scope entries: %w", err)
	}
	done := 0
	for _, t := range targets.Data {
		now := time.Now().UTC()
		if t.TenantID() != tid || !t.IsPending() || t.IsProgramEntry() || t.ExpiredAt(now) {
			continue
		}
		before := ledgerEntryOf(t, now)
		t.Widen("", 0, now)
		if err := s.commitEntry(ctx, before, t, false, func() error {
			return s.targetRepo.Update(ctx, t)
		}); err != nil {
			return done, fmt.Errorf("put pending scope entry %s into effect: %w", t.ID(), err)
		}
		done++
		s.auditSettled(ctx, tid, auditdom.ActionScopeTargetActivated, auditdom.ResourceTypeScopeTarget, t.ID().String(), t.Pattern())
	}
	exclusions, err := s.exclusionRepo.List(ctx, scopedom.ExclusionFilter{TenantID: &tenant, Statuses: []scopedom.Status{scopedom.StatusPending}}, page)
	if err != nil {
		return done, fmt.Errorf("list pending scope exclusions: %w", err)
	}
	for _, e := range exclusions.Data {
		if e.TenantID() != tid || !e.IsPending() || e.IsApproved() || e.RejectedBy() != "" {
			continue
		}
		before := ledgerExclusionOf(e, time.Now())
		if err := e.TakeEffect(""); err != nil {
			continue
		}
		if err := s.commitExclusion(ctx, before, e, false, "", func() error {
			return s.exclusionRepo.Update(ctx, e)
		}); err != nil {
			return done, fmt.Errorf("put pending scope exclusion %s into effect: %w", e.ID(), err)
		}
		done++
		s.auditSettled(ctx, tid, auditdom.ActionScopeExclusionActivated, auditdom.ResourceTypeScopeExclusion, e.ID().String(), e.Pattern())
	}
	return done, nil
}

// auditSettled records a leftover pending row put into effect by the system.
func (s *Service) auditSettled(ctx context.Context, tid shared.ID, action auditdom.Action, rt auditdom.ResourceType, id, pattern string) {
	if s.auditor == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, rt, id).WithResourceName(pattern).
		WithMessage("Pending scope change put into effect: the organization no longer requires approvals for scope changes").
		WithSeverity(auditdom.SeverityMedium).WithMetadata("actor", "system").WithMetadata("reason", "approvals_not_required")
	if err := s.auditor.LogEvent(ctx, auditapp.AuditContext{TenantID: tid.String()}, ev); err != nil {
		s.logger.Warn("scope pending settle: audit", "error", logger.SanitizeError(err))
	}
}
