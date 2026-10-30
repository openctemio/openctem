package scope

// Scope effects: what marking something out of scope does beyond scanning
// (research/320, RFC-054 §20). An asset out of scope for good (a permanent
// not_ours or retired exclusion in effect matches it, or the organization
// marked it not its own) has its open findings closed as resolved with the
// closure reason out_of_scope, never counted as fixed. When that stops
// being true (the exclusion is removed, deactivated, shortened to an end
// date or changed to do_not_scan, the decision undone) the findings closed
// that way reopen to the status they had. Remediation tasks, tickets and
// SLA clocks follow the findings through their own reconcilers.
//
// The reconciler runs as the platform, per organization, after every
// exclusion or "not ours" change (Kick) and on a schedule (ReconcileAll),
// so an expiry, a finding imported meanwhile or a missed kick is caught.
// Each pass is bounded (EffectsBatch per direction) and audited.

import (
	"context"
	"fmt"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EffectsBatch bounds how many findings one pass closes, and how many it
// reopens, per organization. A larger change finishes over the next passes.
const EffectsBatch = 1000

// effectsKickTimeout bounds one kicked pass.
const effectsKickTimeout = 2 * time.Minute

// EffectsRepository closes and reopens findings (*postgres.ScopeEffectsRepository).
type EffectsRepository interface {
	TenantsWithScopeEffects(ctx context.Context) ([]shared.ID, error)
	CloseOutOfScope(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error)
	ReopenBackInScope(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error)
}

// EffectsResult is what one pass changed in one organization.
type EffectsResult struct {
	Closed   []shared.ID
	Reopened []shared.ID
}

// Effects is the scope effects reconciler.
type Effects struct {
	repo   EffectsRepository
	audit  auditapp.EventWriter
	logger *logger.Logger

	mu       sync.Mutex
	inFlight map[shared.ID]bool
	again    map[shared.ID]bool
}

// NewEffects creates the reconciler. audit may be nil (tests).
func NewEffects(repo EffectsRepository, audit auditapp.EventWriter, log *logger.Logger) *Effects {
	return &Effects{repo: repo, audit: audit, logger: log.With("service", "scope-effects"),
		inFlight: map[shared.ID]bool{}, again: map[shared.ID]bool{}}
}

// SetEffects wires the scope effects reconciler: every saved exclusion
// change kicks a pass for its organization.
func (s *Service) SetEffects(e *Effects) { s.effects = e }

// ReconcileTenant runs one pass for one organization: close, then reopen.
// A finding is never both: the two predicates are each other's negation.
func (e *Effects) ReconcileTenant(ctx context.Context, tenantID shared.ID) (EffectsResult, error) {
	var res EffectsResult
	if tenantID.IsZero() {
		return res, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	closed, err := e.repo.CloseOutOfScope(ctx, tenantID, EffectsBatch)
	if err != nil {
		return res, err
	}
	res.Closed = closed
	reopened, err := e.repo.ReopenBackInScope(ctx, tenantID, EffectsBatch)
	if err != nil {
		e.auditPass(ctx, tenantID, res)
		return res, err
	}
	res.Reopened = reopened
	e.auditPass(ctx, tenantID, res)
	return res, nil
}

// ReconcileAll runs one pass for every organization that may have
// something to change, and returns how many findings moved. One
// organization's failure does not stop the others.
func (e *Effects) ReconcileAll(ctx context.Context) (int, error) {
	tenants, err := e.repo.TenantsWithScopeEffects(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range tenants {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		res, err := e.ReconcileTenant(ctx, t)
		n += len(res.Closed) + len(res.Reopened)
		if err != nil {
			e.logger.Warn("scope effects pass failed", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return n, nil
}

// Kick runs a pass for the organization soon, in the background, after a
// change that may close or reopen findings. Kicks while a pass runs fold
// into one more pass. Nil-safe.
func (e *Effects) Kick(tenantID shared.ID) {
	if e == nil || tenantID.IsZero() {
		return
	}
	e.mu.Lock()
	if e.inFlight[tenantID] {
		e.again[tenantID] = true
		e.mu.Unlock()
		return
	}
	e.inFlight[tenantID] = true
	e.mu.Unlock()
	go e.runKicked(tenantID)
}

func (e *Effects) runKicked(tenantID shared.ID) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), effectsKickTimeout)
		if _, err := e.ReconcileTenant(ctx, tenantID); err != nil {
			e.logger.Warn("scope effects pass failed", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
		cancel()
		e.mu.Lock()
		if !e.again[tenantID] {
			delete(e.inFlight, tenantID)
			e.mu.Unlock()
			return
		}
		delete(e.again, tenantID)
		e.mu.Unlock()
	}
}

// auditPass records what a pass changed (nothing when it changed nothing).
func (e *Effects) auditPass(ctx context.Context, tenantID shared.ID, res EffectsResult) {
	if e.audit == nil || (len(res.Closed) == 0 && len(res.Reopened) == 0) {
		return
	}
	actx := auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "system"}
	ev := auditapp.NewSuccessEvent(auditdom.ActionScopeEffectsApplied, auditdom.ResourceTypeScopeExclusion, tenantID.String()).
		WithMessage(fmt.Sprintf("%d finding(s) closed as out of scope, %d reopened as back in scope",
			len(res.Closed), len(res.Reopened))).
		WithMetadata("closed", len(res.Closed)).
		WithMetadata("reopened", len(res.Reopened)).
		WithMetadata("closed_ids", idStrings(res.Closed, 50)).
		WithMetadata("reopened_ids", idStrings(res.Reopened, 50))
	auditapp.RecordOrWarn(ctx, e.logger, e.audit, actx, ev)
}

// idStrings is up to max ids as strings (the audit row names a sample; the
// findings' timelines hold every move).
func idStrings(ids []shared.ID, max int) []string {
	n := len(ids)
	if n > max {
		n = max
	}
	out := make([]string, 0, n)
	for _, id := range ids[:n] {
		out = append(out, id.String())
	}
	return out
}
