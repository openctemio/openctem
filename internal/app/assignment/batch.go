package assignment

import (
	"context"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// BatchAssigner routes a batch of freshly-ingested findings to groups by
// evaluating the tenant's assignment rules once and bulk-inserting the matching
// finding→group records. It closes the gap where auto-assignment ran only on
// the single CreateFinding path, leaving scanner-ingested findings unrouted.
//
// It runs POST-insert (finding IDs must be persisted for the FK), unlike the
// pre-insert priority/SLA enrichers. Per-finding NotifyGroup notifications are
// intentionally NOT emitted here — a bulk scan could route hundreds of findings
// and flood the outbox; group routing is recorded, notification stays a
// single-finding concern.
type BatchAssigner struct {
	engine      *Engine
	acRepo      accesscontrol.Repository
	findingRepo vulnerability.FindingRepository // optional: applies SetFindingPriority override
	logger      *logger.Logger
}

// NewBatchAssigner wires the batch assigner. findingRepo is optional; when nil,
// the SetFindingPriority rule option is skipped (group routing still applies).
func NewBatchAssigner(engine *Engine, acRepo accesscontrol.Repository, findingRepo vulnerability.FindingRepository, log *logger.Logger) *BatchAssigner {
	return &BatchAssigner{
		engine:      engine,
		acRepo:      acRepo,
		findingRepo: findingRepo,
		logger:      log.With("service", "assignment-batch"),
	}
}

// ApplyBatch evaluates assignment rules against the given persisted findings and
// bulk-creates the matching group assignments. Returns the number of
// finding→group records created. Best-effort priority override is applied per
// matched finding when a rule sets one. A nil/empty batch is a no-op.
func (b *BatchAssigner) ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) (int, error) {
	if b == nil || b.engine == nil || b.acRepo == nil || len(findings) == 0 {
		return 0, nil
	}

	matches, err := b.engine.EvaluateBatch(ctx, tenantID, findings)
	if err != nil {
		return 0, err
	}
	if len(matches) == 0 {
		return 0, nil
	}

	// Index findings by ID so we can apply priority overrides without a re-lookup.
	byID := make(map[shared.ID]*vulnerability.Finding, len(findings))
	for _, f := range findings {
		if f != nil {
			byID[f.ID()] = f
		}
	}

	fgas := make([]*accesscontrol.FindingGroupAssignment, 0, len(matches))
	for findingID, results := range matches {
		for _, r := range results {
			ruleID := r.RuleID
			fga, ferr := accesscontrol.NewFindingGroupAssignment(tenantID, findingID, r.GroupID, &ruleID)
			if ferr != nil {
				b.logger.Warn("failed to build finding group assignment",
					"finding_id", findingID.String(), "group_id", r.GroupID.String(), "error", ferr)
				continue
			}
			fgas = append(fgas, fga)
		}
		b.applyPriorityOverride(ctx, byID[findingID], results)
	}

	if len(fgas) == 0 {
		return 0, nil
	}

	inserted, err := b.acRepo.BulkCreateFindingGroupAssignments(ctx, fgas)
	if err != nil {
		return 0, err
	}
	b.logger.Info("ingest findings routed to groups",
		"tenant_id", tenantID.String(), "matched_findings", len(matches), "assignments", inserted)
	return inserted, nil
}

// applyPriorityOverride sets the finding's rank from the first matching rule that
// carries a SetFindingPriority option (mirrors the single-finding path). Best-
// effort: a persistence failure is logged, never aborts the batch.
func (b *BatchAssigner) applyPriorityOverride(ctx context.Context, f *vulnerability.Finding, results []Result) {
	if f == nil || b.findingRepo == nil {
		return
	}
	for _, r := range results {
		if r.Options.SetFindingPriority == "" {
			continue
		}
		rank := r.Options.PriorityRank()
		if rank == nil {
			return
		}
		if err := f.SetRank(rank); err != nil {
			return
		}
		if err := b.findingRepo.Update(ctx, f); err != nil {
			b.logger.Warn("failed to apply assignment-rule priority in batch",
				"finding_id", f.ID().String(), "priority", r.Options.SetFindingPriority, "error", err)
		}
		return // first matching priority wins
	}
}
