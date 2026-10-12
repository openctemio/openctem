package ingest

// Branch-only findings (docs/architecture/branch-only-findings.md): a
// finding seen only on branches that do not count as exposure (a feature or
// merge-request branch) is marked by the database when it is inserted. It
// runs no workflow (notification, ticket rule) and no regression follow-up
// until a counting branch sees it; then it is promoted and its workflows run
// as for a new finding.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// branchOnlyRepo is the part of the finding repository that reads and
// clears the branch-only mark. postgres.FindingRepository implements it; a
// repository without it treats every finding as counting.
type branchOnlyRepo interface {
	BranchOnlyIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error)
	PromoteBranchOnlyByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string) ([]shared.ID, error)
}

// branchOnlyOf returns which of ids are branch-only. A failed lookup returns
// nil (all counting): a missed exclusion notifies once too often, which is
// safer than dropping a real finding's notification.
func (p *FindingProcessor) branchOnlyOf(ctx context.Context, tenantID shared.ID, ids []shared.ID) map[shared.ID]bool {
	repo, ok := p.repo.(branchOnlyRepo)
	if !ok || len(ids) == 0 {
		return nil
	}
	marked, err := repo.BranchOnlyIDs(ctx, tenantID, ids)
	if err != nil {
		p.logger.Warn("branch-only lookup failed; treating findings as counting", "error", err, "count", len(ids))
		return nil
	}
	return marked
}

// withoutBranchOnly drops the branch-only findings from findings.
func (p *FindingProcessor) withoutBranchOnly(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) []*vulnerability.Finding {
	ids := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID())
	}
	marked := p.branchOnlyOf(ctx, tenantID, ids)
	if len(marked) == 0 {
		return findings
	}
	out := make([]*vulnerability.Finding, 0, len(findings))
	for _, f := range findings {
		if !marked[f.ID()] {
			out = append(out, f)
		}
	}
	return out
}

// reopenedWithoutBranchOnly drops the branch-only findings from reopened.
func (p *FindingProcessor) reopenedWithoutBranchOnly(ctx context.Context, tenantID shared.ID, reopened []vulnerability.ReopenedFinding) []vulnerability.ReopenedFinding {
	ids := make([]shared.ID, 0, len(reopened))
	for _, rf := range reopened {
		ids = append(ids, rf.ID)
	}
	marked := p.branchOnlyOf(ctx, tenantID, ids)
	if len(marked) == 0 {
		return reopened
	}
	out := make([]vulnerability.ReopenedFinding, 0, len(reopened))
	for _, rf := range reopened {
		if !marked[rf.ID] {
			out = append(out, rf)
		}
	}
	return out
}

// promoteBranchOnly clears the mark on the batch's branch-only findings that
// a counting branch has now seen (their occurrences were just recorded),
// starting their SLA clock, and runs their workflows as new exposure.
// Best-effort, like the occurrence write before it.
func (p *FindingProcessor) promoteBranchOnly(ctx context.Context, tenantID shared.ID, occurrences []vulnerability.BranchOccurrenceUpsert) {
	repo, ok := p.repo.(branchOnlyRepo)
	if !ok || len(occurrences) == 0 {
		return
	}
	seen := make(map[string]struct{}, len(occurrences))
	fingerprints := make([]string, 0, len(occurrences))
	for _, o := range occurrences {
		if _, dup := seen[o.Fingerprint]; dup {
			continue
		}
		seen[o.Fingerprint] = struct{}{}
		fingerprints = append(fingerprints, o.Fingerprint)
	}
	promoted, err := repo.PromoteBranchOnlyByFingerprints(ctx, tenantID, fingerprints)
	if err != nil {
		p.logger.Warn("failed to promote branch-only findings", "error", err)
		return
	}
	if len(promoted) == 0 {
		return
	}
	p.logger.Info("promoted branch-only findings seen on a counting branch", "count", len(promoted))
	if p.findingCreatedCallback == nil {
		return
	}
	findings, err := p.repo.GetByIDs(ctx, tenantID, promoted)
	if err != nil {
		p.logger.Warn("failed to load promoted findings for workflows", "error", err, "count", len(promoted))
		return
	}
	if len(findings) > 0 {
		p.findingCreatedCallback(ctx, tenantID, findings)
	}
}
