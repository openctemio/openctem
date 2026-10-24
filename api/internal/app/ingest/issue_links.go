package ingest

// Same-issue links at ingest (pkg/domain/issuelink decides).
// https://github.com/openctemio/openctem/blob/develop/api/docs/architecture/deduplication.md
//
// After a batch is stored, the link keys of its SAST and secret findings are
// recomputed and the findings are linked to the findings of other tools (or
// rules) that report the same issue. A link never changes a finding, so this
// step only ever adds grouping; a failure is logged and leaves findings as
// they are.

import (
	"context"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// IssueLinkStore derives same-issue links (the postgres finding issue link
// repository).
type IssueLinkStore interface {
	DeriveIssueLinks(ctx context.Context, tenantID shared.ID, fingerprints []string) error
}

// SetIssueLinkStore wires same-issue links (nil: off).
func (p *FindingProcessor) SetIssueLinkStore(s IssueLinkStore) { p.issueLinks = s }

// linkIssues derives the links of the batch's SAST and secret findings.
func (p *FindingProcessor) linkIssues(ctx context.Context, tenantID shared.ID, findings []correlationItem) {
	if p.issueLinks == nil || len(findings) == 0 {
		return
	}
	fps := make([]string, 0, len(findings))
	for i := range findings {
		if linkableKind(findings[i].finding) {
			fps = append(fps, findings[i].fingerprint)
		}
	}
	if len(fps) == 0 {
		return
	}
	if err := p.issueLinks.DeriveIssueLinks(ctx, tenantID, fps); err != nil {
		p.logger.Warn("same-issue links not derived", "error", err)
	}
}

func linkableKind(f *ctis.Finding) bool {
	k := identityKind(f)
	return k == vulnerability.IdentityKindSAST || k == vulnerability.IdentityKindSecret
}
