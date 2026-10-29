package ingest

// Same-issue links at ingest (pkg/domain/issuelink decides).
// https://github.com/openctemio/openctem/blob/develop/api/docs/architecture/deduplication.md
//
// After a batch is stored, the link keys of its SAST, secret and CVE findings
// are recomputed and the findings are linked to the findings of other tools
// (or rules, or techniques) that report the same issue. A link never changes
// a finding's status or SLA, so this step only ever adds grouping (and marks
// a version match an active check confirmed); a failure is logged and leaves
// findings as they are.
//
// A new finding that joins the same-issue group of an open original raises no
// second "new finding" notification (a higher severity still does).

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
	// ReportedByOpenGroup returns the finding ids (of ids) that are members
	// of a group whose original is open and that are not more severe than
	// the rest of the group.
	ReportedByOpenGroup(ctx context.Context, tenantID shared.ID, ids []string) (map[string]bool, error)
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
	switch identityKind(f) {
	case vulnerability.IdentityKindSAST, vulnerability.IdentityKindSecret,
		vulnerability.IdentityKindNetwork, vulnerability.IdentityKindDAST, vulnerability.IdentityKindSCA:
		return true
	}
	return false
}

// withoutReported drops, from the findings a batch just created, those that
// joined the same-issue group of an open original: the issue is already open
// and reported, so a second "new finding" notification would be noise. The
// links of the created CVE findings are derived first (the later step 11 is
// idempotent). A failure keeps every finding: alert when in doubt.
func (p *FindingProcessor) withoutReported(ctx context.Context, tenantID shared.ID, created []*vulnerability.Finding) []*vulnerability.Finding {
	if p.issueLinks == nil || len(created) == 0 {
		return created
	}
	fps := make([]string, 0, len(created))
	for _, f := range created {
		if f.CVEID() != "" {
			fps = append(fps, f.Fingerprint())
		}
	}
	if len(fps) == 0 {
		return created
	}
	if err := p.issueLinks.DeriveIssueLinks(ctx, tenantID, fps); err != nil {
		p.logger.Warn("same-issue links not derived before notifying", "error", err)
		return created
	}
	ids := make([]string, 0, len(fps))
	for _, f := range created {
		if f.CVEID() != "" {
			ids = append(ids, f.ID().String())
		}
	}
	reported, err := p.issueLinks.ReportedByOpenGroup(ctx, tenantID, ids)
	if err != nil || len(reported) == 0 {
		if err != nil {
			p.logger.Warn("same-issue groups not read before notifying", "error", err)
		}
		return created
	}
	out := make([]*vulnerability.Finding, 0, len(created))
	for _, f := range created {
		if !reported[f.ID().String()] {
			out = append(out, f)
		}
	}
	return out
}
