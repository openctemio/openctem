package finding

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Governed classification (PATCH /findings/{id}/classify).
//
// The classification sets a finding's CVE, CVSS, CWE and OWASP ids. The CVE
// feeds the KEV flag and the priority class, and those decide the finding's
// risk tier: the evidence a resolve needs and the SLA. So the route is not a
// free-text edit:
//
//   - a CVE belongs only on a finding type that carries CVEs (a vulnerability);
//     a secret, misconfiguration, compliance, web3 or license finding refuses one;
//   - a change that lowers the finding's risk tier (clearing or swapping the
//     CVE of a KEV or P0 finding) needs findings:approve, as a severity
//     downgrade needs an approver; findings:severity alone is not enough;
//   - every change writes a timeline entry and an audit event with the old and
//     new values.

// Error codes of a refused classification (English only: they reach the
// caller as the API message).
const (
	// ClassifyCVENotApplicable: the finding type does not carry CVEs.
	ClassifyCVENotApplicable = "CLASSIFY_CVE_NOT_APPLICABLE"
	// ClassifyLowersRisk: the change lowers the risk tier and needs findings:approve.
	ClassifyLowersRisk = "CLASSIFY_LOWERS_RISK"
)

// KEVChecker answers whether a CVE is in the CISA KEV catalog
// (threatintel.KEVRepository).
type KEVChecker interface {
	ExistsByCVEID(ctx context.Context, cveID string) (bool, error)
}

// SetKEVChecker wires the KEV catalog lookup of governed classification. Not
// wired, no CVE counts as KEV after a change, so a change that would drop KEV
// is refused unless the caller can approve (fail closed).
func (s *VulnerabilityService) SetKEVChecker(k KEVChecker) { s.kevChecker = k }

// carriesCVE reports whether findings of the type carry a CVE.
func carriesCVE(t vulnerability.FindingType) bool {
	return t == vulnerability.FindingTypeVulnerability || t == ""
}

// classification is the part of a finding the route edits.
type classification struct {
	CVE    string   `json:"cve_id"`
	CVSS   *float64 `json:"cvss_score"`
	Vector string   `json:"cvss_vector"`
	CWEs   []string `json:"cwe_ids"`
	OWASP  []string `json:"owasp_ids"`
}

func classificationOf(f *vulnerability.Finding) classification {
	return classification{CVE: f.CVEID(), CVSS: f.CVSSScore(), Vector: f.CVSSVector(), CWEs: f.CWEIDs(), OWASP: f.OWASPIDs()}
}

// same compares two classifications (an absent list equals an empty one).
func (c classification) same(o classification) bool {
	if c.CVE != o.CVE || c.Vector != o.Vector || !slices.Equal(c.CWEs, o.CWEs) || !slices.Equal(c.OWASP, o.OWASP) {
		return false
	}
	if (c.CVSS == nil) != (o.CVSS == nil) {
		return false
	}
	return c.CVSS == nil || *c.CVSS == *o.CVSS
}

func (c classification) changes(prefix string) map[string]any {
	m := map[string]any{prefix + "cve_id": c.CVE, prefix + "cvss_vector": c.Vector, prefix + "cwe_ids": c.CWEs, prefix + "owasp_ids": c.OWASP}
	if c.CVSS != nil {
		m[prefix+"cvss_score"] = *c.CVSS
	}
	return m
}

// riskTierRank orders the tiers (higher = more evidence needed to resolve).
func riskTierRank(t vulnerability.RiskTier) int {
	switch t {
	case vulnerability.RiskTierCritical:
		return 2
	case vulnerability.RiskTierHigh:
		return 1
	default:
		return 0
	}
}

// governClassification refuses a classification the type or the caller's
// permissions do not allow. It reads f before the change.
func (s *VulnerabilityService) governClassification(ctx context.Context, f *vulnerability.Finding, in ClassifyFindingInput) error {
	newCVE := vulnerability.NormalizeCVEID(in.CVEID)
	if newCVE != "" && !carriesCVE(f.FindingType()) {
		return shared.NewDomainError(ClassifyCVENotApplicable,
			fmt.Sprintf("A %s finding does not carry a CVE; only vulnerability findings can be linked to one", f.FindingType()),
			shared.ErrValidation)
	}
	oldCVE := f.CVEID()
	if newCVE == oldCVE {
		return nil // CVSS, CWE and OWASP edits do not move the tier
	}
	// The tier before, from the stored facts; the tier after the change: the
	// new CVE's KEV membership, and no priority class (it was derived from
	// the old CVE's signals and is recomputed for the new one).
	pc := ""
	if p := f.PriorityClass(); p != nil {
		pc = string(*p)
	}
	before := vulnerability.FindingRiskTier(f.Severity(), pc, f.IsInKEV())
	kevAfter := false
	if newCVE != "" && s.kevChecker != nil {
		ok, err := s.kevChecker.ExistsByCVEID(ctx, newCVE)
		if err != nil {
			return fmt.Errorf("check KEV membership of %s: %w", newCVE, err)
		}
		kevAfter = ok
	}
	after := vulnerability.FindingRiskTier(f.Severity(), "", kevAfter)
	if riskTierRank(after) < riskTierRank(before) && !in.CanApprove {
		return shared.NewDomainError(ClassifyLowersRisk,
			"This change lowers the finding's risk tier (it drops its KEV or P0 standing) and needs the findings:approve permission; ask an approver, or change the severity through a severity change request",
			shared.ErrForbidden)
	}
	return nil
}

// recordClassification writes the timeline entry and the audit event of an
// applied classification, with the old and new values.
func (s *VulnerabilityService) recordClassification(ctx context.Context, f *vulnerability.Finding, before classification, in ClassifyFindingInput) {
	after := classificationOf(f)
	if before.same(after) {
		return // nothing changed: no entry
	}
	changes := before.changes("old_")
	for k, v := range after.changes("new_") {
		changes[k] = v
	}
	changes["field"] = "classification"
	if s.activityService != nil {
		var actor *string
		if in.ActorID != "" {
			actor = &in.ActorID
		}
		if _, err := s.activityService.RecordActivity(ctx, activity.RecordActivityInput{
			TenantID:     f.TenantID().String(),
			FindingID:    f.ID().String(),
			ActivityType: string(vulnerability.ActivityMetadataUpdated),
			ActorID:      actor,
			ActorType:    string(vulnerability.ActorTypeUser),
			Changes:      changes,
			Source:       string(vulnerability.SourceAPI),
		}); err != nil {
			s.logger.Warn("failed to record classification activity", "error", err)
		}
	}
	meta := map[string]any{"finding_id": f.ID().String()}
	for k, v := range changes {
		meta[k] = v
	}
	meta["cve_changed"] = !strings.EqualFold(before.CVE, after.CVE)
	s.auditSeverity(ctx, in.Audit, audit.ActionFindingClassified, f, "Changed a finding's classification", meta)
}
