package compliance

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	compliancedom "github.com/openctemio/api/pkg/domain/compliance"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// owaspFrameworkSlug is the seeded OWASP Top 10 (2021) framework.
const owaspFrameworkSlug = "owasp"

var owaspCodeRe = regexp.MustCompile(`(?i)A(\d{1,2})`)

// normalizeOWASP extracts the canonical OWASP Top 10 2021 category code
// ("A01".."A10") from any of the shapes findings/controls carry — "A01:2021",
// "A1", "OWASP-A03", "A03:2021 - Injection". Returns "" when there is no code.
func normalizeOWASP(s string) string {
	m := owaspCodeRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ""
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 10 {
		return ""
	}
	return fmt.Sprintf("A%02d", n)
}

// cweToOWASP maps the most common CWEs to their OWASP Top 10 2021 category.
// Deterministic (no heuristics): each entry follows the official OWASP CWE→
// category mapping. Unlisted CWEs simply do not contribute a mapping.
var cweToOWASP = map[string]string{
	// A01 Broken Access Control
	"CWE-22": "A01", "CWE-284": "A01", "CWE-285": "A01", "CWE-639": "A01",
	"CWE-862": "A01", "CWE-863": "A01", "CWE-425": "A01",
	// A02 Cryptographic Failures
	"CWE-259": "A02", "CWE-311": "A02", "CWE-319": "A02", "CWE-326": "A02",
	"CWE-327": "A02", "CWE-328": "A02", "CWE-916": "A02",
	// A03 Injection
	"CWE-79": "A03", "CWE-89": "A03", "CWE-78": "A03", "CWE-94": "A03",
	"CWE-77": "A03", "CWE-90": "A03", "CWE-91": "A03",
	// A04 Insecure Design
	"CWE-209": "A04", "CWE-256": "A04", "CWE-501": "A04", "CWE-657": "A04",
	// A05 Security Misconfiguration
	// CWE-611 (XXE) merged into A05:2021 (was its own A4:2017 category).
	"CWE-16": "A05", "CWE-548": "A05", "CWE-732": "A05", "CWE-1004": "A05",
	"CWE-611": "A05",
	// A06 Vulnerable and Outdated Components
	"CWE-937": "A06", "CWE-1035": "A06", "CWE-1104": "A06",
	// A07 Identification and Authentication Failures
	"CWE-287": "A07", "CWE-297": "A07", "CWE-384": "A07", "CWE-521": "A07",
	"CWE-613": "A07", "CWE-620": "A07", "CWE-798": "A07",
	// A08 Software and Data Integrity Failures
	"CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08", "CWE-502": "A08", "CWE-829": "A08",
	// A09 Security Logging and Monitoring Failures
	"CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",
	// A10 Server-Side Request Forgery
	"CWE-918": "A10",
}

// normalizeCWE canonicalises a CWE reference to "CWE-<n>".
func normalizeCWE(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	digits := strings.TrimPrefix(s, "CWE-")
	digits = strings.TrimPrefix(digits, "CWE")
	digits = strings.TrimSpace(digits)
	if digits == "" {
		return ""
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return "CWE-" + digits
}

// owaspCategoriesForFinding derives the set of OWASP 2021 category codes a
// finding maps to, from its OWASP ids (direct) plus its CWEs (via cweToOWASP).
func owaspCategoriesForFinding(f *vulnerability.Finding) map[string]struct{} {
	cats := make(map[string]struct{})
	for _, o := range f.OWASPIDs() {
		if c := normalizeOWASP(o); c != "" {
			cats[c] = struct{}{}
		}
	}
	for _, cwe := range f.CWEIDs() {
		if c, ok := cweToOWASP[normalizeCWE(cwe)]; ok {
			cats[c] = struct{}{}
		}
	}
	return cats
}

// AutoMapFinding deterministically maps a finding to the OWASP Top 10 (2021)
// controls implied by its OWASP ids / CWEs, creating the finding→control
// mappings that were previously only possible by hand. Idempotent: existing
// mappings are left untouched and only newly-derived ones are returned.
func (s *ComplianceService) AutoMapFinding(ctx context.Context, tenantID, findingID string) ([]*compliancedom.FindingControlMapping, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid finding id", shared.ErrValidation)
	}
	if s.findingRepo == nil {
		return nil, fmt.Errorf("%w: finding lookup not configured", shared.ErrInternal)
	}

	finding, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err != nil {
		return nil, fmt.Errorf("%w: finding not found", shared.ErrNotFound)
	}
	if finding.Status() == vulnerability.FindingStatusDraft || finding.Status() == vulnerability.FindingStatusInReview {
		return nil, fmt.Errorf("%w: cannot map unconfirmed findings to compliance controls", shared.ErrValidation)
	}

	cats := owaspCategoriesForFinding(finding)
	if len(cats) == 0 {
		return []*compliancedom.FindingControlMapping{}, nil
	}

	// Resolve the OWASP framework + its controls, indexed by category code.
	fw, err := s.frameworkRepo.GetBySlug(ctx, owaspFrameworkSlug)
	if err != nil {
		return nil, fmt.Errorf("%w: OWASP framework not available", shared.ErrNotFound)
	}
	controls, err := s.controlRepo.ListByFramework(ctx, fw.ID(), pagination.New(1, 200))
	if err != nil {
		return nil, err
	}
	byCategory := make(map[string]shared.ID, len(controls.Data))
	for _, c := range controls.Data {
		if code := normalizeOWASP(c.ControlID()); code != "" {
			byCategory[code] = c.ID()
		}
	}

	// Skip controls already mapped (idempotency).
	existing, err := s.mappingRepo.ListByFinding(ctx, tid, fid)
	if err != nil {
		return nil, err
	}
	already := make(map[shared.ID]struct{}, len(existing))
	for _, m := range existing {
		already[m.ControlID()] = struct{}{}
	}

	created := make([]*compliancedom.FindingControlMapping, 0, len(cats))
	for cat := range cats {
		cid, ok := byCategory[cat]
		if !ok {
			continue
		}
		if _, dup := already[cid]; dup {
			continue
		}
		m := compliancedom.NewFindingControlMapping(tid, fid, cid, compliancedom.ImpactDirect)
		if cErr := s.mappingRepo.Create(ctx, m); cErr != nil {
			return nil, cErr
		}
		created = append(created, m)
	}

	s.logger.Info("finding auto-mapped to OWASP controls",
		"finding_id", findingID, "categories", len(cats), "created", len(created))
	return created, nil
}
