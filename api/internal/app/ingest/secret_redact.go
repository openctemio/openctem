package ingest

import (
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// redactReportSecrets masks raw secret values in every free-text field of
// every finding of a report, before anything is stored, fingerprinted,
// quarantined or logged.
//
// Producers mask a secret scanner's match (the CTIS spec says they MUST
// NOT carry it anywhere), but a producer that masked only the snippet left
// the bare secret in the title when the scanner's message repeated it, and
// the platform stored it. This is the receiver's half of the rule, as
// defense in depth: for a secret finding, an unmasked snippet or
// masked_value is taken for the raw secret, and that value and each
// secret-looking word of it are masked in the title, description, message,
// evidence, remediation, tags, properties and fingerprints
// (ctis.RedactSecretFinding; at most the first 4 characters of a secret of
// 16 or more, never more than a quarter). A value already masked is kept,
// so the call is idempotent and a well-behaved producer's output is stored
// unchanged.
//
// A finding counts as a secret finding by its CTIS type, or, when that is
// empty or the generic "vulnerability", by its tool: inferFindingType files
// those as secrets too, and they must not skip the masking.
func redactReportSecrets(report *ctis.Report) {
	if report == nil || len(report.Findings) == 0 {
		return
	}
	secretTool := false
	if report.Tool != nil || report.Metadata.Capability != "" {
		secretTool = reportFindingSource(report) == vulnerability.FindingSourceSecret
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		typ := f.Type
		if secretTool && (typ == "" || typ == ctis.FindingTypeVulnerability) {
			f.Type = ctis.FindingTypeSecret
		}
		ctis.RedactSecretFinding(f)
		f.Type = typ
	}
}
