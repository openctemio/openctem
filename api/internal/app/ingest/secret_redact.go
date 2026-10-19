package ingest

import (
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// keyRawSecrets runs before redactReportSecrets. It drops every
// partial-fingerprint key only the server writes (composite/*, sensor/*,
// server/*) from each finding, and, for a secret whose masked_value is not
// masked (the producer sent the raw value), records the server's keyed
// per-tenant hash of that value under partialServerSecretHMAC. The finding
// is then keyed on the secret, not on the mask the redaction leaves; the
// raw value itself is never kept.
func (p *FindingProcessor) keyRawSecrets(tenantID shared.ID, report *ctis.Report) {
	if report == nil {
		return
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		for k := range f.PartialFingerprints {
			if vulnerability.IsServerPartialFingerprintKey(k) {
				delete(f.PartialFingerprints, k)
			}
		}
		if f.Secret == nil || looksMasked(f.Secret.MaskedValue) {
			continue
		}
		h := p.secretFingerprinter.Fingerprint(tenantID, "raw:v1:"+strings.TrimSpace(f.Secret.MaskedValue))
		if h == "" {
			continue
		}
		if f.PartialFingerprints == nil {
			f.PartialFingerprints = map[string]string{}
		}
		f.PartialFingerprints[partialServerSecretHMAC] = h
	}
}

// looksMasked reports whether a reported secret value is already a mask
// (the same test the CTIS redaction applies): empty, only mask characters,
// a run of them, or "redacted".
func looksMasked(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || strings.Trim(t, "*•") == "" {
		return true
	}
	return strings.Contains(t, "***") || strings.Contains(t, "•••") || strings.Contains(strings.ToLower(t), "redacted")
}

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
