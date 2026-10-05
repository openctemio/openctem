package ingest

// Length caps on sensor-supplied finding text (RFC-040 §5.4, gap S4b).
// Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md.
//
// Body size and item counts were bounded, single fields were not: a report
// within the 50 MB body limit could carry a megabyte title or description,
// stored and rendered on every list page, or a title longer than the
// findings.title column, which failed that finding. Every ingest path (v1
// CTIS, protocol v2 segments, SARIF and the other formats converted to CTIS)
// runs Service.Ingest, which applies these caps before anything is stored.
// An oversized value is cut with a marker, never refused: the report and the
// finding still land.

import (
	"strings"
	"unicode/utf8"

	"github.com/openctemio/ctis"
)

// TruncationMarker ends a value cut by a length cap.
const TruncationMarker = "…[truncated]"

// Per-field caps, in characters (runes) including the marker, and caps on
// list lengths. Title and rule name match their varchar(500) columns.
const (
	MaxFindingTitleLen       = 500
	MaxFindingRuleNameLen    = 500
	MaxFindingCategoryLen    = 255
	MaxFindingMessageLen     = 8 * 1024
	MaxFindingDescriptionLen = 32 * 1024
	MaxFindingEvidenceLen    = 64 * 1024
	MaxFindingSnippetLen     = 16 * 1024
	MaxRemediationTextLen    = 16 * 1024
	MaxRemediationStepLen    = 2 * 1024
	MaxRemediationSteps      = 50
	MaxFindingReferenceLen   = 2 * 1024
	MaxFindingReferences     = 100
	MaxFindingTagLen         = 100
	MaxFindingTags           = 50
	MaxFindingClassLen       = 200
	MaxFindingClasses        = 50
	MaxMisconfigTextLen      = 4 * 1024
)

// textCapper caps strings and counts what it changed.
type textCapper struct{ changed int }

// str returns s cut to max runes with the marker, and makes it valid UTF-8.
func (c *textCapper) str(s string, maxRunes int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
		c.changed++
	}
	if len(s) <= maxRunes { // bytes >= runes: short enough
		return s
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	marker := TruncationMarker
	keep := maxRunes - utf8.RuneCountInString(marker)
	if keep < 0 { // no room for the marker: cut only
		keep, marker = maxRunes, ""
	}
	n := 0
	for i := range s {
		if n == keep {
			c.changed++
			return s[:i] + marker
		}
		n++
	}
	return s
}

// list caps the number of items and the length of each. Dropped items are
// replaced by nothing: a list has no room for a marker that is not data.
func (c *textCapper) list(items []string, maxItems, maxRunes int) []string {
	if len(items) > maxItems {
		items = items[:maxItems]
		c.changed++
	}
	for i := range items {
		items[i] = c.str(items[i], maxRunes)
	}
	return items
}

// capReportText applies the caps to every finding of a report, in place, and
// returns how many values it changed.
func capReportText(report *ctis.Report) int {
	if report == nil {
		return 0
	}
	c := &textCapper{}
	for i := range report.Findings {
		capFindingText(c, &report.Findings[i])
	}
	for i := range report.Assets {
		if t := report.Assets[i].Technical; t != nil && t.Certificate != nil {
			capCertificateText(c, t.Certificate)
		}
	}
	return c.changed
}

// Caps on a certificate's text (research/22 E5): the scanned server chose
// every value of the certificate it presented.
const (
	MaxCertNameLen      = 255 // subject CN, issuer CN and organization
	MaxCertSerialLen    = 128
	MaxCertFingerprint  = 128
	MaxCertAlgorithmLen = 64
	MaxCertSANs         = 100
	MaxCertSANLen       = 253
)

func capCertificateText(c *textCapper, ct *ctis.CertificateTechnical) {
	ct.SubjectCN = c.str(stripControl(c, ct.SubjectCN), MaxCertNameLen)
	ct.IssuerCN = c.str(stripControl(c, ct.IssuerCN), MaxCertNameLen)
	ct.IssuerOrg = c.str(stripControl(c, ct.IssuerOrg), MaxCertNameLen)
	ct.SerialNumber = c.str(stripControl(c, ct.SerialNumber), MaxCertSerialLen)
	ct.Fingerprint = c.str(stripControl(c, ct.Fingerprint), MaxCertFingerprint)
	ct.SignatureAlgorithm = c.str(stripControl(c, ct.SignatureAlgorithm), MaxCertAlgorithmLen)
	ct.KeyAlgorithm = c.str(stripControl(c, ct.KeyAlgorithm), MaxCertAlgorithmLen)
	for i := range ct.SANs {
		ct.SANs[i] = stripControl(c, ct.SANs[i])
	}
	ct.SANs = c.list(ct.SANs, MaxCertSANs, MaxCertSANLen)
}

// stripControl removes control characters (newlines included): certificate
// names are shown and logged on one line.
func stripControl(c *textCapper, s string) string {
	out := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if out != s {
		c.changed++
	}
	return out
}

func capFindingText(c *textCapper, f *ctis.Finding) {
	f.Title = c.str(f.Title, MaxFindingTitleLen)
	f.Description = c.str(f.Description, MaxFindingDescriptionLen)
	f.Message = c.str(f.Message, MaxFindingMessageLen)
	f.Evidence = c.str(f.Evidence, MaxFindingEvidenceLen)
	f.RuleName = c.str(f.RuleName, MaxFindingRuleNameLen)
	f.Category = c.str(f.Category, MaxFindingCategoryLen)
	f.References = c.list(f.References, MaxFindingReferences, MaxFindingReferenceLen)
	f.Tags = c.list(f.Tags, MaxFindingTags, MaxFindingTagLen)
	f.VulnerabilityClass = c.list(f.VulnerabilityClass, MaxFindingClasses, MaxFindingClassLen)
	f.Subcategory = c.list(f.Subcategory, MaxFindingClasses, MaxFindingClassLen)

	if l := f.Location; l != nil {
		l.Snippet = c.str(l.Snippet, MaxFindingSnippetLen)
		l.ContextSnippet = c.str(l.ContextSnippet, MaxFindingSnippetLen)
	}
	if r := f.Remediation; r != nil {
		r.Recommendation = c.str(r.Recommendation, MaxRemediationTextLen)
		r.FixCode = c.str(r.FixCode, MaxRemediationTextLen)
		r.Steps = c.list(r.Steps, MaxRemediationSteps, MaxRemediationStepLen)
		r.References = c.list(r.References, MaxFindingReferences, MaxFindingReferenceLen)
	}
	if m := f.Misconfiguration; m != nil {
		m.Expected = c.str(m.Expected, MaxMisconfigTextLen)
		m.Actual = c.str(m.Actual, MaxMisconfigTextLen)
		m.Cause = c.str(m.Cause, MaxMisconfigTextLen)
		m.Query = c.str(m.Query, MaxMisconfigTextLen)
	}
}
