// Package defectdojo converts DefectDojo findings (from its /api/v2/findings/
// REST endpoint) into a CTIS report, so DefectDojo can act as a 200+-parser
// ingestion front-end while OpenCTEM remains the system of record (RFC-013).
//
// This file is the pure converter — no network. The REST client + scheduler is
// a later phase. Keeping the mapping pure makes it unit-testable and keeps
// DefectDojo behind the CTIS contract, so it can be phased out by simply
// removing the connector.
package defectdojo

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// Finding is the subset of a DefectDojo /api/v2/findings/ record we map. Unknown
// fields are ignored by the JSON decoder.
type Finding struct {
	ID               int                `json:"id"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	Severity         string             `json:"severity"` // Critical|High|Medium|Low|Info
	Mitigation       string             `json:"mitigation"`
	CWE              int                `json:"cwe"`
	CVE              string             `json:"cve"` // deprecated in DD but still populated
	VulnerabilityIDs []VulnerabilityRef `json:"vulnerability_ids"`
	CVSSv3Score      float64            `json:"cvssv3_score"`
	CVSSv3           string             `json:"cvssv3"` // vector
	FilePath         string             `json:"file_path"`
	Line             int                `json:"line"`
	ComponentName    string             `json:"component_name"`
	ComponentVersion string             `json:"component_version"`
	UniqueIDFromTool string             `json:"unique_id_from_tool"`
	HashCode         string             `json:"hash_code"`
	References       string             `json:"references"`
	Tags             []string           `json:"tags"`
	// Triage flags — carried as hints/tags only; DefectDojo is not the system of
	// record, so its triage never auto-mutates OpenCTEM status.
	Active       bool `json:"active"`
	Verified     bool `json:"verified"`
	FalseP       bool `json:"false_p"`
	RiskAccepted bool `json:"risk_accepted"`
	IsMitigated  bool `json:"is_mitigated"`
	Duplicate    bool `json:"duplicate"`
	// Endpoints is the resolved list of host/URL strings for this finding (the
	// REST client resolves DD endpoint ids to hosts before conversion).
	Endpoints []string `json:"endpoint_hosts"`
}

// VulnerabilityRef is DefectDojo's per-CVE reference object.
type VulnerabilityRef struct {
	VulnerabilityID string `json:"vulnerability_id"`
}

// ConvertOptions parameterizes a conversion.
type ConvertOptions struct {
	ToolName    string        // default "defectdojo"
	SourceRef   string        // DefectDojo scan/test/engagement id, for traceability
	ProductName string        // fallback asset value when a finding has no endpoint
	Now         time.Time     // report timestamp (defaults to time.Now)
	MinSeverity ctis.Severity // optional floor; "" = keep all
}

// Convert turns a page of DefectDojo findings into a CTIS report.
//
// Invariants (RFC-013):
//   - CoverageType is "partial": a DefectDojo import is never a full scan of a
//     scope, so it MUST NOT trigger OpenCTEM's asset-scoped auto-resolve.
//   - Each finding carries DefectDojo's stable identity (finding_id + hash_code)
//     in partial_fingerprints and a deterministic fingerprint, so re-imports are
//     idempotent and never double-dedup against native findings.
func Convert(findings []Finding, opts ConvertOptions) *ctis.Report {
	toolName := opts.ToolName
	if toolName == "" {
		toolName = "defectdojo"
	}
	ts := opts.Now
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID:         opts.SourceRef,
			Timestamp:  ts,
			SourceType: "integration",
			SourceRef:  opts.SourceRef,
			// NEVER "full": a DefectDojo import is a partial view; auto-resolve
			// must not fire and wrongly close native findings.
			CoverageType: "partial",
		},
		Tool: &ctis.Tool{
			Name:   toolName,
			Vendor: "DefectDojo",
			// A DefectDojo sync is an import from another platform, not a scan
			// we ran. Without this the ingest mapper defaulted to SAST, so a
			// synced network or container finding arrived labeled as source
			// code analysis.
			Capabilities: []string{"external"},
		},
	}

	minRank := severityRank(opts.MinSeverity)
	for i := range findings {
		f := &findings[i]
		sev := mapSeverity(f.Severity)
		if minRank > 0 && severityRank(sev) < minRank {
			continue
		}
		report.Findings = append(report.Findings, buildFinding(f, sev, opts.ProductName))
	}
	return report
}

func buildFinding(f *Finding, sev ctis.Severity, product string) ctis.Finding {
	out := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       strings.TrimSpace(f.Title),
		Description: strings.TrimSpace(f.Description),
		Severity:    sev,
		RuleID:      firstNonEmpty(f.UniqueIDFromTool, f.HashCode, strconv.Itoa(f.ID)),
		References:  splitReferences(f.References),
		// Stable across re-imports so DefectDojo findings map to the same
		// OpenCTEM finding instead of duplicating each pull.
		Fingerprint: defectDojoFingerprint(f),
		PartialFingerprints: map[string]string{
			"defectdojo/finding_id": strconv.Itoa(f.ID),
		},
		Tags: triageTags(f),
	}
	if f.HashCode != "" {
		out.PartialFingerprints["defectdojo/hash_code"] = f.HashCode
	}

	// Asset: prefer a resolved endpoint host (web/host target); else fall back to
	// the product name (an app/repo). Empty → the platform's tool_fallback
	// creates a synthetic asset so findings are never orphaned.
	if host := firstNonEmpty(f.Endpoints...); host != "" {
		out.AssetValue = host
		out.AssetType = ctis.AssetTypeWebsite
	} else if product != "" {
		out.AssetValue = product
		out.AssetType = ctis.AssetTypeRepository
	}

	// Code location for SAST/SCA-style findings.
	if f.FilePath != "" {
		out.Location = &ctis.FindingLocation{Path: f.FilePath, StartLine: f.Line}
	}

	// Vulnerability details: CVE(s), CWE, CVSS.
	vuln := &ctis.VulnerabilityDetails{}
	cves := collectCVEs(f)
	if len(cves) > 0 {
		vuln.CVEID = cves[0]
		vuln.CVEIDs = cves
	}
	if f.CWE > 0 {
		vuln.CWEID = fmt.Sprintf("CWE-%d", f.CWE)
		vuln.CWEIDs = []string{vuln.CWEID}
	}
	if f.CVSSv3Score > 0 {
		vuln.CVSSScore = f.CVSSv3Score
		vuln.CVSSVersion = "3.x"
		vuln.CVSSVector = f.CVSSv3
	}
	if vuln.CVEID != "" || vuln.CWEID != "" || vuln.CVSSScore > 0 {
		out.Vulnerability = vuln
	}

	if m := strings.TrimSpace(f.Mitigation); m != "" {
		out.Remediation = &ctis.Remediation{Recommendation: m}
	}
	return out
}

// defectDojoFingerprint is deterministic per DefectDojo finding so re-imports are
// idempotent. Prefer DD's own hash_code (stable across its rescans); fall back
// to the finding id.
func defectDojoFingerprint(f *Finding) string {
	if f.HashCode != "" {
		return "defectdojo:" + f.HashCode
	}
	return "defectdojo:id:" + strconv.Itoa(f.ID)
}

// collectCVEs merges the deprecated single `cve` and the `vulnerability_ids`
// list, de-duplicated, keeping only CVE-shaped ids.
func collectCVEs(f *Finding) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(f.VulnerabilityIDs)+1)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || !strings.HasPrefix(strings.ToUpper(v), "CVE-") {
			return
		}
		u := strings.ToUpper(v)
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	add(f.CVE)
	for _, v := range f.VulnerabilityIDs {
		add(v.VulnerabilityID)
	}
	return out
}

// triageTags surfaces DefectDojo's triage state as tags (hints), never as an
// authoritative status — OpenCTEM is the system of record.
func triageTags(f *Finding) []string {
	tags := make([]string, 0, len(f.Tags)+2)
	tags = append(tags, f.Tags...)
	if f.RiskAccepted {
		tags = append(tags, "dd:risk_accepted")
	}
	if f.FalseP {
		tags = append(tags, "dd:false_positive")
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

func mapSeverity(s string) ctis.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return ctis.SeverityCritical
	case "high":
		return ctis.SeverityHigh
	case "medium":
		return ctis.SeverityMedium
	case "low":
		return ctis.SeverityLow
	case "info", "informational", "information":
		return ctis.SeverityInfo
	default:
		return ctis.SeverityInfo
	}
}

func severityRank(s ctis.Severity) int {
	switch s {
	case ctis.SeverityCritical:
		return 5
	case ctis.SeverityHigh:
		return 4
	case ctis.SeverityMedium:
		return 3
	case ctis.SeverityLow:
		return 2
	case ctis.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func splitReferences(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
