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

	"github.com/openctemio/ctis/v2"
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

	// A CTIS 2.0 document carries no receiver key: metadata.id is a fresh
	// UUIDv7 idempotency key and DefectDojo's own reference is a source_ref.
	report := &ctis.Report{
		Version: ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{
			ID:          ctis.NewReportID(),
			GeneratedAt: ts,
			Channel:     ctis.ChannelIntegration,
			// NEVER "full": a DefectDojo import is a partial view; auto-resolve
			// must not fire and wrongly close native findings.
			CoverageType: ctis.CoveragePartial,
		},
		// A DefectDojo sync is an import from another platform, not a scan we
		// ran: no technique, so the ingest files the findings as external.
		Tool: &ctis.Tool{Name: toolName, Vendor: "DefectDojo"},
	}
	if ref := strings.TrimSpace(opts.SourceRef); ref != "" {
		report.Metadata.SourceRefs = []ctis.SourceRef{{System: "defectdojo", ID: ref}}
	}
	assets := newAssetIndex(report)

	minRank := severityRank(opts.MinSeverity)
	for i := range findings {
		f := &findings[i]
		sev := mapSeverity(f.Severity)
		if minRank > 0 && severityRank(sev) < minRank {
			continue
		}
		report.Findings = append(report.Findings, buildFinding(f, sev, assets.refFor(f, opts.ProductName)))
	}
	return report
}

func buildFinding(f *Finding, sev ctis.Severity, assetRef string) ctis.Finding {
	out := ctis.Finding{
		Type:        ctis.FindingTypeVulnerability,
		Title:       strings.TrimSpace(f.Title),
		Description: strings.TrimSpace(f.Description),
		Severity:    sev,
		RuleID:      firstNonEmpty(f.UniqueIDFromTool, f.HashCode, strconv.Itoa(f.ID)),
		References:  splitReferences(f.References),
		AssetRef:    assetRef,
		// Stable across re-imports so DefectDojo findings map to the same
		// OpenCTEM finding instead of duplicating each pull.
		Fingerprint: defectDojoFingerprint(f),
		PartialFingerprints: map[string]string{
			"defectdojo/finding_id": strconv.Itoa(f.ID),
		},
		SourceRefs: []ctis.SourceRef{{System: "defectdojo", ID: strconv.Itoa(f.ID)}},
		Tags:       triageTags(f),
	}
	if f.HashCode != "" {
		out.PartialFingerprints["defectdojo/hash_code"] = f.HashCode
	}

	// Code location for SAST/SCA-style findings.
	if f.FilePath != "" {
		out.Location = &ctis.FindingLocation{Path: f.FilePath, StartLine: f.Line}
	}

	// Vulnerability details: CVE(s), CWE; the CVSS score is a finding score.
	vuln := &ctis.VulnerabilityDetails{}
	for _, c := range collectCVEs(f) {
		vuln.AddID(c, "defectdojo")
	}
	if f.CWE > 0 {
		vuln.CWEIDs = []string{fmt.Sprintf("CWE-%d", f.CWE)}
	}
	if len(vuln.IDs) > 0 || len(vuln.CWEIDs) > 0 {
		out.Vulnerability = vuln
	}
	if f.CVSSv3Score > 0 {
		score := f.CVSSv3Score
		out.Scores = []ctis.Score{{System: ctis.ScoreSystemCVSS, Version: "3.x", Vector: f.CVSSv3, Value: &score, Source: "defectdojo"}}
		if v := ctis.CVSSVersionOfVector(f.CVSSv3); v != "" {
			out.Scores[0].Version = v
		}
	}

	if m := strings.TrimSpace(f.Mitigation); m != "" {
		out.Remediation = &ctis.Remediation{Recommendation: m}
	}
	return out
}

// assetIndex is the assets of a converted report, one per canonical value.
type assetIndex struct {
	report *ctis.Report
	refs   map[string]string // type + value -> asset id
}

func newAssetIndex(r *ctis.Report) *assetIndex {
	return &assetIndex{report: r, refs: map[string]string{}}
}

// refFor returns the asset id of the asset a DefectDojo finding is on, adding
// the asset to the report: its first endpoint (a web origin for a URL, else
// an address or a host name), else the product (an unclassified asset named
// after it), else one "defectdojo" asset, so every finding names an asset.
func (x *assetIndex) refFor(f *Finding, product string) string {
	typ, value := ctis.AssetTypeUnclassified, "defectdojo"
	if host := firstNonEmpty(f.Endpoints...); host != "" {
		if t, v, ok := endpointAsset(host); ok {
			typ, value = t, v
		}
	} else if p := strings.TrimSpace(product); p != "" {
		value = p
	}
	key := string(typ) + "\x1f" + value
	if id, ok := x.refs[key]; ok {
		return id
	}
	id := "dd-asset-" + strconv.Itoa(len(x.refs)+1)
	x.refs[key] = id
	x.report.Assets = append(x.report.Assets, ctis.Asset{ID: id, Type: typ, Value: value})
	return id
}

// endpointAsset is the CTIS asset a DefectDojo endpoint string names, in the
// canonical form of its type.
func endpointAsset(raw string) (ctis.AssetType, string, bool) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		if v, err := ctis.CanonicalOrigin(raw); err == nil {
			return ctis.AssetTypeWebOrigin, v, true
		}
		return "", "", false
	}
	host := raw
	if h, _, ok := strings.Cut(raw, "/"); ok {
		host = h
	}
	if v, err := ctis.CanonicalIP(host); err == nil {
		return ctis.AssetTypeIPAddress, v, true
	}
	if v, err := ctis.CanonicalDomain(host); err == nil {
		return ctis.AssetTypeDomainName, v, true
	}
	return "", "", false
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
