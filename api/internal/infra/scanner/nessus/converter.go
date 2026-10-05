// Package nessus converts Tenable Nessus / Tenable.sc ".nessus" XML exports
// into a CTIS report so vulnerability results can flow through the standard
// ingest pipeline (dedup, correlation, idempotency, scoped auto-resolve).
//
// Both Nessus Professional and Tenable.sc emit the same NessusClientData_v2
// format, so this one converter serves both engines. The file is read by the
// one Nessus parser (pkg/parsers/nessus), which the host-only asset import
// (internal/app/asset/import.go) shares; this converter is the findings
// counterpart and is also reused by the Tenable connector.
package nessus

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	nessusparser "github.com/openctemio/openctem/api/pkg/parsers/nessus"
)

// maxNessusFileSize bounds how much XML we read (defense against huge uploads).
const maxNessusFileSize = 200 * 1024 * 1024 // 200MB

// ConvertOptions controls how a .nessus export is turned into a CTIS report.
type ConvertOptions struct {
	// ScanSessionID becomes the CTIS report metadata.id. For rolling batch
	// coverage this MUST be unique per batch — auto-resolve is scoped by
	// (tool, scan id, asset set), so a stable-but-unique session id per batch
	// is what keeps one batch from resolving another batch's findings.
	ScanSessionID string

	// ToolName is the CTIS tool.name. Defaults to "tenable". Auto-resolve is
	// also scoped by tool name, so this keeps Tenable scans from resolving
	// sensor-scanner (nuclei/trivy/...) findings and vice versa.
	ToolName string

	// Now overrides the report timestamp (tests pass a fixed value). Zero →
	// time.Now().UTC().
	Now time.Time

	// MinSeverity drops report items below this Nessus severity (0=info ..
	// 4=critical). Zero keeps everything. Callers typically pass 1 to skip the
	// purely informational scan-metadata plugins.
	MinSeverity int

	// DefaultCriticality is applied to assets that carry no criticality signal.
	// Empty → ctis.CriticalityMedium.
	DefaultCriticality ctis.Criticality
}

// Convert reads a .nessus XML stream and returns a CTIS report containing the
// scanned hosts as assets and their vulnerabilities as findings.
//
// The report is shaped for safe partial-coverage ingestion:
//   - tool.name + metadata.id scope auto-resolve to this batch + this tool;
//   - coverage_type=full and a synthetic default branch make the batch eligible
//     for auto-resolve (the ingest gate is git-centric — network scans have no
//     branch, so we mark a synthetic default branch; auto-resolve still only
//     touches the assets present in THIS report, i.e. the scanned batch);
//   - only the hosts in this export are included, so stale-resolution can never
//     reach assets that were not part of this scan.
func Convert(r io.Reader, opts ConvertOptions) (*ctis.Report, error) {
	doc, err := nessusparser.Parse(r, maxNessusFileSize)
	if err != nil {
		return nil, fmt.Errorf("parse nessus export: %w", err)
	}

	toolName := opts.ToolName
	if toolName == "" {
		toolName = "tenable"
	}
	ts := opts.Now
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	defaultCrit := opts.DefaultCriticality
	if defaultCrit == "" {
		defaultCrit = ctis.CriticalityMedium
	}

	report := &ctis.Report{
		Version: "1.0",
		Metadata: ctis.ReportMetadata{
			ID:           opts.ScanSessionID,
			Timestamp:    ts,
			SourceType:   "scanner",
			CoverageType: "full",
			// Network scans have no git branch; the ingest auto-resolve gate
			// requires a default-branch marker. Mark a synthetic one so infra
			// scans participate in (asset-scoped) auto-resolve.
			Branch: &ctis.BranchInfo{Name: "network", IsDefaultBranch: true},
		},
		Tool: &ctis.Tool{
			Name:   toolName,
			Vendor: "Tenable",
			// Declare what this is instead of letting the ingest mapper guess
			// from the tool name. It guessed wrong: with no capabilities set,
			// detectFindingSource fell through to its default and stamped every
			// network vulnerability as SAST. toolName is caller-controlled via
			// ?tool=, so name-based inference was never trustworthy here.
			Capabilities: []string{"va"},
		},
	}

	for hostIdx := range doc.Hosts {
		host := &doc.Hosts[hostIdx]
		asset, assetID := buildAsset(host, defaultCrit)
		report.Assets = append(report.Assets, asset)

		for itemIdx := range host.Items {
			item := &host.Items[itemIdx]
			if item.Severity < opts.MinSeverity {
				continue
			}
			report.Findings = append(report.Findings, buildFinding(item, assetID, asset.Value))
		}
	}

	return report, nil
}

// buildAsset turns a Nessus host into a CTIS asset and returns the in-report
// asset id used to link findings.
func buildAsset(host *nessusparser.Host, defaultCrit ctis.Criticality) (ctis.Asset, string) {
	p := host.Props()
	ip := p["host-ip"]
	fqdn := p["host-fqdn"]

	// Canonical value: prefer FQDN for readability, fall back to IP, then the
	// ReportHost name. The platform correlator dedups hosts by IP regardless.
	value := fqdn
	if value == "" {
		value = ip
	}
	if value == "" {
		value = host.Name
	}

	assetType := ctis.AssetTypeHost
	if ip != "" && net.ParseIP(value) != nil {
		assetType = ctis.AssetTypeIPAddress
	}

	props := ctis.Properties{}
	if ip != "" {
		props["ip_address"] = ip
	}
	if fqdn != "" {
		props["fqdn"] = fqdn
	}
	if os := p["operating-system"]; os != "" {
		props["os"] = os
	}
	if mac := p["mac-address"]; mac != "" {
		props["mac_address"] = mac
	}

	id := "host-" + value
	asset := ctis.Asset{
		ID:          id,
		Type:        assetType,
		Value:       value,
		Name:        value,
		Criticality: defaultCrit,
		Properties:  props,
	}
	return asset, id
}

// buildFinding turns a Nessus ReportItem into a CTIS vulnerability finding.
func buildFinding(item *nessusparser.Item, assetID, assetValue string) ctis.Finding {
	f := ctis.Finding{
		Type:       ctis.FindingTypeVulnerability,
		Title:      item.PluginName,
		Severity:   mapSeverity(item.Severity),
		AssetRef:   assetID,
		RuleID:     item.PluginID,
		RuleName:   item.PluginName,
		Category:   item.PluginFamily,
		References: splitSeeAlso(item.SeeAlso),
		// Stable across rescans so the same host+plugin+port dedups instead of
		// duplicating every cycle.
		Fingerprint: fmt.Sprintf("nessus:%s:%s:%d/%s", assetValue, item.PluginID, item.Port, item.Protocol),
	}

	f.Description = strings.TrimSpace(strings.Join(nonEmpty(item.Synopsis, item.Description), "\n\n"))

	// Scanner evidence (first-class as of CTIS network/evidence fields).
	if out := strings.TrimSpace(item.PluginOutput); out != "" {
		f.Evidence = out
	}

	// Network location — a network finding lives on a port/service, not a file.
	if item.Port > 0 || item.ServiceName != "" {
		f.Network = &ctis.NetworkLocation{
			Host:     assetValue,
			Port:     item.Port,
			Protocol: item.Protocol,
			Service:  item.ServiceName,
		}
	}

	vuln := &ctis.VulnerabilityDetails{}
	if len(item.CVEs) > 0 {
		vuln.CVEID = item.CVEs[0] // primary (back-compat)
		vuln.CVEIDs = item.CVEs   // all CVEs grouped under this plugin
	}
	// Prefer CVSS v3 when present.
	if score, ok := parseFloat(item.CVSS3Score); ok {
		vuln.CVSSScore = score
		vuln.CVSSVersion = "3.x"
		vuln.CVSSVector = item.CVSS3Vector
	} else if score, ok := parseFloat(item.CVSSScore); ok {
		vuln.CVSSScore = score
		vuln.CVSSVersion = "2.0"
		vuln.CVSSVector = item.CVSSVector
	}
	if vpr, ok := parseFloat(item.VPRScore); ok {
		vuln.VPRScore = vpr
	}
	if isTruthy(item.ExploitAvail) {
		vuln.ExploitAvailable = true
	}
	if cpe := strings.TrimSpace(item.CPE); cpe != "" {
		vuln.CPE = cpe
	}
	if vuln.CVEID != "" || vuln.CVSSScore > 0 || vuln.VPRScore > 0 || vuln.CPE != "" {
		f.Vulnerability = vuln
	}

	props := ctis.Properties{}
	// Stored by ingest as the finding's patch publication date (research 17 R2).
	if d := strings.TrimSpace(item.PatchPubDate); d != "" {
		props["patch_publication_date"] = d
	}
	// Both CVSS vectors (the CVSS block above keeps one): ingest stores them
	// as cvss_v2_vector and cvss_v3_vector (research 24 P0-2).
	if v := strings.TrimSpace(item.CVSSVector); v != "" {
		props["cvss_v2_vector"] = v
	}
	if v := strings.TrimSpace(item.CVSS3Vector); v != "" {
		props["cvss_v3_vector"] = v
	}
	if len(props) > 0 {
		f.Properties = props
	}

	if item.Solution != "" && !strings.EqualFold(item.Solution, "n/a") {
		f.Remediation = &ctis.Remediation{Recommendation: item.Solution}
	}

	return f
}

// isTruthy reports whether a Nessus boolean-ish string means true.
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1":
		return true
	default:
		return false
	}
}

// mapSeverity maps a Nessus severity integer (0..4) to a CTIS severity.
func mapSeverity(n int) ctis.Severity {
	switch n {
	case 4:
		return ctis.SeverityCritical
	case 3:
		return ctis.SeverityHigh
	case 2:
		return ctis.SeverityMedium
	case 1:
		return ctis.SeverityLow
	default:
		return ctis.SeverityInfo
	}
}

func parseFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// splitSeeAlso splits Nessus' newline-separated see_also block into URLs.
func splitSeeAlso(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if u := strings.TrimSpace(line); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}
