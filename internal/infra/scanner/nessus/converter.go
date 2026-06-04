// Package nessus converts Tenable Nessus / Tenable.sc ".nessus" XML exports
// into a CTIS report so vulnerability results can flow through the standard
// ingest pipeline (dedup, correlation, idempotency, scoped auto-resolve).
//
// Both Nessus Professional and Tenable.sc emit the same NessusClientData_v2
// format, so this one converter serves both engines. The existing asset-import
// path (internal/app/asset/import.go) parses the same file but only creates
// host assets and discards the vulnerabilities; this converter is the findings
// counterpart and is also reused by the Tenable connector.
package nessus

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"
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
	// agent-scanner (nuclei/trivy/...) findings and vice versa.
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
	data, err := io.ReadAll(io.LimitReader(r, maxNessusFileSize))
	if err != nil {
		return nil, fmt.Errorf("read nessus data: %w", err)
	}

	var doc nessusDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid Nessus XML: %w", err)
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

// ---- Nessus XML model (richer than the asset-import scaffold) ----

type nessusDocument struct {
	XMLName xml.Name     `xml:"NessusClientData_v2"`
	Hosts   []nessusHost `xml:"Report>ReportHost"`
}

type nessusHost struct {
	Name       string          `xml:"name,attr"`
	Properties []nessusHostTag `xml:"HostProperties>tag"`
	Items      []nessusItem    `xml:"ReportItem"`
}

type nessusHostTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusItem struct {
	Port         int      `xml:"port,attr"`
	Protocol     string   `xml:"protocol,attr"`
	ServiceName  string   `xml:"svc_name,attr"`
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	Severity     int      `xml:"severity,attr"`
	Synopsis     string   `xml:"synopsis"`
	Description  string   `xml:"description"`
	Solution     string   `xml:"solution"`
	RiskFactor   string   `xml:"risk_factor"`
	CVSSScore    string   `xml:"cvss_base_score"`
	CVSSVector   string   `xml:"cvss_vector"`
	CVSS3Score   string   `xml:"cvss3_base_score"`
	CVSS3Vector  string   `xml:"cvss3_vector"`
	CVEs         []string `xml:"cve"`
	SeeAlso      string   `xml:"see_also"`
	PluginOutput string   `xml:"plugin_output"`
}

// hostProps flattens the HostProperties tags into a map.
func (h *nessusHost) props() map[string]string {
	m := make(map[string]string, len(h.Properties))
	for _, p := range h.Properties {
		m[p.Name] = p.Value
	}
	return m
}

// buildAsset turns a Nessus host into a CTIS asset and returns the in-report
// asset id used to link findings.
func buildAsset(host *nessusHost, defaultCrit ctis.Criticality) (ctis.Asset, string) {
	p := host.props()
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
func buildFinding(item *nessusItem, assetID, assetValue string) ctis.Finding {
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

	vuln := &ctis.VulnerabilityDetails{}
	if len(item.CVEs) > 0 {
		vuln.CVEID = item.CVEs[0]
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
	if vuln.CVEID != "" || vuln.CVSSScore > 0 {
		f.Vulnerability = vuln
	}

	if item.Solution != "" && !strings.EqualFold(item.Solution, "n/a") {
		f.Remediation = &ctis.Remediation{Recommendation: item.Solution}
	}

	// Network context that doesn't fit CTIS' code-centric location model.
	f.Properties = ctis.Properties{}
	if item.Port > 0 {
		f.Properties["port"] = item.Port
		f.Properties["protocol"] = item.Protocol
	}
	if item.ServiceName != "" {
		f.Properties["service"] = item.ServiceName
	}
	if len(item.CVEs) > 1 {
		f.Properties["cves"] = item.CVEs
	}
	if out := strings.TrimSpace(item.PluginOutput); out != "" {
		f.Properties["plugin_output"] = out
	}

	return f
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
