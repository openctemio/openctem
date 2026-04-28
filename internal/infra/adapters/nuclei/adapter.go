// Package nuclei provides an adapter to convert Nuclei JSONL output to CTIS.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

// Adapter converts Nuclei JSONL output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Nuclei adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "nuclei"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"nuclei", "jsonl", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	results, err := parseNucleiInput(input)
	if err != nil || len(results) == 0 {
		return false
	}
	// Check for Nuclei-specific fields
	return results[0].TemplateID != "" && results[0].Info.Name != ""
}

// Convert transforms Nuclei JSONL input to CTIS Report.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	results, err := parseNucleiInput(input)
	if err != nil {
		return nil, fmt.Errorf("parse nuclei: %w", err)
	}

	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Tool = &ctis.Tool{
		Name:         "nuclei",
		Vendor:       "ProjectDiscovery",
		Capabilities: []string{"vulnerability"},
		InfoURL:      "https://github.com/projectdiscovery/nuclei",
	}

	if opts != nil && opts.Repository != "" {
		report.Metadata.Scope = &ctis.Scope{
			Name: opts.Repository,
		}
	}

	for i, result := range results {
		finding := a.convertResult(result, opts, i)
		if finding != nil {
			report.Findings = append(report.Findings, *finding)
		}
	}

	return report, nil
}

// convertResult converts a Nuclei result to a CTIS finding.
func (a *Adapter) convertResult(result NucleiResult, opts *core.AdapterOptions, idx int) *ctis.Finding {
	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeVulnerability,
		Title:    result.Info.Name,
		Severity: mapNucleiSeverity(result.Info.Severity),
		RuleID:   result.TemplateID,
	}

	finding.Description = result.Info.Description

	// Message with matched URL
	if result.MatchedAt != "" {
		finding.Message = fmt.Sprintf("%s at %s", result.Info.Name, result.MatchedAt)
	} else {
		finding.Message = result.Info.Name
	}

	// Asset reference from host
	if result.Host != "" {
		finding.AssetValue = result.Host
	}

	// Classification details
	if result.Info.Classification != nil {
		cls := result.Info.Classification
		vulnDetails := &ctis.VulnerabilityDetails{}

		// CVE IDs
		cveIDs := extractStringList(cls.CVEID)
		if len(cveIDs) > 0 {
			vulnDetails.CVEID = cveIDs[0]
		}

		// CWE IDs
		cweIDs := extractStringList(cls.CWEID)
		if len(cweIDs) > 0 {
			vulnDetails.CWEIDs = cweIDs
			vulnDetails.CWEID = cweIDs[0]
		}

		// CVSS
		if cls.CVSSScore > 0 {
			vulnDetails.CVSSScore = cls.CVSSScore
			vulnDetails.CVSSVector = cls.CVSSMetrics
			vulnDetails.CVSSVersion = "3.1"
		}

		finding.Vulnerability = vulnDetails
	}

	// References
	refs := extractStringList(result.Info.Reference)
	finding.References = refs
	if result.TemplateURL != "" {
		finding.References = append(finding.References, result.TemplateURL)
	}

	// Tags
	tags := extractStringList(result.Info.Tags)
	tags = append(tags, "nuclei")
	if result.Type != "" {
		tags = append(tags, result.Type)
	}
	finding.Tags = tags

	// Remediation
	if result.Info.Remediation != "" {
		finding.Remediation = &ctis.Remediation{
			Recommendation: result.Info.Remediation,
		}
	}

	// Location (matched URL as path)
	if result.MatchedAt != "" {
		finding.Location = &ctis.FindingLocation{
			Path: result.MatchedAt,
		}
	}

	// Fingerprint based on template-id + host
	finding.Fingerprint = core.GenerateSastFingerprint(result.Host, result.TemplateID, 0)

	// Confidence based on matcher status
	if result.MatcherStatus {
		finding.Confidence = 90
	} else {
		finding.Confidence = 70
	}

	// Filter by min severity
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// parseNucleiInput parses Nuclei JSONL (one JSON object per line) or a JSON array.
func parseNucleiInput(input []byte) ([]NucleiResult, error) {
	input = bytes.TrimSpace(input)
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Try JSON array first
	if input[0] == '[' {
		var results []NucleiResult
		if err := json.Unmarshal(input, &results); err == nil {
			return results, nil
		}
	}

	// Parse as JSONL (one JSON per line)
	var results []NucleiResult
	scanner := bufio.NewScanner(bytes.NewReader(input))
	// Increase buffer for large lines
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal(line, &result); err != nil {
			continue // Skip invalid lines
		}
		if result.TemplateID != "" {
			results = append(results, result)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan JSONL: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid nuclei results found")
	}

	return results, nil
}

// mapNucleiSeverity maps Nuclei severity to CTIS severity.
func mapNucleiSeverity(s string) ctis.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return ctis.SeverityCritical
	case "high":
		return ctis.SeverityHigh
	case "medium":
		return ctis.SeverityMedium
	case "low":
		return ctis.SeverityLow
	case "info":
		return ctis.SeverityInfo
	case "unknown":
		return ctis.SeverityInfo
	default:
		return ctis.SeverityMedium
	}
}

// extractStringList extracts a list of strings from an interface{} that may
// be a string, []string, or []interface{}.
func extractStringList(v interface{}) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case string:
		if val != "" {
			return []string{val}
		}
		return nil
	case []string:
		return val
	case []interface{}:
		var result []string
		for _, item := range val {
			if s, ok := item.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

// meetsMinSeverity checks if severity meets minimum threshold.
func meetsMinSeverity(s, min ctis.Severity) bool {
	order := map[ctis.Severity]int{
		ctis.SeverityCritical: 5,
		ctis.SeverityHigh:     4,
		ctis.SeverityMedium:   3,
		ctis.SeverityLow:      2,
		ctis.SeverityInfo:     1,
	}
	return order[s] >= order[min]
}

// Ensure Adapter implements core.Adapter
var _ core.Adapter = (*Adapter)(nil)

// ParseToCTIS is a convenience function to parse Nuclei JSONL to CTIS format.
func ParseToCTIS(data []byte, opts *core.ParseOptions) (*ctis.Report, error) {
	adapter := NewAdapter()

	var adapterOpts *core.AdapterOptions
	if opts != nil {
		adapterOpts = &core.AdapterOptions{
			Repository: opts.AssetValue,
		}
		if opts.BranchInfo != nil {
			adapterOpts.Repository = opts.BranchInfo.RepositoryURL
		}
	}

	return adapter.Convert(context.Background(), data, adapterOpts)
}
