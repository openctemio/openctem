// Package semgrep provides an adapter to convert Semgrep JSON output to CTIS.
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

// Adapter converts Semgrep JSON output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Semgrep adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "semgrep"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"semgrep", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var output SemgrepOutput
	if err := json.Unmarshal(input, &output); err != nil {
		return false
	}
	// Semgrep always has a "results" key (even if empty array)
	return output.Results != nil
}

// Convert transforms Semgrep JSON input to CTIS Report.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var semgrepOutput SemgrepOutput
	if err := json.Unmarshal(input, &semgrepOutput); err != nil {
		return nil, fmt.Errorf("parse semgrep: %w", err)
	}

	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Tool = &ctis.Tool{
		Name:         "semgrep",
		Vendor:       "Semgrep, Inc.",
		Capabilities: []string{"vulnerability", "secret"},
	}
	if semgrepOutput.Version != "" {
		report.Tool.Version = semgrepOutput.Version
	}

	if opts != nil && opts.Repository != "" {
		report.Metadata.Scope = &ctis.Scope{
			Name: opts.Repository,
		}
	}

	for i, result := range semgrepOutput.Results {
		finding := a.convertResult(result, opts, i)
		if finding != nil {
			report.Findings = append(report.Findings, *finding)
		}
	}

	return report, nil
}

// convertResult converts a Semgrep result to a CTIS finding.
func (a *Adapter) convertResult(result SemgrepResult, opts *core.AdapterOptions, idx int) *ctis.Finding {
	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeVulnerability,
		Title:    result.Extra.Message,
		Severity: mapSemgrepSeverity(result.Extra.Severity),
		RuleID:   result.CheckID,
		Message:  result.Extra.Message,
	}

	// Derive rule name from check_id
	finding.RuleName = ruleIDToName(result.CheckID)

	// Confidence from metadata
	finding.Confidence = mapConfidence(result.Extra.Metadata.Confidence)

	// Location
	finding.Location = &ctis.FindingLocation{
		Path:        result.Path,
		StartLine:   result.Start.Line,
		EndLine:     result.End.Line,
		StartColumn: result.Start.Col,
		EndColumn:   result.End.Col,
		Snippet:     result.Extra.Lines,
	}

	// CWE IDs
	cwes := extractStringList(result.Extra.Metadata.CWE)
	if len(cwes) > 0 {
		finding.Vulnerability = &ctis.VulnerabilityDetails{
			CWEIDs: cwes,
			CWEID:  cwes[0],
		}
	}

	// OWASP IDs
	owasps := extractStringList(result.Extra.Metadata.OWASP)
	if len(owasps) > 0 {
		if finding.Vulnerability == nil {
			finding.Vulnerability = &ctis.VulnerabilityDetails{}
		}
		finding.Vulnerability.OWASPIDs = owasps
	}

	// Vulnerability class
	vulnClasses := extractStringList(result.Extra.Metadata.VulnerabilityClass)
	if len(vulnClasses) > 0 {
		finding.VulnerabilityClass = vulnClasses
	}

	// Subcategory
	subcats := extractStringList(result.Extra.Metadata.Subcategory)
	if len(subcats) > 0 {
		finding.Subcategory = subcats
	}

	// Category
	finding.Category = result.Extra.Metadata.Category

	// Impact and likelihood
	finding.Impact = result.Extra.Metadata.Impact
	finding.Likelihood = result.Extra.Metadata.Likelihood

	// References
	refs := extractStringList(result.Extra.Metadata.References)
	finding.References = refs
	if result.Extra.Metadata.SourceRuleURL != "" {
		finding.References = append(finding.References, result.Extra.Metadata.SourceRuleURL)
	}

	// Tags from technology
	techs := extractStringList(result.Extra.Metadata.Technology)
	if len(techs) > 0 {
		finding.Tags = append(finding.Tags, techs...)
	}
	finding.Tags = append(finding.Tags, "semgrep")

	// Remediation from fix
	if result.Extra.Fix != "" {
		finding.Remediation = &ctis.Remediation{
			Recommendation: "Apply the suggested fix code.",
			FixCode:        result.Extra.Fix,
			FixAvailable:   true,
		}
	}

	// Fingerprint
	if result.Extra.Fingerprint != "" {
		finding.Fingerprint = result.Extra.Fingerprint
	} else {
		finding.Fingerprint = core.GenerateSastFingerprint(result.Path, result.CheckID, result.Start.Line)
	}

	// Data flow trace
	if result.Extra.Dataflow != nil {
		finding.DataFlow = a.convertDataflow(result.Extra.Dataflow)
	}

	// Filter by min severity
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// convertDataflow converts Semgrep dataflow trace to CTIS DataFlow.
func (a *Adapter) convertDataflow(df *SemgrepDataflow) *ctis.DataFlow {
	dataFlow := &ctis.DataFlow{}
	idx := 0

	for _, src := range df.TaintSource {
		dataFlow.Sources = append(dataFlow.Sources, ctis.DataFlowLocation{
			Path:    src.Location.Path,
			Line:    src.Location.Start.Line,
			Column:  src.Location.Start.Col,
			Content: src.Content,
			Index:   idx,
		})
		idx++
	}

	for _, iv := range df.IntermediateVars {
		dataFlow.Intermediates = append(dataFlow.Intermediates, ctis.DataFlowLocation{
			Path:    iv.Location.Path,
			Line:    iv.Location.Start.Line,
			Column:  iv.Location.Start.Col,
			Content: iv.Content,
			Index:   idx,
		})
		idx++
	}

	for _, sink := range df.TaintSink {
		dataFlow.Sinks = append(dataFlow.Sinks, ctis.DataFlowLocation{
			Path:    sink.Location.Path,
			Line:    sink.Location.Start.Line,
			Column:  sink.Location.Start.Col,
			Content: sink.Content,
			Index:   idx,
		})
		idx++
	}

	return dataFlow
}

// mapSemgrepSeverity maps Semgrep severity to CTIS severity.
func mapSemgrepSeverity(s string) ctis.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return ctis.SeverityHigh
	case "WARNING":
		return ctis.SeverityMedium
	case "INFO":
		return ctis.SeverityLow
	case "INVENTORY":
		return ctis.SeverityInfo
	case "EXPERIMENT":
		return ctis.SeverityInfo
	default:
		return ctis.SeverityMedium
	}
}

// mapConfidence maps confidence string to numeric score.
func mapConfidence(c string) int {
	switch strings.ToUpper(c) {
	case "HIGH":
		return 90
	case "MEDIUM":
		return 70
	case "LOW":
		return 50
	default:
		return 70
	}
}

// ruleIDToName converts a Semgrep check_id to a human-readable name.
// e.g., "python.lang.security.injection.sql-injection" -> "Sql Injection"
func ruleIDToName(checkID string) string {
	parts := strings.Split(checkID, ".")
	if len(parts) == 0 {
		return checkID
	}

	lastPart := parts[len(parts)-1]
	words := strings.Split(lastPart, "-")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
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

// ParseToCTIS is a convenience function to parse Semgrep JSON to CTIS format.
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
