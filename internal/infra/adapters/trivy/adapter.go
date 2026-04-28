// Package trivy provides an adapter to convert Trivy JSON output to CTIS.
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

// Adapter converts Trivy JSON output to CTIS.
type Adapter struct{}

// NewAdapter creates a new Trivy adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "trivy"
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	return []string{"trivy", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var report TrivyReport
	if err := json.Unmarshal(input, &report); err != nil {
		return false
	}
	return report.SchemaVersion > 0 && len(report.Results) > 0
}

// Convert transforms Trivy JSON input to CTIS Report.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var trivyReport TrivyReport
	if err := json.Unmarshal(input, &trivyReport); err != nil {
		return nil, fmt.Errorf("parse trivy: %w", err)
	}

	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Tool = &ctis.Tool{
		Name:         "trivy",
		Vendor:       "Aqua Security",
		Capabilities: []string{"vulnerability", "misconfiguration", "secret"},
	}

	if opts != nil {
		if opts.Repository != "" {
			report.Metadata.Scope = &ctis.Scope{
				Name: opts.Repository,
			}
		}
	}

	findingIdx := 0

	for _, result := range trivyReport.Results {
		// Convert vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			finding := a.convertVulnerability(vuln, result.Target, opts, findingIdx)
			if finding != nil {
				report.Findings = append(report.Findings, *finding)
				findingIdx++
			}
		}

		// Convert misconfigurations
		for _, misconfig := range result.Misconfigurations {
			finding := a.convertMisconfig(misconfig, result.Target, opts, findingIdx)
			if finding != nil {
				report.Findings = append(report.Findings, *finding)
				findingIdx++
			}
		}

		// Convert secrets
		for _, secret := range result.Secrets {
			finding := a.convertSecret(secret, result.Target, opts, findingIdx)
			if finding != nil {
				report.Findings = append(report.Findings, *finding)
				findingIdx++
			}
		}
	}

	return report, nil
}

// convertVulnerability converts a Trivy vulnerability to a CTIS finding.
func (a *Adapter) convertVulnerability(vuln TrivyVulnerability, target string, opts *core.AdapterOptions, idx int) *ctis.Finding {
	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeVulnerability,
		Title:    vuln.Title,
		Severity: mapTrivySeverity(vuln.Severity),
		RuleID:   vuln.VulnerabilityID,
	}

	if finding.Title == "" {
		finding.Title = fmt.Sprintf("%s in %s", vuln.VulnerabilityID, vuln.PkgName)
	}

	finding.Description = vuln.Description

	// Build vulnerability details
	vulnDetails := &ctis.VulnerabilityDetails{
		Package:         vuln.PkgName,
		AffectedVersion: vuln.InstalledVersion,
		FixedVersion:    vuln.FixedVersion,
	}

	// Set CVE ID
	if strings.HasPrefix(vuln.VulnerabilityID, "CVE-") {
		vulnDetails.CVEID = vuln.VulnerabilityID
	}

	// Set CWE IDs
	if len(vuln.CweIDs) > 0 {
		vulnDetails.CWEIDs = vuln.CweIDs
		vulnDetails.CWEID = vuln.CweIDs[0]
	}

	// Extract best CVSS score
	score, vector, version := a.extractBestCVSS(vuln.CVSS)
	if score > 0 {
		vulnDetails.CVSSScore = score
		vulnDetails.CVSSVector = vector
		vulnDetails.CVSSVersion = version
	}

	finding.Vulnerability = vulnDetails

	// Set references
	if vuln.PrimaryURL != "" {
		finding.References = append(finding.References, vuln.PrimaryURL)
	}
	finding.References = append(finding.References, vuln.References...)

	// Set location for package path
	if vuln.PkgPath != "" {
		finding.Location = &ctis.FindingLocation{
			Path: vuln.PkgPath,
		}
	}

	// Generate fingerprint
	finding.Fingerprint = core.GenerateScaFingerprint(vuln.PkgName, vuln.InstalledVersion, vuln.VulnerabilityID)

	// Tags
	finding.Tags = []string{"trivy", target}

	// Filter by min severity
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// convertMisconfig converts a Trivy misconfiguration to a CTIS finding.
func (a *Adapter) convertMisconfig(mc TrivyMisconfig, target string, opts *core.AdapterOptions, idx int) *ctis.Finding {
	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeMisconfiguration,
		Title:    mc.Title,
		Severity: mapTrivySeverity(mc.Severity),
		RuleID:   mc.ID,
		Message:  mc.Message,
	}

	finding.Description = mc.Description

	// Misconfiguration details
	finding.Misconfiguration = &ctis.MisconfigurationDetails{
		PolicyID:   mc.ID,
		PolicyName: mc.Title,
		AVDID:      mc.AVDID,
		Namespace:  mc.Namespace,
	}

	if mc.CauseMetadata != nil {
		finding.Misconfiguration.Provider = mc.CauseMetadata.Provider
		finding.Misconfiguration.Service = mc.CauseMetadata.Service
		finding.Misconfiguration.ResourceName = mc.CauseMetadata.Resource

		if mc.CauseMetadata.StartLine > 0 {
			finding.Location = &ctis.FindingLocation{
				Path:      target,
				StartLine: mc.CauseMetadata.StartLine,
				EndLine:   mc.CauseMetadata.EndLine,
			}
		}
	}

	// Remediation
	if mc.Resolution != "" {
		finding.Remediation = &ctis.Remediation{
			Recommendation: mc.Resolution,
		}
	}

	// References
	if mc.PrimaryURL != "" {
		finding.References = append(finding.References, mc.PrimaryURL)
	}
	finding.References = append(finding.References, mc.References...)

	// Fingerprint
	startLine := 0
	if mc.CauseMetadata != nil {
		startLine = mc.CauseMetadata.StartLine
	}
	finding.Fingerprint = core.GenerateSastFingerprint(target, mc.ID, startLine)

	// Tags
	finding.Tags = []string{"trivy", "misconfiguration", target}

	// Filter by min severity
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// convertSecret converts a Trivy secret finding to a CTIS finding.
func (a *Adapter) convertSecret(s TrivySecret, target string, opts *core.AdapterOptions, idx int) *ctis.Finding {
	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeSecret,
		Title:    s.Title,
		Severity: mapTrivySeverity(s.Severity),
		RuleID:   s.RuleID,
	}

	finding.Secret = &ctis.SecretDetails{
		SecretType: s.Category,
	}

	if s.StartLine > 0 {
		finding.Location = &ctis.FindingLocation{
			Path:      target,
			StartLine: s.StartLine,
			EndLine:   s.EndLine,
		}
	}

	finding.Fingerprint = core.GenerateSecretFingerprint(target, s.RuleID, s.StartLine, s.Match)

	finding.Tags = []string{"trivy", "secret", target}

	// Filter by min severity
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// extractBestCVSS extracts the best (highest) CVSS score from Trivy CVSS data.
func (a *Adapter) extractBestCVSS(cvss TrivyCVSS) (score float64, vector string, version string) {
	if cvss == nil {
		return 0, "", ""
	}

	for _, data := range cvss {
		if data.V3Score > score {
			score = data.V3Score
			vector = data.V3Vector
			version = "3.1"
		}
		if data.V2Score > score && score == 0 {
			score = data.V2Score
			vector = data.V2Vector
			version = "2.0"
		}
	}

	return score, vector, version
}

// mapTrivySeverity maps Trivy severity strings to CTIS severity.
func mapTrivySeverity(s string) ctis.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return ctis.SeverityCritical
	case "HIGH":
		return ctis.SeverityHigh
	case "MEDIUM":
		return ctis.SeverityMedium
	case "LOW":
		return ctis.SeverityLow
	case "UNKNOWN":
		return ctis.SeverityInfo
	default:
		return ctis.SeverityMedium
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

// ParseToCTIS is a convenience function to parse Trivy JSON to CTIS format.
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
