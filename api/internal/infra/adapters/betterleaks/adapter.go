package betterleaks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/infra/adapters/core"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
)

// Adapter converts Betterleaks JSON reports to CTIS.
type Adapter struct{}

// NewAdapter creates a new Betterleaks adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return tooldom.NameBetterleaks
}

// InputFormats returns supported input formats.
func (a *Adapter) InputFormats() []string {
	// "gitleaks" is the report format betterleaks v1 kept, so reports
	// named with the old format still convert.
	return []string{"betterleaks", "gitleaks", "json"}
}

// OutputFormat returns the output format.
func (a *Adapter) OutputFormat() string {
	return "ctis"
}

// CanConvert checks if the input can be converted.
func (a *Adapter) CanConvert(input []byte) bool {
	var findings []Finding
	if err := json.Unmarshal(input, &findings); err != nil {
		return false
	}
	// The report is a JSON array with RuleID and File fields
	if len(findings) == 0 {
		return false
	}
	return findings[0].RuleID != "" && findings[0].File != ""
}

// Convert transforms a Betterleaks JSON report to a CTIS Report.
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var findings []Finding
	if err := json.Unmarshal(input, &findings); err != nil {
		return nil, fmt.Errorf("parse betterleaks: %w", err)
	}

	report := ctis.NewReport()
	report.Metadata.SourceType = "scanner"
	report.Tool = &ctis.Tool{
		Name:         tooldom.NameBetterleaks,
		Vendor:       "Betterleaks",
		Capabilities: []string{"secret"},
		InfoURL:      "https://github.com/betterleaks/betterleaks",
	}

	if opts != nil && opts.Repository != "" {
		report.Metadata.Scope = &ctis.Scope{
			Name: opts.Repository,
		}
	}

	for i, f := range findings {
		finding := a.convertFinding(f, opts, i)
		if finding != nil {
			report.Findings = append(report.Findings, *finding)
		}
	}

	return report, nil
}

// convertFinding converts a report finding to a CTIS finding.
func (a *Adapter) convertFinding(gf Finding, opts *core.AdapterOptions, idx int) *ctis.Finding {
	finding := &ctis.Finding{
		ID:       fmt.Sprintf("finding-%d", idx+1),
		Type:     ctis.FindingTypeSecret,
		Title:    gf.Description,
		Severity: mapSeverity(gf.RuleID),
		RuleID:   gf.RuleID,
	}

	finding.Message = fmt.Sprintf("Secret detected: %s in %s", gf.Description, gf.File)

	// Location
	finding.Location = &ctis.FindingLocation{
		Path:        gf.File,
		StartLine:   gf.StartLine,
		EndLine:     gf.EndLine,
		StartColumn: gf.StartColumn,
		EndColumn:   gf.EndColumn,
	}

	// Set commit info on location
	if gf.Commit != "" {
		finding.Location.CommitSHA = gf.Commit
	}

	// Secret details
	secretDetails := &ctis.SecretDetails{
		SecretType: ruleIDToSecretType(gf.RuleID),
		Entropy:    gf.Entropy,
	}

	// Mask the secret value
	if gf.Secret != "" {
		secretDetails.MaskedValue = maskSecret(gf.Secret)
		secretDetails.Length = len(gf.Secret)
	}

	// Detect service from rule ID
	secretDetails.Service = ruleIDToService(gf.RuleID)

	finding.Secret = secretDetails

	// Git author information
	if gf.Author != "" {
		finding.Author = gf.Author
	}
	if gf.Email != "" {
		finding.AuthorEmail = gf.Email
	}

	// Fingerprint
	if gf.Fingerprint != "" {
		finding.Fingerprint = gf.Fingerprint
	} else {
		finding.Fingerprint = core.GenerateSecretFingerprint(gf.File, gf.RuleID, gf.StartLine, gf.Secret)
	}

	// Tags
	finding.Tags = []string{tooldom.NameBetterleaks, "secret"}
	if len(gf.Tags) > 0 {
		finding.Tags = append(finding.Tags, gf.Tags...)
	}

	// Confidence is high (pattern-based detection)
	finding.Confidence = 85

	// Filter by min severity
	if opts != nil && opts.MinSeverity != "" {
		if !meetsMinSeverity(finding.Severity, ctis.Severity(opts.MinSeverity)) {
			return nil
		}
	}

	return finding
}

// mapSeverity maps rule IDs to severity.
// The report carries no severity, so we infer it from the rule type.
func mapSeverity(ruleID string) ctis.Severity {
	id := strings.ToLower(ruleID)

	// Critical: cloud provider credentials, private keys
	criticalPatterns := []string{
		"aws-access-key", "aws-secret", "gcp-service-account",
		"azure-", "private-key", "jwt-", "github-pat",
		"github-fine-grained", "gitlab-pat",
	}
	for _, p := range criticalPatterns {
		if strings.Contains(id, p) {
			return ctis.SeverityCritical
		}
	}

	// High: API keys, tokens, passwords
	highPatterns := []string{
		"api-key", "api-token", "access-token", "secret-key",
		"password", "credential", "auth-token", "bearer",
		"stripe", "twilio", "sendgrid", "slack-token",
	}
	for _, p := range highPatterns {
		if strings.Contains(id, p) {
			return ctis.SeverityHigh
		}
	}

	// Default to high for any secret
	return ctis.SeverityHigh
}

// ruleIDToSecretType maps rule ID to a secret type category.
func ruleIDToSecretType(ruleID string) string {
	id := strings.ToLower(ruleID)

	if strings.Contains(id, "private-key") {
		return "private_key"
	}
	if strings.Contains(id, "password") {
		return "password"
	}
	if strings.Contains(id, "token") {
		return "token"
	}
	if strings.Contains(id, "api-key") || strings.Contains(id, "api_key") {
		return "api_key"
	}
	if strings.Contains(id, "secret") {
		return "secret"
	}
	if strings.Contains(id, "certificate") || strings.Contains(id, "cert") {
		return "certificate"
	}

	return "credential"
}

// ruleIDToService maps rule ID to a service name.
func ruleIDToService(ruleID string) string {
	id := strings.ToLower(ruleID)

	services := map[string]string{
		"aws":      "aws",
		"gcp":      "gcp",
		"azure":    "azure",
		"github":   "github",
		"gitlab":   "gitlab",
		"slack":    "slack",
		"stripe":   "stripe",
		"twilio":   "twilio",
		"sendgrid": "sendgrid",
		"mailgun":  "mailgun",
		"heroku":   "heroku",
		"npm":      "npm",
		"pypi":     "pypi",
		"docker":   "docker",
		"firebase": "firebase",
		"telegram": "telegram",
		"discord":  "discord",
		"shopify":  "shopify",
	}

	for pattern, service := range services {
		if strings.Contains(id, pattern) {
			return service
		}
	}

	return ""
}

// maskSecret masks a secret value, showing only first and last 4 characters.
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
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

// ParseToCTIS is a convenience function to parse a Betterleaks JSON report to CTIS format.
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
