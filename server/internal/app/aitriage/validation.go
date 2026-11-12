package aitriage

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/aiprompt"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
)

// =============================================================================
// Output Validation - Validates LLM responses
// =============================================================================

// TriageOutputValidator validates LLM triage output for security and correctness.
type TriageOutputValidator struct {
	maxSummaryLength       int
	maxJustificationLength int
	maxSteps               int
	maxRelatedItems        int
	validSeverities        map[string]bool
	validExploitabilities  map[string]bool
}

// NewTriageOutputValidator creates a new validator with default settings.
func NewTriageOutputValidator() *TriageOutputValidator {
	return &TriageOutputValidator{
		maxSummaryLength:       2000,
		maxJustificationLength: 5000,
		maxSteps:               20,
		maxRelatedItems:        50,
		validSeverities: map[string]bool{
			"critical": true, "high": true, riskLevelMedium: true, "low": true, "info": true,
		},
		validExploitabilities: map[string]bool{
			"high": true, riskLevelMedium: true, "low": true, "theoretical": true,
		},
	}
}

// ValidateAndSanitize validates and sanitizes the LLM output.
// Returns a sanitized analysis or an error if validation fails.
func (v *TriageOutputValidator) ValidateAndSanitize(content string) (*aitriagedom.TriageAnalysis, error) {
	// Parse JSON
	var raw map[string]any
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}

	analysis := &aitriagedom.TriageAnalysis{
		RawResponse: raw,
	}

	// Validate and extract severity_assessment.
	// SECURITY: a malicious finding title can prompt-inject the LLM
	// into emitting an out-of-set severity (e.g. "informational" via a
	// jailbreak). The previous behaviour silently coerced to "medium"
	// — that hid the manipulation. We still default to medium so the
	// existing scan workflow keeps moving, but flag a ValidationWarning so
	// downstream logic can refuse to auto-apply this triage to the
	// finding's persisted severity until a human reviews it.
	if severity, ok := raw["severity_assessment"].(string); ok {
		raw := strings.ToLower(strings.TrimSpace(severity))
		if !v.validSeverities[raw] {
			analysis.ValidationWarnings = append(analysis.ValidationWarnings,
				fmt.Sprintf("severity_assessment %q is not in the validated set; defaulted to %q — flag for human review", severity, riskLevelMedium))
			raw = riskLevelMedium
		}
		analysis.SeverityAssessment = raw
	} else {
		analysis.ValidationWarnings = append(analysis.ValidationWarnings,
			"severity_assessment missing or non-string; defaulted to medium")
		analysis.SeverityAssessment = riskLevelMedium
	}

	// Validate severity_justification (sanitize and truncate)
	if justification, ok := raw["severity_justification"].(string); ok {
		analysis.SeverityJustification = v.sanitizeText(justification, v.maxJustificationLength)
	}

	// Validate risk_score (must be 0-100)
	if score, ok := raw["risk_score"].(float64); ok {
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		analysis.RiskScore = score
	}

	// Validate exploitability — same fail-soft-with-warning pattern
	// as severity_assessment above. Out-of-set values from the LLM
	// are flagged so downstream code can require human review before
	// they affect priority ranking or auto-remediation actions.
	if exploitability, ok := raw["exploitability"].(string); ok {
		clean := strings.ToLower(strings.TrimSpace(exploitability))
		if !v.validExploitabilities[clean] {
			analysis.ValidationWarnings = append(analysis.ValidationWarnings,
				fmt.Sprintf("exploitability %q is not in the validated set; defaulted to %q — flag for human review", exploitability, riskLevelMedium))
			clean = riskLevelMedium
		}
		analysis.Exploitability = aitriagedom.Exploitability(clean)
	}

	// Validate exploitability_details
	if details, ok := raw["exploitability_details"].(string); ok {
		analysis.ExploitabilityDetails = v.sanitizeText(details, v.maxJustificationLength)
	}

	// Validate business_impact
	if impact, ok := raw["business_impact"].(string); ok {
		analysis.BusinessImpact = v.sanitizeText(impact, v.maxJustificationLength)
	}

	// Validate priority_rank (must be 1-100)
	if rank, ok := raw["priority_rank"].(float64); ok {
		rankInt := int(rank)
		if rankInt < 1 {
			rankInt = 1
		}
		if rankInt > 100 {
			rankInt = 100
		}
		analysis.PriorityRank = rankInt
	} else {
		analysis.PriorityRank = 50 // Default middle priority
	}

	// Validate false_positive_likelihood (must be 0-1)
	if likelihood, ok := raw["false_positive_likelihood"].(float64); ok {
		if likelihood < 0 {
			likelihood = 0
		}
		if likelihood > 1 {
			likelihood = 1
		}
		analysis.FalsePositiveLikelihood = likelihood
	}

	// Validate false_positive_reason
	if reason, ok := raw["false_positive_reason"].(string); ok {
		analysis.FalsePositiveReason = v.sanitizeText(reason, v.maxJustificationLength)
	}

	// Validate summary
	if summary, ok := raw["summary"].(string); ok {
		analysis.Summary = v.sanitizeText(summary, v.maxSummaryLength)
	}

	// Validate remediation_steps
	if steps, ok := raw["remediation_steps"].([]any); ok {
		analysis.RemediationSteps = v.validateRemediationSteps(steps)
	}

	// Validate related_cves
	if cves, ok := raw["related_cves"].([]any); ok {
		analysis.RelatedCVEs = v.validateCVEs(cves)
	}

	// Validate related_cwes
	if cwes, ok := raw["related_cwes"].([]any); ok {
		analysis.RelatedCWEs = v.validateCWEs(cwes)
	}

	return analysis, nil
}

// sanitizeText sanitizes and truncates text.
func (v *TriageOutputValidator) sanitizeText(text string, maxLen int) string {
	// Remove potential script injection
	text = strings.TrimSpace(text)

	// Remove HTML/script tags (basic protection)
	text = stripHTMLTags(text)

	// Truncate if too long
	if len(text) > maxLen {
		text = text[:maxLen] + "..."
	}

	return text
}

// validateRemediationSteps validates and sanitizes remediation steps.
func (v *TriageOutputValidator) validateRemediationSteps(steps []any) []aitriagedom.RemediationStep {
	result := make([]aitriagedom.RemediationStep, 0, len(steps))

	validEfforts := map[string]bool{"low": true, riskLevelMedium: true, "high": true}

	for i, s := range steps {
		if i >= v.maxSteps {
			break
		}

		stepMap, ok := s.(map[string]any)
		if !ok {
			continue
		}

		step := aitriagedom.RemediationStep{
			Step: i + 1,
		}

		if stepNum, ok := stepMap["step"].(float64); ok {
			step.Step = int(stepNum)
		}

		if desc, ok := stepMap["description"].(string); ok {
			step.Description = v.sanitizeText(desc, 1000)
		}

		if effort, ok := stepMap["effort"].(string); ok {
			effort = strings.ToLower(strings.TrimSpace(effort))
			if validEfforts[effort] {
				step.Effort = effort
			} else {
				step.Effort = riskLevelMedium
			}
		}

		if step.Description != "" {
			result = append(result, step)
		}
	}

	return result
}

// validateCVEs validates CVE identifiers.
func (v *TriageOutputValidator) validateCVEs(cves []any) []string {
	cvePattern := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	result := make([]string, 0)

	for _, c := range cves {
		if len(result) >= v.maxRelatedItems {
			break
		}
		if cve, ok := c.(string); ok {
			cve = strings.TrimSpace(strings.ToUpper(cve))
			if cvePattern.MatchString(cve) {
				result = append(result, cve)
			}
		}
	}

	return result
}

// validateCWEs validates CWE identifiers.
func (v *TriageOutputValidator) validateCWEs(cwes []any) []string {
	cwePattern := regexp.MustCompile(`^CWE-\d+$`)
	result := make([]string, 0)

	for _, c := range cwes {
		if len(result) >= v.maxRelatedItems {
			break
		}
		if cwe, ok := c.(string); ok {
			cwe = strings.TrimSpace(strings.ToUpper(cwe))
			if cwePattern.MatchString(cwe) {
				result = append(result, cwe)
			}
		}
	}

	return result
}

// stripHTMLTags removes HTML tags from text (basic XSS protection).
func stripHTMLTags(s string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	s = re.ReplaceAllString(s, "")

	// Remove script-like patterns
	scriptPatterns := []string{
		`javascript:`,
		`data:text/html`,
		`vbscript:`,
		`on\w+\s*=`,
	}

	for _, pattern := range scriptPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		s = re.ReplaceAllString(s, "")
	}

	return s
}

// =============================================================================
// Prompt Injection Protection (shared with the AI context bundle: aiprompt)
// =============================================================================

// PromptSanitizer sanitizes user-provided data before including in prompts.
type PromptSanitizer = aiprompt.Sanitizer

// NewPromptSanitizer creates a new prompt sanitizer.
func NewPromptSanitizer() *PromptSanitizer { return aiprompt.NewSanitizer() }

// filteredMarker replaces text that matched a known prompt-injection pattern.
const filteredMarker = aiprompt.FilteredMarker

// newPromptFence returns a fence with a fresh 128-bit nonce.
func newPromptFence() aiprompt.Fence { return aiprompt.NewFence() }

// =============================================================================
// Token Limit Checker
// =============================================================================

// TokenLimitError is returned when token limit is exceeded.
type TokenLimitError struct {
	Used  int
	Limit int
}

func (e *TokenLimitError) Error() string {
	return fmt.Sprintf("monthly token limit exceeded: used %d of %d", e.Used, e.Limit)
}

// CheckTokenLimit checks if a tenant has exceeded their monthly token limit.
// Returns nil if within limit, TokenLimitError if exceeded.
func CheckTokenLimit(usedTokens, limitTokens int) error {
	if limitTokens <= 0 {
		// No limit set
		return nil
	}

	if usedTokens >= limitTokens {
		return &TokenLimitError{
			Used:  usedTokens,
			Limit: limitTokens,
		}
	}

	return nil
}
