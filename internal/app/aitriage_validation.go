package app

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/openctemio/api/pkg/domain/aitriage"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
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
func (v *TriageOutputValidator) ValidateAndSanitize(content string) (*aitriage.TriageAnalysis, error) {
	// Parse JSON
	var raw map[string]any
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}

	analysis := &aitriage.TriageAnalysis{
		RawResponse: raw,
	}

	// Validate and extract severity_assessment
	if severity, ok := raw["severity_assessment"].(string); ok {
		severity = strings.ToLower(strings.TrimSpace(severity))
		if !v.validSeverities[severity] {
			severity = riskLevelMedium // Default to medium if invalid
		}
		analysis.SeverityAssessment = severity
	} else {
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

	// Validate exploitability
	if exploitability, ok := raw["exploitability"].(string); ok {
		exploitability = strings.ToLower(strings.TrimSpace(exploitability))
		if !v.validExploitabilities[exploitability] {
			exploitability = riskLevelMedium
		}
		analysis.Exploitability = aitriage.Exploitability(exploitability)
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
func (v *TriageOutputValidator) validateRemediationSteps(steps []any) []aitriage.RemediationStep {
	result := make([]aitriage.RemediationStep, 0, len(steps))

	validEfforts := map[string]bool{"low": true, riskLevelMedium: true, "high": true}

	for i, s := range steps {
		if i >= v.maxSteps {
			break
		}

		stepMap, ok := s.(map[string]any)
		if !ok {
			continue
		}

		step := aitriage.RemediationStep{
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
// Prompt Injection Protection
// =============================================================================

// PromptSanitizer sanitizes user-provided data before including in prompts.
type PromptSanitizer struct {
	maxFieldLength int
}

// NewPromptSanitizer creates a new prompt sanitizer.
func NewPromptSanitizer() *PromptSanitizer {
	return &PromptSanitizer{
		maxFieldLength: 10000, // Max 10KB per field
	}
}

// SanitizeForPrompt sanitizes a string for inclusion in an LLM prompt.
// Applies unicode normalization to prevent bypass via homoglyphs and special characters.
func (s *PromptSanitizer) SanitizeForPrompt(text string) string {
	if text == "" {
		return ""
	}

	// SECURITY: Normalize unicode to prevent homoglyph attacks
	// Attackers can use characters like "ｉｇｎｏｒｅ" (fullwidth) instead of "ignore"
	// or "іgnore" (Cyrillic 'і') to bypass ASCII-based regex filters
	text = normalizeUnicode(text)

	// Truncate if too long (after normalization to avoid truncating in middle of char)
	if len(text) > s.maxFieldLength {
		text = text[:s.maxFieldLength] + "\n[TRUNCATED]"
	}

	// Remove potential prompt injection patterns
	// These patterns could trick the LLM into ignoring instructions
	// SECURITY: Expanded pattern list to cover more injection techniques
	injectionPatterns := []string{
		// Direct instruction override
		`(?i)ignore (previous|above|all|prior|system) instructions?`,
		`(?i)disregard (previous|above|all|prior|system) instructions?`,
		`(?i)forget (previous|above|all|prior|system) instructions?`,
		`(?i)override (previous|above|all|prior|system) instructions?`,
		`(?i)bypass (previous|above|all|prior|system) instructions?`,
		`(?i)skip (previous|above|all|prior) instructions?`,
		// New instruction injection
		`(?i)new instructions?:`,
		`(?i)updated instructions?:`,
		`(?i)revised instructions?:`,
		`(?i)actual instructions?:`,
		`(?i)real instructions?:`,
		// System prompt access/override
		`(?i)system prompt:`,
		`(?i)system message:`,
		`(?i)output (the|your) (system|initial) (prompt|instructions?)`,
		`(?i)reveal (the|your) (system|initial) (prompt|instructions?)`,
		`(?i)show (the|your) (system|initial) (prompt|instructions?)`,
		`(?i)print (the|your) (system|initial) (prompt|instructions?)`,
		// Role/persona manipulation
		`(?i)you are now`,
		`(?i)you're now`,
		`(?i)from now on,? you`,
		`(?i)act as if`,
		`(?i)pretend (that|to be|you)`,
		`(?i)roleplay as`,
		`(?i)behave as`,
		`(?i)respond as`,
		`(?i)switch (to|into) (a|the)? ?(\w+)? ?mode`,
		`(?i)enter (\w+)? ?mode`,
		`(?i)enable (\w+)? ?mode`,
		// Special tokens/markers (model-specific)
		`(?i)\[SYSTEM\]`,
		`(?i)\[INST\]`,
		`(?i)\[/INST\]`,
		`(?i)<\|im_start\|>`,
		`(?i)<\|im_end\|>`,
		`(?i)<\|system\|>`,
		`(?i)<\|user\|>`,
		`(?i)<\|assistant\|>`,
		`(?i)<<SYS>>`,
		`(?i)<</SYS>>`,
		`(?i)### (System|Instruction|Human|Assistant):?`,
		// Tool call injection
		`(?i)<\|tool_use\|>`,
		`(?i)<function_call>`,
		`(?i)<tool_call>`,
		// Delimiter escape attempts
		`(?i)"""[\s\S]*"""`,
		`(?i)'''[\s\S]*'''`,
		// Output manipulation
		`(?i)always (respond|answer|output|say|reply)`,
		`(?i)never (respond|answer|output|say|reply)`,
		`(?i)only (respond|answer|output|say|reply)`,
		// Security bypass attempts
		`(?i)jailbreak`,
		`(?i)dan mode`,
		`(?i)developer mode`,
		`(?i)sudo mode`,
		`(?i)admin mode`,
	}

	for _, pattern := range injectionPatterns {
		re := regexp.MustCompile(pattern)
		text = re.ReplaceAllString(text, "[FILTERED]")
	}

	return text
}

// SanitizeCodeSnippet sanitizes a code snippet for inclusion in prompts.
func (s *PromptSanitizer) SanitizeCodeSnippet(code string) string {
	// Limit code size
	maxCodeLength := 5000
	if len(code) > maxCodeLength {
		code = code[:maxCodeLength] + "\n// [TRUNCATED]"
	}

	return code
}

// normalizeUnicode normalizes unicode text to prevent homoglyph attacks.
// This converts characters to their closest ASCII equivalents where possible,
// and removes non-printable control characters.
//
// Examples of attacks this prevents:
// - Fullwidth characters: "ｉｇｎｏｒｅ" → "ignore"
// - Cyrillic lookalikes: "іgnore" (Cyrillic і) → "ignore"
// - Mathematical symbols: "𝓲𝓷𝓼𝓽𝓻𝓾𝓬𝓽𝓲𝓸𝓷" → "instruction"
// - Control characters: Zero-width spaces, direction overrides
func normalizeUnicode(text string) string {
	// Step 1: Apply NFKC normalization
	// This decomposes characters and then recomposes them in a canonical way.
	// It converts fullwidth, halfwidth, and compatibility characters to their
	// standard equivalents. E.g., "ｉｇｎｏｒｅ" → "ignore"
	nfkcTransformer := transform.Chain(
		norm.NFKC,
		// Step 2: Remove non-printable and control characters
		runes.Remove(runes.Predicate(func(r rune) bool {
			// Remove invisible/control characters that could be used to hide text
			// Keep basic ASCII printables, newlines, tabs
			if r == '\n' || r == '\r' || r == '\t' {
				return false // Keep these
			}
			// Remove control characters (except the ones above)
			if unicode.IsControl(r) {
				return true
			}
			// Remove zero-width characters
			if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
				return true
			}
			// Remove directional overrides (can hide text direction)
			if r >= '\u202A' && r <= '\u202E' {
				return true
			}
			// Remove homoglyphs that look like basic ASCII but aren't
			// These are commonly used in prompt injection
			return false
		})),
	)

	result, _, err := transform.String(nfkcTransformer, text)
	if err != nil {
		// If transformation fails, return original text (fail-safe)
		return text
	}

	// Step 3: Additional homoglyph normalization for Cyrillic lookalikes
	// NFKC doesn't catch all cases, especially Cyrillic characters that
	// look identical to Latin characters
	homoglyphReplacements := map[rune]rune{
		'а': 'a', // Cyrillic
		'е': 'e', // Cyrillic
		'і': 'i', // Cyrillic
		'о': 'o', // Cyrillic
		'р': 'p', // Cyrillic
		'с': 'c', // Cyrillic
		'у': 'y', // Cyrillic
		'х': 'x', // Cyrillic
		'А': 'A', // Cyrillic
		'В': 'B', // Cyrillic
		'Е': 'E', // Cyrillic
		'К': 'K', // Cyrillic
		'М': 'M', // Cyrillic
		'Н': 'H', // Cyrillic
		'О': 'O', // Cyrillic
		'Р': 'P', // Cyrillic
		'С': 'C', // Cyrillic
		'Т': 'T', // Cyrillic
		'У': 'Y', // Cyrillic
		'Х': 'X', // Cyrillic
	}

	var sb strings.Builder
	sb.Grow(len(result))
	for _, r := range result {
		if replacement, ok := homoglyphReplacements[r]; ok {
			sb.WriteRune(replacement)
		} else {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

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
