// Package validators provides template validation for different scanner types.
package validators

import (
	"context"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// Regex Safety (ReDoS Prevention)
// =============================================================================

// regexSafetyConfig defines limits for regex validation.
type regexSafetyConfig struct {
	MaxLength          int           // Maximum regex pattern length
	MaxGroupDepth      int           // Maximum nested group depth
	MaxQuantifierWidth int           // Maximum width of quantifiers
	CompileTimeout     time.Duration // Timeout for compile check
}

var defaultRegexSafetyConfig = regexSafetyConfig{
	MaxLength:          1000,
	MaxGroupDepth:      5,
	MaxQuantifierWidth: 100,
	CompileTimeout:     100 * time.Millisecond,
}

// isRegexSafe checks if a regex pattern is safe from ReDoS attacks.
// Returns (safe, reason) where reason explains why it's unsafe.
func isRegexSafe(pattern string) (bool, string) {
	cfg := defaultRegexSafetyConfig

	// Check length
	if len(pattern) > cfg.MaxLength {
		return false, fmt.Sprintf("pattern too long (%d > %d)", len(pattern), cfg.MaxLength)
	}

	// Parse regex syntax tree
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false, fmt.Sprintf("invalid regex syntax: %v", err)
	}

	// Check for dangerous patterns
	if unsafe, reason := checkRegexTree(re, 0, cfg); unsafe {
		return false, reason
	}

	// Test compile with timeout (catches catastrophic backtracking at compile time)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.CompileTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := regexp.Compile(pattern)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return false, fmt.Sprintf("regex compile error: %v", err)
		}
	case <-ctx.Done():
		return false, "regex compile timeout (potentially dangerous)"
	}

	return true, ""
}

// hasNestedQuantifier recursively checks if any subexpression contains a quantifier.
func hasNestedQuantifier(subs []*syntax.Regexp) bool {
	for _, sub := range subs {
		switch sub.Op {
		case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
			return true
		case syntax.OpCapture, syntax.OpConcat:
			// Check children of capture groups and concatenations
			if hasNestedQuantifier(sub.Sub) {
				return true
			}
		case syntax.OpAlternate:
			// Check all branches of alternation
			if hasNestedQuantifier(sub.Sub) {
				return true
			}
		}
	}
	return false
}

// checkRegexTree recursively checks regex AST for dangerous patterns.
func checkRegexTree(re *syntax.Regexp, depth int, cfg regexSafetyConfig) (bool, string) {
	// Check depth
	if depth > cfg.MaxGroupDepth {
		return true, fmt.Sprintf("group nesting too deep (%d > %d)", depth, cfg.MaxGroupDepth)
	}

	// Check for dangerous quantifiers
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
		// Check for nested quantifiers (e.g., (a+)+ or (a*)*) - classic ReDoS
		// We need to recursively check if any descendant has a quantifier
		if hasNestedQuantifier(re.Sub) {
			return true, "nested quantifiers detected (potential ReDoS)"
		}
	case syntax.OpRepeat:
		// Check repeat bounds
		if re.Max > cfg.MaxQuantifierWidth || re.Max == -1 {
			if re.Min > 0 {
				return true, fmt.Sprintf("quantifier width too large (max %d)", cfg.MaxQuantifierWidth)
			}
		}
		// Check for nested quantifiers in repeat as well
		if hasNestedQuantifier(re.Sub) {
			return true, "nested quantifiers in repeat detected (potential ReDoS)"
		}
	case syntax.OpAlternate:
		// Check for overlapping alternations (e.g., (a|ab)+)
		// This is a heuristic - more sophisticated analysis would be needed for full coverage
		if len(re.Sub) > 10 {
			return true, "too many alternations (potential performance issue)"
		}
	}

	// Recursively check sub-expressions
	for _, sub := range re.Sub {
		if unsafe, reason := checkRegexTree(sub, depth+1, cfg); unsafe {
			return true, reason
		}
	}

	return false, ""
}

// ValidationResult represents the result of template validation.
type ValidationResult struct {
	Valid     bool              `json:"valid"`
	Errors    []ValidationError `json:"errors,omitempty"`
	RuleCount int               `json:"rule_count"`
	Metadata  map[string]any    `json:"metadata,omitempty"`
}

// ValidationError represents a single validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// AddError adds an error to the validation result.
func (r *ValidationResult) AddError(field, message, code string) {
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
	r.Valid = false
}

// HasErrors returns true if there are any validation errors.
func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// ErrorMessages returns all error messages as a single string.
func (r *ValidationResult) ErrorMessages() string {
	if len(r.Errors) == 0 {
		return ""
	}
	msgs := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		msgs = append(msgs, fmt.Sprintf("%s: %s", e.Field, e.Message))
	}
	return strings.Join(msgs, "; ")
}

// TemplateValidator defines the interface for scanner-specific validators.
type TemplateValidator interface {
	// Validate validates the template content.
	Validate(content []byte) *ValidationResult

	// CountRules counts the number of rules in the template.
	CountRules(content []byte) int

	// ExtractMetadata extracts scanner-specific metadata from the template.
	ExtractMetadata(content []byte) map[string]any
}

// GetValidator returns the appropriate validator for the template type.
func GetValidator(templateType scannertemplate.TemplateType) TemplateValidator {
	switch templateType {
	case scannertemplate.TemplateTypeNuclei:
		return &NucleiValidator{}
	case scannertemplate.TemplateTypeSemgrep:
		return &SemgrepValidator{}
	case scannertemplate.TemplateTypeGitleaks:
		return &GitleaksValidator{}
	default:
		return nil
	}
}

// ValidateTemplate validates template content based on its type.
func ValidateTemplate(templateType scannertemplate.TemplateType, content []byte) *ValidationResult {
	validator := GetValidator(templateType)
	if validator == nil {
		result := &ValidationResult{Valid: false}
		result.AddError("template_type", "unsupported template type", "UNSUPPORTED_TYPE")
		return result
	}
	return validator.Validate(content)
}

// =============================================================================
// Nuclei Validator
// =============================================================================

// NucleiValidator validates Nuclei template files (YAML).
type NucleiValidator struct{}

// Validate validates Nuclei template content.
func (v *NucleiValidator) Validate(content []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Metadata: make(map[string]any),
	}

	var tpl map[string]any
	if err := yaml.Unmarshal(content, &tpl); err != nil {
		result.AddError("content", fmt.Sprintf("invalid YAML: %v", err), "INVALID_YAML")
		return result
	}

	// Required field: id
	id, ok := tpl["id"]
	if !ok {
		result.AddError("id", "missing required field 'id'", "MISSING_FIELD")
	} else {
		result.Metadata["id"] = id
	}

	// Required field: info
	info, ok := tpl["info"].(map[string]any)
	if !ok {
		result.AddError("info", "missing required field 'info'", "MISSING_FIELD")
	} else {
		// info.name is required
		if name, ok := info["name"]; ok {
			result.Metadata["name"] = name
		} else {
			result.AddError("info.name", "missing template name", "MISSING_FIELD")
		}

		// info.severity is required
		if severity, ok := info["severity"]; ok {
			result.Metadata["severity"] = severity
			// Validate severity value
			if !v.isValidSeverity(fmt.Sprintf("%v", severity)) {
				result.AddError("info.severity", "invalid severity level", "INVALID_VALUE")
			}
		} else {
			result.AddError("info.severity", "missing severity", "MISSING_FIELD")
		}

		// Extract optional metadata
		if author, ok := info["author"]; ok {
			result.Metadata["author"] = author
		}
		if tags, ok := info["tags"]; ok {
			result.Metadata["tags"] = tags
		}
		if description, ok := info["description"]; ok {
			result.Metadata["description"] = description
		}
	}

	// Must have requests, workflows, or other execution blocks
	hasExecution := false
	for _, key := range []string{"requests", "http", "dns", "file", "network", "headless", "ssl", "websocket", "whois", "code", "javascript", "workflows"} {
		if _, ok := tpl[key]; ok {
			hasExecution = true
			result.Metadata["execution_type"] = key
			break
		}
	}
	if !hasExecution {
		result.AddError("requests", "missing execution block (requests, http, dns, etc.)", "MISSING_EXECUTION")
	}

	// Check for potentially dangerous patterns
	if v.hasDangerousPatterns(content) {
		result.AddError("content", "potentially dangerous patterns detected", "DANGEROUS_PATTERN")
	}

	result.RuleCount = 1 // Nuclei templates are typically single templates
	return result
}

// CountRules returns 1 for Nuclei (each file is one template).
func (v *NucleiValidator) CountRules(content []byte) int {
	return 1
}

// ExtractMetadata extracts metadata from Nuclei template.
func (v *NucleiValidator) ExtractMetadata(content []byte) map[string]any {
	result := v.Validate(content)
	return result.Metadata
}

func (v *NucleiValidator) isValidSeverity(severity string) bool {
	severity = strings.ToLower(severity)
	switch severity {
	case "info", "low", "medium", "high", "critical", "unknown":
		return true
	}
	return false
}

func (v *NucleiValidator) hasDangerousPatterns(content []byte) bool {
	contentStr := string(content)
	contentLower := strings.ToLower(contentStr)

	// Exact dangerous strings (case-insensitive)
	dangerousStrings := []string{
		"{{shell(",
		"{{exec(",
		"rm -rf",
		">/dev/",
		"| bash",
		"| sh",
		"|bash",
		"|sh",
		"; bash",
		"; sh",
		"& bash",
		"& sh",
		"`bash",
		"`sh",
		"$(bash",
		"$(sh",
		"mkfifo",      // Named pipe for reverse shells
		"/etc/passwd", // Sensitive file access
		"/etc/shadow",
		"nc -e", // Netcat reverse shell
		"ncat -e",
		"python -c", // Python one-liners
		"python3 -c",
		"perl -e",   // Perl one-liners
		"ruby -e",   // Ruby one-liners
		"php -r",    // PHP one-liners
		"base64 -d", // Base64 decode (often used to obfuscate)
		"eval(",
		"exec(",
	}

	for _, pattern := range dangerousStrings {
		if strings.Contains(contentLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Regex patterns for more sophisticated detection
	dangerousRegex := []*regexp.Regexp{
		// Curl/wget piped to shell
		regexp.MustCompile(`(?i)(curl|wget)\s+[^\n]*\|\s*(ba)?sh`),
		// Reverse shell patterns
		regexp.MustCompile(`(?i)/dev/(tcp|udp)/`),
		// Base64 encoded commands
		regexp.MustCompile(`(?i)echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64`),
		// Environment variable exfiltration
		regexp.MustCompile(`(?i)\$\{?[A-Z_]+\}?\s*[|>]`),
		// Encoded/obfuscated shell commands
		regexp.MustCompile(`(?i)\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}`),
		// Process substitution
		regexp.MustCompile(`<\(\s*(bash|sh|curl|wget)`),
	}

	for _, re := range dangerousRegex {
		if re.MatchString(contentStr) {
			return true
		}
	}

	return false
}

// =============================================================================
// Semgrep Validator
// =============================================================================

// SemgrepValidator validates Semgrep rule files (YAML).
type SemgrepValidator struct{}

// Validate validates Semgrep rule content.
func (v *SemgrepValidator) Validate(content []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Metadata: make(map[string]any),
	}

	var config map[string]any
	if err := yaml.Unmarshal(content, &config); err != nil {
		result.AddError("content", fmt.Sprintf("invalid YAML: %v", err), "INVALID_YAML")
		return result
	}

	// Must have 'rules' array
	rulesRaw, ok := config["rules"]
	if !ok {
		result.AddError("rules", "missing required 'rules' array", "MISSING_RULES")
		return result
	}

	rules, ok := rulesRaw.([]any)
	if !ok {
		result.AddError("rules", "'rules' must be an array", "INVALID_TYPE")
		return result
	}

	if len(rules) == 0 {
		result.AddError("rules", "must contain at least one rule", "EMPTY_RULES")
		return result
	}

	// Validate each rule
	var ruleIDs []string
	for i, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			result.AddError(fmt.Sprintf("rules[%d]", i), "rule must be an object", "INVALID_TYPE")
			continue
		}

		// Required: id
		if id, ok := rule["id"].(string); ok {
			ruleIDs = append(ruleIDs, id)
		} else {
			result.AddError(fmt.Sprintf("rules[%d].id", i), "missing rule id", "MISSING_FIELD")
		}

		// Required: pattern or patterns or pattern-either, etc.
		hasPattern := false
		for _, key := range []string{"pattern", "patterns", "pattern-either", "pattern-regex"} {
			if _, ok := rule[key]; ok {
				hasPattern = true
				break
			}
		}
		if !hasPattern {
			result.AddError(fmt.Sprintf("rules[%d].pattern", i), "missing pattern", "MISSING_PATTERN")
		}

		// Required: message
		if _, ok := rule["message"]; !ok {
			result.AddError(fmt.Sprintf("rules[%d].message", i), "missing message", "MISSING_FIELD")
		}

		// Required: languages
		if _, ok := rule["languages"]; !ok {
			result.AddError(fmt.Sprintf("rules[%d].languages", i), "missing languages", "MISSING_FIELD")
		}

		// Required: severity
		if severity, ok := rule["severity"].(string); ok {
			if !v.isValidSeverity(severity) {
				result.AddError(fmt.Sprintf("rules[%d].severity", i), "invalid severity", "INVALID_VALUE")
			}
		} else {
			result.AddError(fmt.Sprintf("rules[%d].severity", i), "missing severity", "MISSING_FIELD")
		}
	}

	result.RuleCount = len(rules)
	result.Metadata["rule_ids"] = ruleIDs
	result.Metadata["rule_count"] = len(rules)

	return result
}

// CountRules counts the number of rules in the Semgrep config.
func (v *SemgrepValidator) CountRules(content []byte) int {
	var config map[string]any
	if err := yaml.Unmarshal(content, &config); err != nil {
		return 0
	}
	if rules, ok := config["rules"].([]any); ok {
		return len(rules)
	}
	return 0
}

// ExtractMetadata extracts metadata from Semgrep rules.
func (v *SemgrepValidator) ExtractMetadata(content []byte) map[string]any {
	result := v.Validate(content)
	return result.Metadata
}

func (v *SemgrepValidator) isValidSeverity(severity string) bool {
	severity = strings.ToUpper(severity)
	switch severity {
	case "INFO", "WARNING", "ERROR":
		return true
	}
	return false
}

// =============================================================================
// Gitleaks Validator
// =============================================================================

// GitleaksValidator validates Gitleaks config files (TOML).
type GitleaksValidator struct{}

// Validate validates Gitleaks config content.
func (v *GitleaksValidator) Validate(content []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Metadata: make(map[string]any),
	}

	// Parse TOML manually (simplified - in production use a TOML library)
	contentStr := string(content)

	// Check for [[rules]] sections
	ruleCount := strings.Count(contentStr, "[[rules]]")
	if ruleCount == 0 {
		result.AddError("rules", "must contain at least one [[rules]] section", "MISSING_RULES")
		return result
	}

	// Extract and validate rules
	rules := v.extractRules(contentStr)
	var ruleIDs []string

	for i, rule := range rules {
		// Required: id
		if id, ok := rule["id"]; ok {
			ruleIDs = append(ruleIDs, id)
		} else {
			result.AddError(fmt.Sprintf("rules[%d].id", i), "missing rule id", "MISSING_FIELD")
		}

		// Required: regex or path
		hasDetection := false
		if regex, ok := rule["regex"]; ok {
			hasDetection = true
			// Validate regex syntax AND safety (ReDoS prevention)
			if safe, reason := isRegexSafe(regex); !safe {
				result.AddError(fmt.Sprintf("rules[%d].regex", i), fmt.Sprintf("unsafe regex: %s", reason), "UNSAFE_REGEX")
			} else if _, err := regexp.Compile(regex); err != nil {
				result.AddError(fmt.Sprintf("rules[%d].regex", i), fmt.Sprintf("invalid regex: %v", err), "INVALID_REGEX")
			}
		}
		if _, ok := rule["path"]; ok {
			hasDetection = true
		}
		if !hasDetection {
			result.AddError(fmt.Sprintf("rules[%d]", i), "missing regex or path", "MISSING_DETECTION")
		}
	}

	result.RuleCount = len(rules)
	result.Metadata["rule_ids"] = ruleIDs
	result.Metadata["rule_count"] = len(rules)

	return result
}

// CountRules counts the number of rules in the Gitleaks config.
func (v *GitleaksValidator) CountRules(content []byte) int {
	return strings.Count(string(content), "[[rules]]")
}

// ExtractMetadata extracts metadata from Gitleaks config.
func (v *GitleaksValidator) ExtractMetadata(content []byte) map[string]any {
	result := v.Validate(content)
	return result.Metadata
}

// extractRules extracts rules from TOML content (simplified parser).
func (v *GitleaksValidator) extractRules(content string) []map[string]string {
	var rules []map[string]string

	// Split by [[rules]]
	parts := strings.Split(content, "[[rules]]")
	for i, part := range parts {
		if i == 0 {
			continue // Skip content before first [[rules]]
		}

		rule := make(map[string]string)

		// Extract key-value pairs (simplified)
		lines := strings.Split(part, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[[") {
				continue
			}

			// Parse key = value
			if idx := strings.Index(line, "="); idx > 0 {
				key := strings.TrimSpace(line[:idx])
				value := strings.TrimSpace(line[idx+1:])
				// Remove quotes
				value = strings.Trim(value, `"'`)
				// Handle triple-quoted strings
				value = strings.Trim(value, "`")
				rule[key] = value
			}
		}

		if len(rule) > 0 {
			rules = append(rules, rule)
		}
	}

	return rules
}
