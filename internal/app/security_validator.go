// Package app provides the security validator service for validating
// pipeline steps, scan configurations, and command payloads to prevent
// command injection and other security vulnerabilities.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
)

// ValidationResult represents the result of a validation.
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string
	Message string
	Code    string
}

// SecurityValidator provides validation for security-sensitive operations.
// It validates tool names, capabilities, and configurations against registered
// tools to prevent command injection and unauthorized access.
type SecurityValidator struct {
	toolRepo tool.Repository
	logger   *logger.Logger

	// Cache of allowed capabilities (loaded from DB + defaults)
	allowedCapabilities []string
	capabilitiesMu      sync.RWMutex
	capabilitiesLoaded  time.Time
	capabilitiesTTL     time.Duration
}

// Default capabilities that are always allowed (fallback if DB is empty)
var defaultCapabilities = []string{
	"scan",
	"recon",
	"web",
	"network",
	"host",
	"container",
	"code",
	"sast",
	"dast",
	"secrets",
	"compliance",
	"vulnerability",
	"cloud",
	"api",
	"mobile",
	"iac",
	"sbom",
	// Additional common capabilities
	"discovery",
	"asset",
	"http",
	"screenshot",
	"enumeration",
	"fingerprint",
	"fuzzing",
	"subdomain",
	"port",
}

// NewSecurityValidator creates a new SecurityValidator.
func NewSecurityValidator(toolRepo tool.Repository, log *logger.Logger) *SecurityValidator {
	sv := &SecurityValidator{
		toolRepo:            toolRepo,
		logger:              log.With("service", "security_validator"),
		allowedCapabilities: defaultCapabilities,
		capabilitiesTTL:     5 * time.Minute, // Refresh every 5 minutes
	}

	// Load capabilities from DB on startup (non-blocking)
	go sv.refreshCapabilities()

	return sv
}

// refreshCapabilities loads capabilities from the database and merges with defaults.
func (v *SecurityValidator) refreshCapabilities() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbCaps, err := v.toolRepo.GetAllCapabilities(ctx)
	if err != nil {
		v.logger.Warn("failed to load capabilities from DB, using defaults", "error", err)
		return
	}

	// Merge DB capabilities with defaults (ensure defaults are always included)
	merged := make(map[string]bool)
	for _, cap := range defaultCapabilities {
		merged[strings.ToLower(cap)] = true
	}
	for _, cap := range dbCaps {
		merged[strings.ToLower(cap)] = true
	}

	// Convert to slice
	capabilities := make([]string, 0, len(merged))
	for cap := range merged {
		capabilities = append(capabilities, cap)
	}

	// Update cache
	v.capabilitiesMu.Lock()
	v.allowedCapabilities = capabilities
	v.capabilitiesLoaded = time.Now()
	v.capabilitiesMu.Unlock()

	v.logger.Debug("capabilities cache refreshed", "count", len(capabilities))
}

// getCapabilities returns allowed capabilities, refreshing if stale.
func (v *SecurityValidator) getCapabilities() []string {
	v.capabilitiesMu.RLock()
	if time.Since(v.capabilitiesLoaded) < v.capabilitiesTTL {
		caps := v.allowedCapabilities
		v.capabilitiesMu.RUnlock()
		return caps
	}
	v.capabilitiesMu.RUnlock()

	// Refresh in background, return current cache
	go v.refreshCapabilities()

	v.capabilitiesMu.RLock()
	defer v.capabilitiesMu.RUnlock()
	return v.allowedCapabilities
}

// addValidationError is a helper to add an error to a validation result.
func addValidationError(r *ValidationResult, field, message, code string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// ValidateStepConfig validates a pipeline step's tool name and configuration.
// This is called before creating a pipeline step to ensure the tool is registered
// and the configuration matches the tool's schema.
func (v *SecurityValidator) ValidateStepConfig(ctx context.Context, tenantID shared.ID, toolName string, capabilities []string, config map[string]any) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// 1. Validate tool name against whitelist and get tool capabilities
	var toolCapabilities []string
	if toolName != "" {
		toolCaps, err := v.validateToolNameAndGetCapabilities(ctx, tenantID, toolName)
		if err != nil {
			addValidationError(result, "tool", err.Error(), "INVALID_TOOL")
		} else {
			toolCapabilities = toolCaps
		}
	}

	// 2. Validate capabilities against whitelist
	for _, cap := range capabilities {
		if !v.isValidCapability(cap) {
			addValidationError(result, "capabilities", fmt.Sprintf("invalid capability: %s", cap), "INVALID_CAPABILITY")
		}
	}

	// 3. If tool is selected, validate capabilities must match tool's capabilities
	if toolName != "" && len(toolCapabilities) > 0 && len(capabilities) > 0 {
		// Check that all provided capabilities are in the tool's capabilities
		for _, cap := range capabilities {
			if !slices.Contains(toolCapabilities, strings.ToLower(cap)) {
				addValidationError(result, "capabilities", fmt.Sprintf("capability '%s' is not supported by tool '%s' (allowed: %v)", cap, toolName, toolCapabilities), "CAPABILITY_TOOL_MISMATCH")
			}
		}
	}

	// 4. Validate config keys (no dangerous keys allowed)
	if config != nil {
		if errs := v.validateConfigKeys(config); len(errs) > 0 {
			for _, err := range errs {
				addValidationError(result, "config", err, "DANGEROUS_CONFIG_KEY")
			}
		}
	}

	// 5. Validate config values (no command injection patterns)
	if config != nil {
		if errs := v.validateConfigValues(config); len(errs) > 0 {
			for _, err := range errs {
				addValidationError(result, "config", err, "DANGEROUS_CONFIG_VALUE")
			}
		}
	}

	return result
}

// ValidateScannerConfig validates a scan configuration's scanner settings.
func (v *SecurityValidator) ValidateScannerConfig(ctx context.Context, tenantID shared.ID, scannerConfig map[string]any) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if scannerConfig == nil {
		return result
	}

	// Validate config keys
	if errs := v.validateConfigKeys(scannerConfig); len(errs) > 0 {
		for _, err := range errs {
			addValidationError(result, "scanner_config", err, "DANGEROUS_CONFIG_KEY")
		}
	}

	// Validate config values
	if errs := v.validateConfigValues(scannerConfig); len(errs) > 0 {
		for _, err := range errs {
			addValidationError(result, "scanner_config", err, "DANGEROUS_CONFIG_VALUE")
		}
	}

	return result
}

// ValidateCommandPayload validates a command payload before sending to an agent.
// This is the last line of defense before a command is executed.
func (v *SecurityValidator) ValidateCommandPayload(ctx context.Context, tenantID shared.ID, payload map[string]any) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check for required fields
	requiredFields := []string{"pipeline_run_id", "step_run_id", "step_id"}
	for _, field := range requiredFields {
		if _, ok := payload[field]; !ok {
			addValidationError(result, field, "required field missing", "MISSING_FIELD")
		}
	}

	// Validate step_config if present
	if stepConfig, ok := payload["step_config"].(map[string]any); ok {
		if errs := v.validateConfigKeys(stepConfig); len(errs) > 0 {
			for _, err := range errs {
				addValidationError(result, "step_config", err, "DANGEROUS_CONFIG_KEY")
			}
		}
		if errs := v.validateConfigValues(stepConfig); len(errs) > 0 {
			for _, err := range errs {
				addValidationError(result, "step_config", err, "DANGEROUS_CONFIG_VALUE")
			}
		}
	}

	// Validate preferred_tool if present
	if toolName, ok := payload["preferred_tool"].(string); ok && toolName != "" {
		if err := v.validateToolName(ctx, tenantID, toolName); err != nil {
			addValidationError(result, "preferred_tool", err.Error(), "INVALID_TOOL")
		}
	}

	// Validate required_capabilities if present
	if caps, ok := payload["required_capabilities"].([]string); ok {
		for _, cap := range caps {
			if !v.isValidCapability(cap) {
				addValidationError(result, "required_capabilities", fmt.Sprintf("invalid capability: %s", cap), "INVALID_CAPABILITY")
			}
		}
	}

	return result
}

// validateToolName checks if a tool name is registered in the tool registry.
func (v *SecurityValidator) validateToolName(ctx context.Context, tenantID shared.ID, toolName string) error {
	_, err := v.validateToolNameAndGetCapabilities(ctx, tenantID, toolName)
	return err
}

// validateToolNameAndGetCapabilities checks if a tool is registered and returns its capabilities.
func (v *SecurityValidator) validateToolNameAndGetCapabilities(ctx context.Context, tenantID shared.ID, toolName string) ([]string, error) {
	// Validate format first - only alphanumeric, dash, underscore allowed
	if !isValidToolNameFormat(toolName) {
		return nil, fmt.Errorf("tool name contains invalid characters: %s", toolName)
	}

	// Check if tool exists in registry (platform or tenant-specific)
	t, err := v.toolRepo.GetByName(ctx, toolName)
	if err != nil {
		// Try tenant-specific tool
		t, err = v.toolRepo.GetByTenantAndName(ctx, tenantID, toolName)
		if err != nil {
			return nil, fmt.Errorf("tool not found in registry: %s", toolName)
		}
	}

	// Check if tool is active
	if !t.IsActive {
		return nil, fmt.Errorf("tool is not active: %s", toolName)
	}

	// Normalize capabilities to lowercase for comparison
	caps := make([]string, len(t.Capabilities))
	for i, cap := range t.Capabilities {
		caps[i] = strings.ToLower(cap)
	}

	return caps, nil
}

// isValidCapability checks if a capability is in the allowed list.
// Capabilities are loaded from the database and cached with periodic refresh.
func (v *SecurityValidator) isValidCapability(cap string) bool {
	return slices.Contains(v.getCapabilities(), strings.ToLower(cap))
}

// Dangerous config keys that could be used for command injection
var dangerousConfigKeys = []string{
	"command",
	"cmd",
	"exec",
	"execute",
	"shell",
	"bash",
	"sh",
	"script",
	"eval",
	"system",
	"popen",
	"subprocess",
	"spawn",
	"run_command",
	"os_command",
	"raw_command",
	"custom_command",
}

// validateConfigKeys checks for dangerous configuration keys.
func (v *SecurityValidator) validateConfigKeys(config map[string]any) []string {
	var errors []string
	for key := range config {
		keyLower := strings.ToLower(key)
		for _, dangerous := range dangerousConfigKeys {
			if keyLower == dangerous || strings.Contains(keyLower, dangerous) {
				errors = append(errors, fmt.Sprintf("dangerous config key not allowed: %s", key))
			}
		}
	}
	return errors
}

// Command injection patterns to detect
var commandInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|$\x60]`),                      // Shell metacharacters
	regexp.MustCompile(`\$\([^)]+\)`),                     // Command substitution $(...)
	regexp.MustCompile("`[^`]+`"),                         // Backtick command substitution
	regexp.MustCompile(`\|\s*\w+`),                        // Pipe to command
	regexp.MustCompile(`;\s*\w+`),                         // Command chaining with ;
	regexp.MustCompile(`&&\s*\w+`),                        // Command chaining with &&
	regexp.MustCompile(`\|\|\s*\w+`),                      // Command chaining with ||
	regexp.MustCompile(`>\s*/`),                           // Redirect to absolute path
	regexp.MustCompile(`<\s*/`),                           // Read from absolute path
	regexp.MustCompile(`\.\./`),                           // Path traversal
	regexp.MustCompile(`(?i)(curl|wget|nc|bash|sh)\s+`),   // Common command injection tools
	regexp.MustCompile(`(?i)/bin/|/usr/bin/|/tmp/|/etc/`), // Suspicious paths
}

// validateConfigValues checks for command injection patterns in config values.
func (v *SecurityValidator) validateConfigValues(config map[string]any) []string {
	var errors []string
	v.checkValueRecursive(config, "", &errors)
	return errors
}

// checkValueRecursive recursively checks config values for injection patterns.
func (sv *SecurityValidator) checkValueRecursive(value any, path string, errors *[]string) {
	switch val := value.(type) {
	case string:
		for _, pattern := range commandInjectionPatterns {
			if pattern.MatchString(val) {
				*errors = append(*errors, fmt.Sprintf("potential command injection in %s: pattern matched", path))
				return // Only report first match per value
			}
		}
	case map[string]any:
		for k, v := range val {
			newPath := k
			if path != "" {
				newPath = path + "." + k
			}
			sv.checkValueRecursive(v, newPath, errors)
		}
	case []any:
		for i, item := range val {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			sv.checkValueRecursive(item, newPath, errors)
		}
	case json.RawMessage:
		var parsed any
		if err := json.Unmarshal(val, &parsed); err == nil {
			sv.checkValueRecursive(parsed, path, errors)
		}
	}
}

// isValidToolNameFormat checks if a tool name has a valid format.
func isValidToolNameFormat(name string) bool {
	if len(name) == 0 || len(name) > 50 {
		return false
	}
	// Only allow alphanumeric, dash, underscore
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// isValidIdentifierFormat checks if an identifier has a valid format.
// Identifiers can only contain alphanumeric characters, dashes, and underscores.
func isValidIdentifierFormat(name string) bool {
	if len(name) == 0 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ValidateIdentifier validates an identifier string against safe character patterns.
// Identifiers can only contain alphanumeric characters, dashes, and underscores.
// This should be used for StepKey, Tags, and similar user-provided identifiers.
func (v *SecurityValidator) ValidateIdentifier(name string, maxLen int, fieldName string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check empty
	if len(name) == 0 {
		addValidationError(result, fieldName, fmt.Sprintf("%s cannot be empty", fieldName), "EMPTY_IDENTIFIER")
		return result
	}

	// Check length
	if maxLen > 0 && len(name) > maxLen {
		addValidationError(result, fieldName, fmt.Sprintf("%s exceeds maximum length of %d", fieldName, maxLen), "IDENTIFIER_TOO_LONG")
		return result
	}

	// Validate format - only alphanumeric, dash, underscore
	if !isValidIdentifierFormat(name) {
		addValidationError(result, fieldName, fmt.Sprintf("%s contains invalid characters (only alphanumeric, dash, and underscore allowed)", fieldName), "INVALID_IDENTIFIER_FORMAT")
	}

	return result
}

// ValidateIdentifiers validates a slice of identifiers.
func (v *SecurityValidator) ValidateIdentifiers(names []string, maxLen int, fieldName string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	for i, name := range names {
		itemResult := v.ValidateIdentifier(name, maxLen, fmt.Sprintf("%s[%d]", fieldName, i))
		if !itemResult.Valid {
			for _, err := range itemResult.Errors {
				addValidationError(result, err.Field, err.Message, err.Code)
			}
		}
	}

	return result
}

// GetAllowedCapabilities returns the list of allowed capabilities.
// This can be used by the UI to show valid options.
// Capabilities are loaded from the database with caching.
func (v *SecurityValidator) GetAllowedCapabilities() []string {
	return v.getCapabilities()
}

// ValidateCronExpression validates a cron expression format.
// This prevents cron injection attacks.
func (v *SecurityValidator) ValidateCronExpression(expr string) error {
	if expr == "" {
		return nil
	}

	// Check for dangerous characters
	for _, pattern := range commandInjectionPatterns {
		if pattern.MatchString(expr) {
			return fmt.Errorf("invalid cron expression: contains dangerous pattern")
		}
	}

	// Basic cron format validation (5 or 6 fields)
	fields := strings.Fields(expr)
	if len(fields) < 5 || len(fields) > 6 {
		return fmt.Errorf("invalid cron expression: expected 5 or 6 fields, got %d", len(fields))
	}

	// Each field should only contain valid cron characters
	cronFieldPattern := regexp.MustCompile(`^[\d\*,\-/LW#?]+$`)
	for i, field := range fields {
		if !cronFieldPattern.MatchString(field) {
			return fmt.Errorf("invalid cron expression: field %d contains invalid characters", i+1)
		}
	}

	return nil
}

// =============================================================================
// TIER VALIDATION (v3.3 - Security Hardening)
// =============================================================================

// ValidTiers contains all valid platform agent tiers.
var ValidTiers = []string{"shared", "dedicated", "premium"}

// ValidateTier validates a tier value against the allowed tier list.
// This should be called at application boundaries before database operations.
// Returns nil if the tier is valid or empty (empty defaults to 'shared').
func (v *SecurityValidator) ValidateTier(tier string) error {
	if tier == "" {
		return nil // Empty is allowed, will default to 'shared'
	}

	// Lowercase for comparison
	tierLower := strings.ToLower(tier)

	// Check against whitelist
	for _, validTier := range ValidTiers {
		if tierLower == validTier {
			return nil
		}
	}

	return fmt.Errorf("invalid tier: %s (allowed: %s)", tier, strings.Join(ValidTiers, ", "))
}

// ValidateTierWithResult validates a tier and returns a ValidationResult.
func (v *SecurityValidator) ValidateTierWithResult(tier string, fieldName string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if err := v.ValidateTier(tier); err != nil {
		addValidationError(result, fieldName, err.Error(), "INVALID_TIER")
	}

	return result
}

// SanitizeTier converts a tier string to a valid tier, defaulting to "shared".
// This is useful for normalizing user input before processing.
func SanitizeTier(tier string) string {
	if tier == "" {
		return "shared"
	}

	tierLower := strings.ToLower(strings.TrimSpace(tier))
	for _, validTier := range ValidTiers {
		if tierLower == validTier {
			return validTier
		}
	}

	// Invalid tier, return shared
	return "shared"
}
