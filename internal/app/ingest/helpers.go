package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// =============================================================================
// Error Helpers
// =============================================================================

// addError adds an error to the output, respecting the limit.
func addError(output *Output, errMsg string) {
	if len(output.Errors) < MaxErrorsToReturn {
		output.Errors = append(output.Errors, errMsg)
	}
}

// =============================================================================
// Count Helpers
// =============================================================================

// countTrue counts true values in a map.
func countTrue(m map[string]bool) int {
	count := 0
	for _, v := range m {
		if v {
			count++
		}
	}
	return count
}

// =============================================================================
// Deep Merge Functions
// =============================================================================

// mergePropertiesDeep performs a deep merge of properties.
func mergePropertiesDeep(base, overlay map[string]any) map[string]any {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	result := make(map[string]any)

	// Copy base
	for k, v := range base {
		result[k] = v
	}

	// Merge overlay
	for k, v := range overlay {
		baseVal, exists := result[k]
		if !exists {
			result[k] = v
			continue
		}

		// Handle nested maps
		if baseMap, ok := baseVal.(map[string]any); ok {
			if overlayMap, ok := v.(map[string]any); ok {
				result[k] = mergePropertiesDeep(baseMap, overlayMap)
				continue
			}
		}

		// Handle special array merging
		switch k {
		case "dns_records":
			result[k] = mergeArraysByKey(baseVal, v, []string{"type", "name", "value"})
		case "ports":
			result[k] = mergeArraysByKey(baseVal, v, []string{"port", "protocol"})
		case "technologies", "nameservers", "sans", "tags":
			result[k] = mergeStringArrays(baseVal, v)
		default:
			// Default: overlay wins
			result[k] = v
		}
	}

	return result
}

// mergeArraysByKey merges two arrays of maps, deduplicating by composite key.
func mergeArraysByKey(base, overlay any, keyFields []string) []map[string]any {
	result := make([]map[string]any, 0)
	seen := make(map[string]bool)

	processArray := func(arr any) {
		switch v := arr.(type) {
		case []map[string]any:
			for _, item := range v {
				key := buildCompositeKey(item, keyFields)
				if !seen[key] {
					result = append(result, item)
					seen[key] = true
				}
			}
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					key := buildCompositeKey(m, keyFields)
					if !seen[key] {
						result = append(result, m)
						seen[key] = true
					}
				}
			}
		}
	}

	processArray(base)
	processArray(overlay)

	return result
}

// buildCompositeKey builds a composite key from map fields.
// Format: "field1=value1|field2=value2|..." to avoid collision from missing fields.
// Example: {"a":"x","c":"z"} → "a=x|b=|c=z" (not "x::z" which could collide with "x|z")
func buildCompositeKey(m map[string]any, keyFields []string) string {
	parts := make([]string, len(keyFields))
	for i, field := range keyFields {
		value := ""
		if v, ok := m[field]; ok {
			value = fmt.Sprintf("%v", v)
		}
		// Include field name to avoid collision when fields are missing
		parts[i] = fmt.Sprintf("%s=%s", field, value)
	}
	return strings.Join(parts, "|")
}

// =============================================================================
// Fingerprint Helpers
// =============================================================================

// createCompositeFingerprint creates a fingerprint that includes both assetID and base fingerprint.
// This ensures findings are unique per-asset, preventing incorrect deduplication across assets.
// Format: sha256(assetID + ":" + baseFingerprint)
func createCompositeFingerprint(assetID, baseFingerprint string) string {
	data := assetID + ":" + baseFingerprint
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// =============================================================================
// Array Merge Functions
// =============================================================================

// =============================================================================
// Security: Input Sanitization
// =============================================================================

// MaxAssetNameLength is the maximum allowed length for auto-created asset names.
const MaxAssetNameLength = 500

// dangerousCharsPattern matches potentially dangerous characters for asset names.
// Prevents injection attacks (SQL, XSS, path traversal).
var dangerousCharsPattern = regexp.MustCompile(`[<>'";&|$\x00-\x1f\x7f]`)

// pathTraversalPattern matches path traversal sequences.
var pathTraversalPattern = regexp.MustCompile(`\.\.[\\/]|[\\/]\.\.`)

// sanitizeAssetName sanitizes user-provided asset name/value.
// This prevents injection attacks and ensures safe storage.
//
// Security measures:
//   - Removes dangerous characters (SQL injection, XSS)
//   - Blocks path traversal attempts (../ or ..\)
//   - Limits length to prevent DoS
//   - Removes control characters
//   - Trims whitespace
func sanitizeAssetName(name string) string {
	if name == "" {
		return ""
	}

	// Step 1: Remove control characters (except common whitespace)
	var sanitized strings.Builder
	sanitized.Grow(len(name))
	for _, r := range name {
		if r == '\t' || r == '\n' || r == '\r' || !unicode.IsControl(r) {
			sanitized.WriteRune(r)
		}
	}
	name = sanitized.String()

	// Step 2: Remove dangerous characters
	name = dangerousCharsPattern.ReplaceAllString(name, "")

	// Step 3: Block path traversal - replace with safe separator
	name = pathTraversalPattern.ReplaceAllString(name, "/")

	// Step 4: Normalize multiple slashes
	for strings.Contains(name, "//") {
		name = strings.ReplaceAll(name, "//", "/")
	}

	// Step 5: Trim whitespace
	name = strings.TrimSpace(name)

	// Step 6: Enforce length limit
	if len(name) > MaxAssetNameLength {
		name = name[:MaxAssetNameLength]
	}

	return name
}

// sanitizePathForProperty sanitizes a path before storing in properties.
// This prevents information disclosure of server paths.
//
// Returns only the meaningful part of the path (removes absolute prefix).
func sanitizePathForProperty(path string) string {
	if path == "" {
		return ""
	}

	// Remove common sensitive prefixes
	sensitivePrefeixes := []string{
		"/home/",
		"/root/",
		"/var/",
		"/tmp/",
		"/etc/",
		"/Users/",
		"C:\\Users\\",
		"C:\\Windows\\",
	}

	for _, prefix := range sensitivePrefeixes {
		if idx := strings.Index(strings.ToLower(path), strings.ToLower(prefix)); idx >= 0 {
			// Find the project directory (usually 2-3 levels deep from home)
			parts := strings.Split(path[idx:], string(path[idx+len(prefix)-1]))
			if len(parts) > 3 {
				// Return from project dir onwards
				return strings.Join(parts[3:], "/")
			}
		}
	}

	// Remove leading slash for relative display
	path = strings.TrimPrefix(path, "/")

	return path
}

// isValidGitHost checks if the host is a known git hosting provider.
// This prevents abuse of path inference with arbitrary domains.
func isValidGitHost(host string) bool {
	validHosts := map[string]bool{
		"github.com":    true,
		"gitlab.com":    true,
		"bitbucket.org": true,
		// Self-hosted instances should be validated differently
	}
	return validHosts[strings.ToLower(host)]
}

// mergeStringArrays merges two string arrays with deduplication.
func mergeStringArrays(base, overlay any) []string {
	result := make([]string, 0)
	seen := make(map[string]bool)

	processArray := func(arr any) {
		switch v := arr.(type) {
		case []string:
			for _, s := range v {
				if !seen[s] {
					result = append(result, s)
					seen[s] = true
				}
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					if !seen[s] {
						result = append(result, s)
						seen[s] = true
					}
				}
			}
		}
	}

	processArray(base)
	processArray(overlay)

	return result
}
