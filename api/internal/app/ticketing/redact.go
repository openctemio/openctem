// Package ticketing holds shared logic for creating issue-tracker tickets
// (Jira, GitHub Issues, ...) from findings. The secret-redaction routine
// lives here so every provider scrubs ticket text through ONE implementation
// and they cannot diverge — a divergence would risk leaking a credential into
// a ticket that one provider redacts and another does not.
package ticketing

import (
	"regexp"
)

// redactionPlaceholder is substituted for any matched secret-like token.
const redactionPlaceholder = "[REDACTED]"

// secretPatterns matches well-known credential formats by shape alone
// (independent of surrounding text). These are intentionally conservative —
// they target high-confidence credential formats to avoid mangling benign
// content.
var secretPatterns = []*regexp.Regexp{
	// AWS access key IDs (AKIA / ASIA / AGPA / AIDA / AROA ... + 16 base32 chars).
	regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`),
	// Generic GitHub tokens (classic + fine-grained + oauth + app).
	regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{20,}\b`),
	regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{20,}\b`),
	// Slack tokens.
	regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
	// Google API keys.
	regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	// Private key blocks.
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
}

// secretAssignment matches `key = value` / `key: value` style assignments
// where the key name implies a secret (password, secret, token, api_key,
// access_key, private_key, etc.). The value is redacted, the key kept.
var secretAssignment = regexp.MustCompile(
	`(?i)\b((?:api[_-]?key|access[_-]?key|secret[_-]?key|secret|password|passwd|pwd|token|auth|bearer|private[_-]?key|client[_-]?secret))\b(\s*[:=]\s*)(['"]?)([^\s'"]{4,})(['"]?)`,
)

// RedactSecrets scrubs credential-shaped substrings from text before it is
// embedded in an outbound ticket. It is intentionally provider-agnostic and
// shared by every ticketing provider. It never returns the original secret.
func RedactSecrets(text string) string {
	if text == "" {
		return text
	}

	// 1. Assignment-style secrets: keep the key + separator, redact the value.
	out := secretAssignment.ReplaceAllString(text, "${1}${2}${3}"+redactionPlaceholder+"${5}")

	// 2. Shape-based secrets anywhere in the text.
	for _, p := range secretPatterns {
		out = p.ReplaceAllString(out, redactionPlaceholder)
	}

	return out
}
