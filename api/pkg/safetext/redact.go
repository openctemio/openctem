package safetext

import "regexp"

// RedactionPlaceholder replaces every secret RedactSecrets finds.
const RedactionPlaceholder = "[REDACTED]"

// MaxBriefRunes caps operator-written guidance (a mobilization brief, an
// epic description) appended to a ticket, well inside the trackers' body
// limits even after the finding description.
const MaxBriefRunes = 8000

// pemBlockRE matches a whole private key block, header to footer, body
// included. pemOpenRE then catches a block whose footer is missing (a
// truncated description): from the header to the end of its base64 run.
var (
	pemBlockRE = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	pemOpenRE  = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:[ \t]*\r?\n?(?:[A-Za-z0-9+/=:\- \t,]*\r?\n)*[A-Za-z0-9+/=]*)?`)
)

// secretShapes match credential formats by shape alone. Conservative: high
// confidence formats only, so benign text is left alone.
var secretShapes = []*regexp.Regexp{
	// AWS access key ids (long-term AKIA, temporary ASIA, and the other
	// principal prefixes).
	regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`),
	// JSON Web Tokens (header.payload.signature, base64url).
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	// GitHub tokens: classic, OAuth, user-to-server, server-to-server,
	// refresh, and fine-grained.
	regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{20,}\b`),
	regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{20,}\b`),
	// Slack tokens and app-level tokens.
	regexp.MustCompile(`\bxox[abeprs]-[0-9A-Za-z-]{10,}\b`),
	regexp.MustCompile(`\bxapp-[0-9A-Za-z-]{10,}\b`),
	// Google API keys and OAuth access tokens.
	regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
	regexp.MustCompile(`\bya29\.[0-9A-Za-z\-_]{20,}`),
}

// secretAssignmentRE matches `key = value` / `key: value` where the key
// names a secret; the key and separator stay, the value goes.
var secretAssignmentRE = regexp.MustCompile(
	`(?i)\b(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|secret|password|passwd|pwd|token|auth)\b(\s*[:=]\s*)(['"]?)([^\s'"]{4,})(['"]?)`,
)

// bearerRE matches an Authorization header value or a "Bearer <token>".
var bearerRE = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)?\s*|bearer\s+)([A-Za-z0-9\-._~+/]{8,}=*)`)

// RedactSecrets removes secret material from text before it leaves the
// platform for a third-party system (Jira, GitHub issues). It is the one
// redactor every ticket provider uses. Private key blocks are removed whole
// (header, body and footer), so no line of the key survives.
func RedactSecrets(text string) string {
	if text == "" {
		return text
	}
	out := pemBlockRE.ReplaceAllString(text, RedactionPlaceholder)
	out = pemOpenRE.ReplaceAllString(out, RedactionPlaceholder)
	out = bearerRE.ReplaceAllString(out, "${1}"+RedactionPlaceholder)
	out = secretAssignmentRE.ReplaceAllString(out, "${1}${2}${3}"+RedactionPlaceholder+"${5}")
	for _, re := range secretShapes {
		out = re.ReplaceAllString(out, RedactionPlaceholder)
	}
	return out
}
