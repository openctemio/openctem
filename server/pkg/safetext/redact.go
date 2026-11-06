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
// names a secret; the key and separator stay, the value goes. A quoted key
// (a JSON body: `"password": "x"`) and a query parameter
// (`access_token=x`) count too.
var secretAssignmentRE = regexp.MustCompile(
	`(?i)\b(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|(?:access|refresh|id|auth)[_-]?token|secret|password|passwd|pwd|token|auth)\b(["']?\s*[:=]\s*)(['"]?)([^\s'"]{4,})(['"]?)`,
)

// cookieRE matches a Cookie / Set-Cookie header line, also as a verbose HTTP
// client prints it ("> Cookie:", "< Set-Cookie:"); the header name stays, the
// whole value (session ids, attributes) goes. cookieQuotedRE is the same
// header as a quoted JSON member ("Cookie": "sid=...").
var (
	cookieRE       = regexp.MustCompile(`(?im)^([ \t]*(?:[<>][ \t]*)?(?:set-)?cookie[ \t]*:[ \t]*)[^\r\n]+`)
	cookieQuotedRE = regexp.MustCompile(`(?i)(["'](?:set-)?cookie["'][ \t]*:[ \t]*["'])[^"'\r\n]+`)
)

// bearerRE matches an Authorization header value (any of the token schemes,
// a quoted JSON member too) or a "Bearer <token>". The placeholder is a
// token too, so a second pass leaves masked text as it is.
var bearerRE = regexp.MustCompile(`(?i)\b(authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|negotiate|ntlm)?\s*|bearer\s+)(\[REDACTED\]|[A-Za-z0-9\-._~+/]{8,}=*)`)

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
	out = cookieRE.ReplaceAllString(out, "${1}"+RedactionPlaceholder)
	out = cookieQuotedRE.ReplaceAllString(out, "${1}"+RedactionPlaceholder)
	out = bearerRE.ReplaceAllString(out, "${1}"+RedactionPlaceholder)
	out = secretAssignmentRE.ReplaceAllString(out, "${1}${2}${3}"+RedactionPlaceholder+"${5}")
	for _, re := range secretShapes {
		out = re.ReplaceAllString(out, RedactionPlaceholder)
	}
	return out
}

// SecretSpan is one secret value FindSecrets found: text[Start:End] is the
// value (a header name or assignment key around it is not part of the span),
// Kind a stable type name ("private_key", "aws_access_key", "jwt", ...).
type SecretSpan struct {
	Start, End int
	Kind       string
}

// shapeKinds names secretShapes, index by index.
var shapeKinds = []string{
	"aws_access_key", "jwt", "github_token", "github_token", "slack_token",
	"slack_token", "google_api_key", "google_oauth_token",
}

// FindSecrets reports where RedactSecrets would remove secret material,
// without changing the text, so a caller can replace each value with its own
// placeholder (the AI context masker). Spans may overlap; callers resolve
// overlaps. Same rules as RedactSecrets.
func FindSecrets(text string) []SecretSpan {
	if text == "" {
		return nil
	}
	var out []SecretSpan
	add := func(re *regexp.Regexp, group int, kind string) {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[2*group], m[2*group+1]
			if s >= 0 && e > s {
				out = append(out, SecretSpan{Start: s, End: e, Kind: kind})
			}
		}
	}
	add(pemBlockRE, 0, "private_key")
	add(pemOpenRE, 0, "private_key")
	// The header name stays: the value is everything after the prefix group.
	for _, re := range []*regexp.Regexp{cookieRE, cookieQuotedRE} {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if m[3] < m[1] {
				out = append(out, SecretSpan{Start: m[3], End: m[1], Kind: "cookie"})
			}
		}
	}
	add(bearerRE, 2, "authorization")
	add(secretAssignmentRE, 4, "credential")
	for i, re := range secretShapes {
		add(re, 0, shapeKinds[i])
	}
	return out
}
