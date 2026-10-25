package logger

import (
	"regexp"
	"strings"
)

const redacted = "[REDACTED]"

var (
	// scheme://user:password@host: keep scheme and host, drop the userinfo.
	urlUserinfoRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/]*@`)
	// key=value, key: value, "key":"value" where the key names a secret.
	// The value may be preceded by an auth scheme ("Authorization: Bearer x").
	secretKVRe = regexp.MustCompile(`(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|credential|private[_-]?key)[\w.-]*["']?\s*[=:]\s*)(?:(?:bearer|basic)\s+)?("[^"]*"|'[^']*'|[^\s,;&"']+)`)
	bearerRe   = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	basicRe    = regexp.MustCompile(`(?i)\bbasic\s+([A-Za-z0-9+/]{12,}={0,2})`)
	hexRunRe   = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	b64RunRe   = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
)

// RedactText masks secrets that free-form text (an upstream error, a driver
// message) can carry: URL userinfo, key=value pairs for secret-like keys,
// bearer and basic credentials, and long hex or base64 runs. Ordinary
// sentences pass through unchanged. It does not bound length or strip line
// breaks; combine it with SanitizeText before logging.
func RedactText(s string) string {
	s = urlUserinfoRe.ReplaceAllString(s, "${1}"+redacted+"@")
	s = secretKVRe.ReplaceAllString(s, "${1}"+redacted)
	s = bearerRe.ReplaceAllString(s, "Bearer "+redacted)
	s = basicRe.ReplaceAllStringFunc(s, func(m string) string {
		tok := m[strings.IndexAny(m, " \t")+1:]
		tok = strings.TrimSpace(tok)
		// "basic configuration" is prose; a credential carries a digit or
		// base64 punctuation.
		if strings.ContainsAny(tok, "0123456789+/=") {
			return "Basic " + redacted
		}
		return m
	})
	s = hexRunRe.ReplaceAllString(s, redacted)
	return b64RunRe.ReplaceAllString(s, redacted)
}

// RedactedText is RedactText followed by SanitizeText: the form for logging a
// message that may quote secrets and user input.
func RedactedText(s string) string {
	return SanitizeText(RedactText(s))
}
