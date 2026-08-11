package handler

import "strings"

// sanitizeLogField strips CR/LF from an attacker-influenceable value (e.g. a
// raw URL path parameter that has not yet been validated into a typed ID)
// before it reaches the structured logger, preventing log forging
// (CWE-117 / CodeQL go/log-injection). CR/LF become a single space so the
// token still round-trips visibly; length is capped so a pathological value
// can't blow up log rotation.
func sanitizeLogField(s string) string {
	const maxLen = 256
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
