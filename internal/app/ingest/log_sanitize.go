package ingest

import "strings"

// sanitizeIngestLogField strips CR/LF from an attacker-influenceable
// string value before it hits the structured logger. Scanner-authored
// report metadata (IDs, source types, etc.) is the primary taint
// source — a compromised agent could submit a report whose ID is
//
//	"run-42\nWARN: admin force-logout"
//
// and forge a fake log line if the underlying slog handler serialises
// string values verbatim. CR/LF get replaced with a single space so
// the visible token still round-trips.
//
// Also caps length at 512 chars so a pathological source can't blow
// up log rotation; beyond that the prefix is enough to debug and the
// raw payload still lives in the CTIS report we persist.
//
// Closes CodeQL go/log-injection flagged at ingest/service.go:139.
func sanitizeIngestLogField(s string) string {
	const maxLen = 512
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
