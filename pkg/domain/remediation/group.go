package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// KeyInput carries the finding signals used to derive a remediation group key.
// Primitives only, so the derivation stays decoupled from the vulnerability
// package and is trivially unit-testable.
type KeyInput struct {
	// ComponentKey is a stable package identity (purl, or name@ecosystem) when
	// the finding is on a dependency/package. Empty for non-SCA findings.
	ComponentKey string
	// FixAvailable reports that a fix/upgrade is known (a fixed version exists,
	// or the scanner supplied a fix). Only groupable fixes form SCA groups.
	FixAvailable bool
	// SolutionText is the remediation recommendation / Nessus <solution> — the
	// fallback grouping signal for host/infra findings.
	SolutionText string
}

// DeriveKey computes the remediation-group key and a human-readable title for a
// finding. ok is false when the finding is not groupable (no shared fix signal).
//
// Grouping precedence:
//  1. SCA / package: group by component identity — one upgrade resolves every
//     finding on that package. This is the strongest, most reliable signal.
//  2. Host / infra: group by the normalized solution text (Nessus/Tenable
//     "solution" — the patch that fixes a whole plugin family).
func DeriveKey(in KeyInput) (key, title string, ok bool) {
	if c := normalize(in.ComponentKey); c != "" && in.FixAvailable {
		return "sca:" + c, "Upgrade " + strings.TrimSpace(in.ComponentKey), true
	}
	if s := normalize(in.SolutionText); s != "" {
		sum := sha256.Sum256([]byte(s))
		return "sol:" + hex.EncodeToString(sum[:]), firstLine(in.SolutionText), true
	}
	return "", "", false
}

// normalize lowercases, trims, and collapses internal whitespace so trivially
// different renderings of the same fix map to one key.
func normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// firstLine returns a compact, single-line title from possibly multi-line text.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	const max = 200
	if len(s) > max {
		s = s[:max]
	}
	return s
}
