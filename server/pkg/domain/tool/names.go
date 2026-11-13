package tool

import "strings"

// NameBetterleaks is the secret scanner's tool name.
const NameBetterleaks = "betterleaks"

// retiredNames maps the name of a tool that was replaced to its replacement.
//
// Betterleaks replaced gitleaks (migration 000241): it is gitleaks' successor
// by its original author and writes the same report, so its findings keep
// their fingerprints. Sensors released before the switch (v0.3.0 and older)
// still report "gitleaks".
var retiredNames = map[string]string{
	"gitleaks": NameBetterleaks,
}

// CanonicalName returns the platform's name for a tool name a sensor or a
// report supplied: a retired name maps to its replacement, anything else is
// returned unchanged.
//
// This is the platform's ONE mapping of old tool names. It is applied where a
// name enters from outside — ingest (the report's tool), the comparison of a
// report's tool with the tools a sensor declares, and suppression rules —
// so stored data and every comparison downstream see a single name.
func CanonicalName(name string) string {
	if to, ok := retiredNames[strings.ToLower(strings.TrimSpace(name))]; ok {
		return to
	}
	return name
}

// SameTool reports whether two tool names name the same tool, ignoring case,
// surrounding space and retired names.
func SameTool(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(CanonicalName(a)), strings.TrimSpace(CanonicalName(b)))
}
