package simulation

import (
	"strings"
	"unicode"
)

// knownFrameworks maps a framework's comparison key (lower case, letters and
// digits only) to the one name shown everywhere. "cis", "CIS" and
// "CIS Controls" are the same framework; storing them apart split one
// framework into several cards and filters.
var knownFrameworks = map[string]string{
	"nistcsf":     "NIST CSF",
	"nist":        "NIST CSF",
	"iso27001":    "ISO 27001",
	"soc2":        "SOC 2",
	"cis":         "CIS Controls",
	"ciscontrols": "CIS Controls",
	"pcidss":      "PCI DSS",
	"pci":         "PCI DSS",
	"hipaa":       "HIPAA",
	"mitreattack": "MITRE ATT&CK",
	"owaspasvs":   "OWASP ASVS",
	"custom":      "Custom",
}

// FrameworkKey is the comparison key of a framework name: lower case, letters
// and digits only. Two names with the same key are the same framework.
func FrameworkKey(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CanonicalFramework returns the name a framework is stored and shown under:
// the standard name for a known framework, else the trimmed input with its
// inner spaces collapsed.
func CanonicalFramework(name string) string {
	if canon, ok := knownFrameworks[FrameworkKey(name)]; ok {
		return canon
	}
	return strings.Join(strings.Fields(name), " ")
}
