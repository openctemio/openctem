package signer

import "strings"

// The signer's own view of how intrusive a tool is. The signer is a trust
// root separate from the API (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md): it
// signs a job only when the organization's ledger covers its targets at the
// tool's tier, so it cannot take that tier from the API, nor from the tool
// contracts the API reads from sensors. It keeps the tiers of the tools it
// knows; every other tool is checked as active (T1). This list is the
// signer's policy, not the platform's tool catalog: the platform plans from
// the tools' reported contracts.
var signerToolTiers = map[string]int{
	// Passive (T0): third-party sources, resolvers, code and image analysis.
	"subfinder": tierPassive, "dnsx": tierPassive, "rdap": tierPassive, "asn": tierPassive,
	"betterleaks": tierPassive, "trufflehog": tierPassive, "gitleaks": tierPassive,
	"semgrep": tierPassive, "opengrep": tierPassive, "codeql": tierPassive,
	"trivy": tierPassive, "osv-scanner": tierPassive, "grype": tierPassive,
	"checkov": tierPassive, "kics": tierPassive,
	// Intrusive (T2).
	"zap": tierIntrusive,
}

const (
	tierPassive   = 0
	tierActive    = 1
	tierIntrusive = 2
)

// toolTier is the tier the signer checks a job of the tool at.
func toolTier(tool string) int {
	if t, ok := signerToolTiers[strings.ToLower(strings.TrimSpace(tool))]; ok {
		return t
	}
	return tierActive
}
