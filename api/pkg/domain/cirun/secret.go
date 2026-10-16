package cirun

import "strings"

// Which secret findings page (RFC-051 §gate, research 148 section 9.1 #3).
//
// A secret that is certainly dead, or that a heuristic rule guessed at (a
// hard-coded password literal, a high-entropy string), does not stop every
// pipeline and does not open a rotation task. Such a finding follows the
// policy's severity and modes like any other finding. Everything else (a
// provider-specific key shape, or a secret whose validity is unknown or
// confirmed) blocks the gate and is raised as an organization finding with a
// rotation task.

// genericSecretMarkers are the substrings of a rule id that name a
// heuristic (not provider-specific) secret rule.
var genericSecretMarkers = []string{
	"generic", "password", "passwd", "pwd", "hardcoded", "hard-coded", "hard_coded",
	"entropy", "high-entropy", "credential-literal",
}

// GenericSecretRule reports whether ruleID is a generic or heuristic secret
// rule, whose hits often are not credentials.
func GenericSecretRule(ruleID string) bool {
	id := strings.ToLower(ruleID)
	for _, m := range genericSecretMarkers {
		if strings.Contains(id, m) {
			return true
		}
	}
	return false
}

// IsSecret reports whether the finding is a secret finding.
func (f RunFinding) IsSecret() bool {
	return strings.EqualFold(f.FindingType, "secret")
}

// SecretPages reports whether a secret finding blocks the gate and is raised
// as an organization finding with a rotation task: it is a secret, it is not
// known to be invalid (validated false), and its rule is not a generic one.
func (f RunFinding) SecretPages() bool {
	if !f.IsSecret() {
		return false
	}
	if f.SecretValid != nil && !*f.SecretValid {
		return false
	}
	return !GenericSecretRule(f.RuleID)
}

// SecretIdentity is what makes two secret findings the same credential: its
// keyed fingerprint when the platform wrote one, otherwise the finding's own
// fingerprint (one secret on one repository).
func (f RunFinding) SecretIdentity() string {
	if f.SecretFingerprint != "" {
		return f.SecretFingerprint
	}
	return f.Fingerprint
}
