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

// genericSecretRules is the allowlist of scanner rule ids known to be
// heuristic (not provider-specific). A rule id is matched exactly (after
// lower-casing, and by its last dotted or slashed segment for a qualified
// id), never by substring: a provider rule whose id merely contains "pwd" or
// "password" must still page.
var genericSecretRules = map[string]struct{}{
	"generic-api-key":              {},
	"generic-secret":               {},
	"generic-password":             {},
	"generic-credential":           {},
	"hardcoded-password":           {},
	"hardcoded-secret":             {},
	"hardcoded-credential":         {},
	"hardcoded-credentials":        {},
	"hard-coded-password":          {},
	"hard_coded_password":          {},
	"high-entropy":                 {},
	"high-entropy-string":          {},
	"high-entropy-secret":          {},
	"credential-literal":           {},
	"detected-generic-secret":      {},
	"detected-generic-api-key":     {},
	"detected-hardcoded-password":  {},
	"detected-high-entropy-string": {},
}

// GenericSecretRule reports whether ruleID is on the allowlist of generic or
// heuristic secret rules, whose hits often are not credentials.
func GenericSecretRule(ruleID string) bool {
	id := strings.ToLower(strings.TrimSpace(ruleID))
	if _, ok := genericSecretRules[id]; ok {
		return true
	}
	if i := strings.LastIndexAny(id, "./"); i >= 0 {
		_, ok := genericSecretRules[id[i+1:]]
		return ok
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
// SecretValid is set only from a validation the platform ran itself, never
// from an uploaded report (a fork pull request could otherwise claim a live
// secret is dead and switch off blocking and rotation).
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
