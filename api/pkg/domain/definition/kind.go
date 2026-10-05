// Package definition is the issue-definition catalog: what an issue is, in
// general, independent of where it was found. A finding is one occurrence of
// one or more definitions.
//
// Design: https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-044-issue-definitions-and-findings.md
//
// Definitions live in the vulnerabilities table, extended in place (every
// existing CVE row keeps its id). The vulnerability package keeps serving the
// CVE catalog on top of the same rows.
//
// Scope and trust: a global definition (no tenant) is platform-owned and
// read-only to tenants; its shared content comes only from trusted feeds and
// the rule-catalog import. A tenant definition (custom rule, pentest issue, a
// rule id a sensor reported that no curated pack knows) is visible to its
// tenant only. The schema enforces both: see Scope.
package definition

import "fmt"

// Kind classifies a definition (RFC-044 §4.1). A finding's type is the kind
// of its primary definition.
type Kind string

const (
	// KindVulnerability is a flaw in a specific product, package or version
	// with an advisory (CVE, GHSA, OSV, vendor advisory, scanner plugin).
	KindVulnerability Kind = "vulnerability"
	// KindWeakness is a flaw class in first-party code, without an advisory
	// (SAST rule, CWE-typed; SWC).
	KindWeakness Kind = "weakness"
	// KindMisconfiguration is a resource that deviates from a secure setting
	// (Trivy, Checkov, KICS, Prowler, CIS recommendation).
	KindMisconfiguration Kind = "misconfiguration"
	// KindExposure is something reachable that should not be (panel, file,
	// service, takeover, default login) without an advisory.
	KindExposure Kind = "exposure"
	// KindSecret is a credential or key exposed in code, an image or logs.
	KindSecret Kind = "secret"
	// KindCompliance is a framework control evaluated and failed.
	KindCompliance Kind = "compliance"
	// KindMalicious is malware, a malicious package or an IOC match.
	KindMalicious Kind = "malicious"
)

// AllKinds returns every kind in display order.
func AllKinds() []Kind {
	return []Kind{
		KindVulnerability, KindWeakness, KindMisconfiguration, KindExposure,
		KindSecret, KindCompliance, KindMalicious,
	}
}

// IsValid reports whether k is one of AllKinds.
func (k Kind) IsValid() bool {
	switch k {
	case KindVulnerability, KindWeakness, KindMisconfiguration, KindExposure,
		KindSecret, KindCompliance, KindMalicious:
		return true
	}
	return false
}

// ParseKind returns the kind named s.
func ParseKind(s string) (Kind, error) {
	k := Kind(s)
	if !k.IsValid() {
		return "", fmt.Errorf("%w: unknown definition kind %q", ErrInvalid, s)
	}
	return k, nil
}

// OCSF finding classes a kind maps to (OCSF 1.3+).
const (
	OCSFVulnerabilityFinding = 2002
	OCSFComplianceFinding    = 2003
	OCSFDetectionFinding     = 2004
	OCSFDataSecurityFinding  = 2006
	OCSFAppSecPostureFinding = 2007
)

// OCSFClass returns the OCSF finding class uid for k (RFC-044 §4.1), or 0 for
// an invalid kind.
func (k Kind) OCSFClass() int {
	switch k {
	case KindVulnerability, KindExposure:
		return OCSFVulnerabilityFinding
	case KindWeakness:
		return OCSFAppSecPostureFinding
	case KindMisconfiguration, KindCompliance:
		return OCSFComplianceFinding
	case KindSecret:
		return OCSFDataSecurityFinding
	case KindMalicious:
		return OCSFDetectionFinding
	}
	return 0
}
