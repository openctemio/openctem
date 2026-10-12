package definition

import (
	"fmt"
	"regexp"
	"strings"
)

// Namespace registry (RFC-044 §5.6): per namespace, how its ids look and are
// normalized, the default kind, how to link to it, and whether it may hold
// global definitions.
//
// A namespace is either a plain name (CVE, GHSA, NUCLEI, ...) or a family and
// a sub-name: OSV:<database> for an advisory database without its own entry
// (OSV:PYSEC, OSV:RUSTSEC, OSV:MAL) and CUSTOM:<tool> for a tool the platform
// does not know (always tenant-scoped). A scanner rule never relies on prefix
// guessing: ingest knows the tool and names the namespace.

// Well-known namespace names.
const (
	NamespaceCVE         = "CVE"
	NamespaceGHSA        = "GHSA"
	NamespaceRHSA        = "RHSA"
	NamespaceDSA         = "DSA"
	NamespaceUSN         = "USN"
	NamespaceMSRC        = "MSRC"
	NamespaceNuclei      = "NUCLEI"
	NamespaceSemgrep     = "SEMGREP"
	NamespaceCodeQL      = "CODEQL"
	NamespaceTrivy       = "TRIVY"
	NamespaceCheckov     = "CHECKOV"
	NamespaceBetterleaks = "BETTERLEAKS"
	NamespaceGitleaks    = "GITLEAKS"
	NamespaceTrufflehog  = "TRUFFLEHOG"
	NamespaceTenable     = "TENABLE"
	NamespaceQualys      = "QUALYS"
	NamespaceSWC         = "SWC"
	NamespacePentest     = "PENTEST"

	// FamilyOSV prefixes an OSV database without its own entry: OSV:PYSEC.
	FamilyOSV = "OSV"
	// FamilyCustom prefixes an unknown tool: CUSTOM:<tool>. Tenant scope only.
	FamilyCustom = "CUSTOM"
)

// maxExternalIDLen matches vulnerabilities.external_id VARCHAR(512).
const maxExternalIDLen = 512

// Namespace describes one namespace of the registry.
type Namespace struct {
	// Name is the full namespace as stored: "CVE", "OSV:PYSEC", "CUSTOM:acme".
	Name string
	// DefaultKind is the kind a definition in this namespace has unless the
	// source says otherwise.
	DefaultKind Kind
	// Display is the short label shown next to an id ("CVE", "Nuclei").
	Display string
	// GlobalCapable: global definitions may exist in this namespace. False
	// for CUSTOM:<tool>, whose ids are only meaningful to one tenant.
	GlobalCapable bool
	// Advisory: an advisory database. Ingest may create a global identity
	// stub for an advisory id nobody has reported yet (RFC-044 §5.5); a
	// scanner-rule id a sensor reports becomes a tenant definition instead.
	Advisory bool

	urlTemplate string
	pattern     *regexp.Regexp
	normalize   func(string) string
}

// ReferenceURL returns the public page of id, or "" when the namespace has
// no stable per-id page.
func (n Namespace) ReferenceURL(id string) string {
	if n.urlTemplate == "" || id == "" {
		return ""
	}
	return strings.ReplaceAll(n.urlTemplate, "{id}", id)
}

var (
	// namespacePattern matches the vulnerabilities/definition_identifiers
	// CHECK constraint (migration 000820).
	namespacePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}(:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$`)

	// identifierShape: "<DB>-<ENTRYID>" with a digit after the first dash
	// (CVE-2021-44228, GHSA-jfh8-c2jp-5v3q, PYSEC-2021-1, MS17-010), unlike a
	// nickname ("Log4Shell", "Spring4Shell"). Migration 000822 uses the same
	// rule to keep nicknames apart from identifiers.
	identifierShape = regexp.MustCompile(`(?i)^[a-z][a-z0-9]*-[a-z0-9:._-]*[0-9][a-z0-9:._-]*$`)

	cvePattern  = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	ghsaPattern = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
	digits      = regexp.MustCompile(`^\d+$`)
	swcPattern  = regexp.MustCompile(`^SWC-\d+$`)
	ckvPattern  = regexp.MustCompile(`^CKV2?_[A-Z0-9_]+$`)
	osvIDShape  = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Za-z0-9:._-]+$`)
	customTool  = regexp.MustCompile(`[^a-z0-9_.-]+`)
)

func upper(s string) string { return strings.ToUpper(s) }

// normalizeGHSA upper-cases the prefix and lower-cases the body, the form
// GitHub publishes (GHSA-jfh8-c2jp-5v3q).
func normalizeGHSA(s string) string {
	if len(s) < 5 || !strings.EqualFold(s[:5], "GHSA-") {
		return s
	}
	return "GHSA-" + strings.ToLower(s[5:])
}

func identity(s string) string { return s }

var registry = map[string]Namespace{
	NamespaceCVE: {
		Name: NamespaceCVE, DefaultKind: KindVulnerability, Display: "CVE", GlobalCapable: true, Advisory: true,
		urlTemplate: "https://www.cve.org/CVERecord?id={id}", pattern: cvePattern, normalize: upper,
	},
	NamespaceGHSA: {
		Name: NamespaceGHSA, DefaultKind: KindVulnerability, Display: "GHSA", GlobalCapable: true, Advisory: true,
		urlTemplate: "https://github.com/advisories/{id}", pattern: ghsaPattern, normalize: normalizeGHSA,
	},
	NamespaceRHSA: {
		Name: NamespaceRHSA, DefaultKind: KindVulnerability, Display: "RHSA", GlobalCapable: true, Advisory: true,
		urlTemplate: "https://access.redhat.com/errata/{id}", normalize: upper,
	},
	NamespaceDSA: {
		Name: NamespaceDSA, DefaultKind: KindVulnerability, Display: "DSA", GlobalCapable: true, Advisory: true,
		normalize: upper,
	},
	NamespaceUSN: {
		Name: NamespaceUSN, DefaultKind: KindVulnerability, Display: "USN", GlobalCapable: true, Advisory: true,
		urlTemplate: "https://ubuntu.com/security/notices/{id}", normalize: upper,
	},
	NamespaceMSRC: {
		Name: NamespaceMSRC, DefaultKind: KindVulnerability, Display: "MSRC", GlobalCapable: true, Advisory: true,
		normalize: upper,
	},
	NamespaceNuclei: {
		Name: NamespaceNuclei, DefaultKind: KindExposure, Display: "Nuclei", GlobalCapable: true, normalize: identity,
	},
	NamespaceSemgrep: {
		Name: NamespaceSemgrep, DefaultKind: KindWeakness, Display: "Semgrep", GlobalCapable: true,
		urlTemplate: "https://semgrep.dev/r/{id}", normalize: identity,
	},
	NamespaceCodeQL: {
		Name: NamespaceCodeQL, DefaultKind: KindWeakness, Display: "CodeQL", GlobalCapable: true, normalize: identity,
	},
	NamespaceTrivy: {
		Name: NamespaceTrivy, DefaultKind: KindMisconfiguration, Display: "Trivy", GlobalCapable: true, normalize: upper,
	},
	NamespaceCheckov: {
		Name: NamespaceCheckov, DefaultKind: KindMisconfiguration, Display: "Checkov", GlobalCapable: true,
		pattern: ckvPattern, normalize: upper,
	},
	NamespaceBetterleaks: {
		Name: NamespaceBetterleaks, DefaultKind: KindSecret, Display: "Betterleaks", GlobalCapable: true, normalize: identity,
	},
	NamespaceGitleaks: {
		Name: NamespaceGitleaks, DefaultKind: KindSecret, Display: "Gitleaks", GlobalCapable: true, normalize: identity,
	},
	NamespaceTrufflehog: {
		Name: NamespaceTrufflehog, DefaultKind: KindSecret, Display: "TruffleHog", GlobalCapable: true, normalize: identity,
	},
	NamespaceTenable: {
		Name: NamespaceTenable, DefaultKind: KindVulnerability, Display: "Tenable", GlobalCapable: true,
		urlTemplate: "https://www.tenable.com/plugins/nessus/{id}", pattern: digits, normalize: identity,
	},
	NamespaceQualys: {
		Name: NamespaceQualys, DefaultKind: KindVulnerability, Display: "Qualys QID", GlobalCapable: true,
		pattern: digits, normalize: identity,
	},
	NamespaceSWC: {
		Name: NamespaceSWC, DefaultKind: KindWeakness, Display: "SWC", GlobalCapable: true,
		urlTemplate: "https://swcregistry.io/docs/{id}", pattern: swcPattern, normalize: upper,
	},
	NamespacePentest: {
		Name: NamespacePentest, DefaultKind: KindVulnerability, Display: "Pentest", GlobalCapable: true, normalize: identity,
	},
}

// Lookup returns the registry entry for name: a plain namespace, OSV:<db> or
// CUSTOM:<tool>. ok is false for a name the registry does not know or that
// the database would refuse.
func Lookup(name string) (Namespace, bool) {
	if !namespacePattern.MatchString(name) {
		return Namespace{}, false
	}
	if ns, ok := registry[name]; ok {
		return ns, true
	}
	family, sub, found := strings.Cut(name, ":")
	if !found {
		return Namespace{}, false
	}
	switch family {
	case FamilyOSV:
		kind := KindVulnerability
		if sub == "MAL" {
			kind = KindMalicious
		}
		return Namespace{
			Name: name, DefaultKind: kind, Display: sub, GlobalCapable: true, Advisory: true,
			urlTemplate: "https://osv.dev/vulnerability/{id}", pattern: osvIDShape, normalize: upper,
		}, true
	case FamilyCustom:
		return Namespace{Name: name, DefaultKind: KindVulnerability, Display: sub, normalize: identity}, true
	}
	return Namespace{}, false
}

// NormalizeID returns externalID in the canonical form of namespace, or an
// error when the namespace is unknown or the id cannot belong to it.
func NormalizeID(namespace, externalID string) (string, error) {
	ns, ok := Lookup(namespace)
	if !ok {
		return "", fmt.Errorf("%w: unknown namespace %q", ErrInvalid, namespace)
	}
	return ns.Normalize(externalID)
}

// Normalize returns externalID in this namespace's canonical form.
func (n Namespace) Normalize(externalID string) (string, error) {
	id := strings.TrimSpace(externalID)
	if n.normalize != nil {
		id = n.normalize(id)
	}
	if id == "" {
		return "", fmt.Errorf("%w: empty %s id", ErrInvalid, n.Name)
	}
	if len(id) > maxExternalIDLen {
		return "", fmt.Errorf("%w: %s id longer than %d characters", ErrInvalid, n.Name, maxExternalIDLen)
	}
	if n.pattern != nil && !n.pattern.MatchString(id) {
		return "", fmt.Errorf("%w: %q is not a %s id", ErrInvalid, id, n.Name)
	}
	return id, nil
}

// LooksLikeIdentifier reports whether s has the shape of an advisory id
// ("<DB>-<ENTRYID>" with a digit) rather than a nickname.
func LooksLikeIdentifier(s string) bool {
	return identifierShape.MatchString(strings.TrimSpace(s))
}

// DetectAdvisory returns the namespace and canonical form of an advisory id
// by its prefix, following the OSV id format ("<DB>-<ENTRYID>"): CVE-, GHSA-,
// the vendor databases with their own entry, else OSV:<DB>. It is for
// advisory ids only; a scanner rule's namespace comes from the tool.
func DetectAdvisory(id string) (namespace, externalID string, ok bool) {
	id = strings.TrimSpace(id)
	if !LooksLikeIdentifier(id) {
		return "", "", false
	}
	prefix, _, _ := strings.Cut(id, "-")
	prefix = strings.ToUpper(prefix)
	switch prefix {
	case NamespaceCVE, NamespaceGHSA, NamespaceRHSA, NamespaceDSA, NamespaceUSN:
		namespace = prefix
	default:
		namespace = FamilyOSV + ":" + prefix
	}
	norm, err := NormalizeID(namespace, id)
	if err != nil {
		return "", "", false
	}
	return namespace, norm, true
}

// CustomNamespace returns the CUSTOM:<tool> namespace for a tool the registry
// does not know, or "" when tool has no usable characters.
func CustomNamespace(tool string) string {
	t := customTool.ReplaceAllString(strings.ToLower(strings.TrimSpace(tool)), "-")
	t = strings.Trim(t, "-._")
	if len(t) > 64 {
		t = t[:64]
	}
	if t == "" {
		return ""
	}
	name := FamilyCustom + ":" + t
	if !namespacePattern.MatchString(name) {
		return ""
	}
	return name
}
