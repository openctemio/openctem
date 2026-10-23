// Package importmapping is an organization's declarative import mapping: a
// document in the CTIS mapping language (openctem.io/mapping/v1) that turns a
// CSV, JSON, JSON Lines or XML export into CTIS, kept in immutable versions.
//
// Design: docs/rfcs/RFC-126-import-mappings.md.
package importmapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis/importer/mapping"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bounds.
const (
	MaxDescription = 1000
	MaxNote        = 500
	// MaxDocumentBytes is the largest mapping document (the language's own
	// bound).
	MaxDocumentBytes = mapping.MaxMappingBytes
	// MaxPerTenant bounds the mappings of one organization.
	MaxPerTenant = 200
	// MaxVersions bounds the versions of one mapping.
	MaxVersions = 500
)

// FormatPrefix starts an import format that names a mapping:
// "mapping:<name or id>[@<version>]".
const FormatPrefix = "mapping:"

// SourcePrefix starts the source name a mapped import is recorded under:
// "mapped:<name>".
const SourcePrefix = "mapped:"

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Errors.
var (
	// ErrIdentityChangeUnconfirmed: a new version changes the identity and
	// the caller did not confirm it.
	ErrIdentityChangeUnconfirmed = errors.New("the new version changes the identity of findings")
	// ErrUnknownMapping: the format names no mapping of the organization.
	ErrUnknownMapping = errors.New("unknown import mapping")
	// ErrLimit: the organization or the mapping is at a count limit.
	ErrLimit = errors.New("import mapping limit reached")
)

// Mapping is one organization's import mapping.
type Mapping struct {
	ID            shared.ID  `json:"id"`
	TenantID      shared.ID  `json:"-"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Source        string     `json:"source"`
	LatestVersion int        `json:"latest_version"`
	CreatedBy     *shared.ID `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Version is one immutable version of a mapping.
type Version struct {
	MappingID shared.ID       `json:"-"`
	TenantID  shared.ID       `json:"-"`
	Version   int             `json:"version"`
	Document  json.RawMessage `json:"mapping,omitempty"`
	Digest    string          `json:"digest"`
	Identity  []string        `json:"identity"`
	// IdentityChanged: the identity differs from the previous version's,
	// so findings imported with earlier versions are keyed apart from new
	// ones (confirmed when the version was saved).
	IdentityChanged bool       `json:"identity_changed"`
	Note            string     `json:"note"`
	CreatedBy       *shared.ID `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// ValidateName checks a mapping name: a slug of 1 to 64 characters.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w: name must be 1 to 64 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit", shared.ErrValidation)
	}
	return nil
}

// ValidateText checks the description and note lengths.
func ValidateText(description, note string) error {
	if len(description) > MaxDescription {
		return fmt.Errorf("%w: description is longer than %d bytes", shared.ErrValidation, MaxDescription)
	}
	if len(note) > MaxNote {
		return fmt.Errorf("%w: note is longer than %d bytes", shared.ErrValidation, MaxNote)
	}
	return nil
}

// Members a mapping may set. Everything else is reserved: the organization,
// asset ownership, criticality and exposure, identity hints, statuses,
// provenance and fingerprints are decided by the platform or by trusted
// channels, never by a file an organization member maps.
var allowedTargets = map[string]map[string]bool{
	mapping.KindFinding: setOf(
		"type", "title", "description", "message", "severity", "confidence", "impact", "likelihood",
		"category", "vulnerability_class", "subcategory", "rule_id", "rule_name", "asset_value", "asset_type",
		"evidence", "references", "tags",
		"location.path", "location.start_line", "location.end_line", "location.start_column", "location.end_column",
		"location.snippet", "location.context_snippet",
		"network.host", "network.port", "network.protocol", "network.service",
		"vulnerability.cve_id", "vulnerability.cve_ids", "vulnerability.cwe_ids", "vulnerability.cwe_id",
		"vulnerability.owasp_ids", "vulnerability.cvss_version", "vulnerability.cvss_score", "vulnerability.cvss_vector",
		"vulnerability.package", "vulnerability.purl", "vulnerability.affected_version", "vulnerability.affected_version_range",
		"vulnerability.fixed_version", "vulnerability.fixed_versions", "vulnerability.ecosystem", "vulnerability.published_at",
		"vulnerability.cpe", "vulnerability.advisories", "vulnerability.vendor_severity",
		"misconfiguration.policy_id", "misconfiguration.policy_name", "misconfiguration.resource_type",
		"misconfiguration.resource_name", "misconfiguration.provider", "misconfiguration.service",
		"misconfiguration.namespace", "misconfiguration.expected", "misconfiguration.actual", "misconfiguration.cause",
		"remediation.recommendation", "remediation.steps", "remediation.effort", "remediation.fix_available",
		"remediation.references",
	),
	mapping.KindAsset: setOf("type", "value", "name", "description", "tags"),
}

// IdentityMembers are the finding members a mapping may declare as its
// identity: the members the server's identity recipes read (RFC-043). A
// member the recipes ignore would claim an identity the platform does not
// use, and findings that differ only there would merge.
var IdentityMembers = []string{
	"title", "rule_id", "asset_value", "location.path", "location.start_line",
	"vulnerability.cve_id", "vulnerability.package", "vulnerability.purl",
	"network.host", "network.port", "network.protocol",
	"misconfiguration.policy_id", "misconfiguration.resource_type", "misconfiguration.resource_name",
}

// Finding types a mapping may produce. A secret needs the producer's keyed
// hash to get its identity, which a mapped file cannot carry.
var allowedFindingTypes = setOf("vulnerability", "misconfiguration")

// AllowedTargets lists the members a mapping may set for kind, sorted.
func AllowedTargets(kind string) []string {
	out := make([]string, 0, len(allowedTargets[kind]))
	for t := range allowedTargets[kind] {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// specView is the part of a value spec the policy reads.
type specView struct {
	Path     string            `json:"path"`
	Const    any               `json:"const"`
	Template string            `json:"template"`
	Map      map[string]string `json:"map"`
	Default  any               `json:"default"`
}

func readSpec(raw string) specView {
	var v specView
	if strings.HasPrefix(raw, `"`) {
		_ = json.Unmarshal([]byte(raw), &v.Path)
		return v
	}
	_ = json.Unmarshal([]byte(raw), &v)
	return v
}

// Compile loads a mapping document and applies the organization policy on
// top of the language's own checks: only finding and asset rules, only
// allowed members, a finding type of vulnerability or misconfiguration, and
// an identity of identity members whenever the mapping makes findings. It
// returns every problem it finds.
func Compile(doc []byte) (*mapping.Mapping, []string) {
	m, err := mapping.Load(doc)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var problems []string
	findings := false
	for i, r := range m.Rules() {
		allowed, ok := allowedTargets[r.Kind]
		if !ok {
			problems = append(problems, fmt.Sprintf("records[%d]: kind %q is not available for imports (finding or asset)", i, r.Kind))
			continue
		}
		if r.Kind == mapping.KindFinding {
			findings = true
		}
		for _, t := range r.Targets {
			if !allowed[t] {
				problems = append(problems, fmt.Sprintf("records[%d]: %q is reserved and cannot be set by an import mapping", i, t))
			}
		}
		if raw, ok := r.Specs["type"]; ok && r.Kind == mapping.KindFinding {
			if p := checkFindingType(readSpec(raw)); p != "" {
				problems = append(problems, fmt.Sprintf("records[%d]: %s", i, p))
			}
		}
	}
	ident := m.Identity()
	if findings && len(ident) == 0 {
		problems = append(problems, "identity: a mapping that makes findings declares its identity members (for example [\"title\", \"asset_value\"])")
	}
	for _, t := range ident {
		if !slices.Contains(IdentityMembers, t) {
			problems = append(problems, fmt.Sprintf("identity: %q is not an identity member (one of %s)", t, strings.Join(IdentityMembers, ", ")))
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return m, nil
}

// checkFindingType: a constant type, or a mapped one whose every table
// value and default, is an allowed finding type.
func checkFindingType(v specView) string {
	bad := fmt.Sprintf("type must be one of vulnerability, misconfiguration (a constant, or a map whose values are)")
	str := func(x any) (string, bool) { s, ok := x.(string); return s, ok }
	switch {
	case v.Const != nil:
		if s, ok := str(v.Const); !ok || !allowedFindingTypes[s] {
			return bad
		}
	case len(v.Map) > 0:
		for _, out := range v.Map {
			if !allowedFindingTypes[out] {
				return bad
			}
		}
		if v.Default != nil {
			if s, ok := str(v.Default); !ok || !allowedFindingTypes[s] {
				return bad
			}
		}
	default:
		return bad
	}
	return ""
}

// identityInputs are the members whose value specs decide a finding's
// identity under a mapping: the declared members and the asset the finding
// lands on.
func identityInputs(m *mapping.Mapping) map[string][]string {
	members := append(m.Identity(), "asset_value", "asset_type")
	out := map[string][]string{}
	for _, r := range m.Rules() {
		if r.Kind != mapping.KindFinding {
			continue
		}
		for _, t := range members {
			out[t] = append(out[t], r.Specs[t])
		}
	}
	return out
}

// IdentityChanged reports whether next keys findings differently from prev:
// another identity list, or another value spec for an identity member or
// the finding's asset in any finding rule. A change of description,
// severity or any other member is not an identity change.
func IdentityChanged(prev, next *mapping.Mapping) bool {
	if !slices.Equal(prev.Identity(), next.Identity()) {
		return true
	}
	a, b := identityInputs(prev), identityInputs(next)
	if len(a) != len(b) {
		return true
	}
	for k, va := range a {
		if !slices.Equal(va, b[k]) {
			return true
		}
	}
	return false
}

// FormatRef is a parsed "mapping:<ref>[@<version>]" format.
type FormatRef struct {
	// Ref is a mapping name or id.
	Ref string
	// Version is the version asked for; 0 is the latest.
	Version int
}

// ParseFormat parses an import format naming a mapping. ok is false when
// the format does not start with "mapping:"; err is set when it does but is
// malformed.
func ParseFormat(format string) (FormatRef, bool, error) {
	rest, ok := strings.CutPrefix(format, FormatPrefix)
	if !ok {
		return FormatRef{}, false, nil
	}
	var fr FormatRef
	ref, ver, hasVer := strings.Cut(rest, "@")
	if hasVer {
		n, err := strconv.Atoi(ver)
		if err != nil || n <= 0 || n > 1_000_000 {
			return fr, true, fmt.Errorf("%w: mapping version must be a positive integer", shared.ErrValidation)
		}
		fr.Version = n
	}
	if _, err := shared.IDFromString(ref); err != nil && ValidateName(ref) != nil {
		return fr, true, fmt.Errorf("%w: mapping:<name or id>[@<version>]", shared.ErrValidation)
	}
	fr.Ref = ref
	return fr, true, nil
}
