// Package contentrule is the domain of detection rules: web fingerprint
// rules that name the technologies a web response shows, and
// sensitive-information rules that find secrets, keys, internal host names
// and personal data in it. Rules come from signed platform content packs
// (kinds web-fingerprints and secret-rules) and from an organization's own
// rules. A rule is data only: it names fields to look at, literal keywords
// and an RE2 pattern; it cannot fetch, write or send anything.
//
// Design and threat model: docs/rfcs/RFC-140-rule-packs.md.
package contentrule

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is the kind of a rule: the content pack kind it ships in.
type Kind string

// Kinds (= content pack kinds).
const (
	KindFingerprint Kind = "web-fingerprints"
	KindSecret      Kind = "secret-rules"
)

// IsValid reports whether k is a rule kind.
func (k Kind) IsValid() bool { return k == KindFingerprint || k == KindSecret }

// Conditions of a rule's matchers.
const (
	ConditionAny = "any"
	ConditionAll = "all"
)

// Location is the part of a web document a matcher reads.
type Location string

// Locations.
const (
	// LocBody is the response body (HTML, JS, JSON).
	LocBody Location = "body"
	// LocURL is the document's URL (and the final URL after redirects).
	LocURL Location = "url"
	// LocTitle is the HTML title.
	LocTitle Location = "title"
	// LocHeader is one response header value, named by Matcher.Header.
	LocHeader Location = "header"
	// LocCookie is a cookie name (values are never kept by the platform).
	LocCookie Location = "cookie"
	// LocFavicon is the favicon's MurmurHash3 (signed 32-bit decimal).
	LocFavicon Location = "favicon"
	// LocScript is a script source path or URL of the page.
	LocScript Location = "script"
)

func (l Location) valid() bool {
	switch l {
	case LocBody, LocURL, LocTitle, LocHeader, LocCookie, LocFavicon, LocScript:
		return true
	}
	return false
}

// secretLocation reports whether a secret rule may read l. Cookie names and
// favicon hashes hold no secret.
func (l Location) secretLocation() bool {
	switch l {
	case LocBody, LocURL, LocTitle, LocHeader, LocScript:
		return true
	}
	return false
}

// Bounds on a rule. Rules from organizations are hostile input: every
// string is capped and every pattern checked (CheckPattern).
const (
	MaxRuleIDLen      = 64
	MaxNameLen        = 128
	MaxDescriptionLen = 500
	MaxMatchers       = 8
	MaxKeywords       = 8
	MinKeywordLen     = 3
	MaxKeywordLen     = 64
	MaxFaviconHashes  = 16
	MaxHeaderNameLen  = 64
	MaxCPELen         = 255
	// MaxRulesPerPack bounds one pack's rules (all its files).
	MaxRulesPerPack = 2000
	// MaxRuleJSON bounds one stored organization rule.
	MaxRuleJSON = 16 << 10
	// DefaultConfidence is a fingerprint's confidence when the rule names
	// none: a rule reads what the site says about itself, which a hostile
	// site can fake.
	DefaultConfidence = 70
)

// Severities of a secret rule (the exposure severities).
var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true} //nolint:gochecknoglobals // static table

// Secret categories. credential-class categories become credential_leaked
// exposures, the others sensitive_data_exposed.
const (
	CategoryCredential   = "credential"
	CategoryToken        = "token"
	CategoryPrivateKey   = "private_key"
	CategoryInternalHost = "internal_host"
	CategoryPII          = "pii"
	CategoryDebug        = "debug"
)

var secretCategories = map[string]bool{ //nolint:gochecknoglobals // static table
	CategoryCredential: true, CategoryToken: true, CategoryPrivateKey: true,
	CategoryInternalHost: true, CategoryPII: true, CategoryDebug: true,
}

// IsCredentialCategory reports whether a category is a credential (a value
// that grants access) rather than other sensitive data.
func IsCredentialCategory(c string) bool {
	return c == CategoryCredential || c == CategoryToken || c == CategoryPrivateKey
}

var (
	ruleIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	headerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	faviconPattern    = regexp.MustCompile(`^-?[0-9]{1,10}$`)
)

// ErrInvalid marks a rule that cannot be used.
var ErrInvalid = fmt.Errorf("%w: invalid detection rule", shared.ErrValidation)

// Rule is one detection rule.
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Condition is "any" (default) or "all" of the matchers.
	Condition string    `yaml:"condition,omitempty" json:"condition,omitempty"`
	Matchers  []Matcher `yaml:"matchers" json:"matchers"`
	// Technology is what a fingerprint rule detects.
	Technology *Technology `yaml:"technology,omitempty" json:"technology,omitempty"`
	// Confidence of a fingerprint (1-100, default DefaultConfidence).
	Confidence int `yaml:"confidence,omitempty" json:"confidence,omitempty"`
	// Secret is what a secret rule finds.
	Secret *Secret `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// Matcher is one test on one location.
type Matcher struct {
	Location Location `yaml:"location" json:"location"`
	// Header names the header of a header matcher (lower case).
	Header string `yaml:"header,omitempty" json:"header,omitempty"`
	// Keywords are literals (case-insensitive); the pattern runs only near
	// one of them. Required for body and script matchers.
	Keywords []string `yaml:"keywords,omitempty" json:"keywords,omitempty"`
	// Pattern is an RE2 pattern. A named group "version" captures a
	// fingerprint's version, a named group "secret" the secret value.
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	// Hashes are favicon hashes of a favicon matcher.
	Hashes []string `yaml:"hashes,omitempty" json:"hashes,omitempty"`
}

// Technology is the product a fingerprint rule detects.
type Technology struct {
	Name     string `yaml:"name" json:"name"`
	Category string `yaml:"category,omitempty" json:"category,omitempty"`
	// CPE is a CPE 2.3 name; "{version}" is replaced by the detected
	// version, or "*" when there is none.
	CPE string `yaml:"cpe,omitempty" json:"cpe,omitempty"`
}

// Secret is what a secret rule finds.
type Secret struct {
	Category string `yaml:"category" json:"category"`
	Severity string `yaml:"severity" json:"severity"`
}

// File is the format of one rules file of a pack.
type File struct {
	Schema int    `yaml:"schema"`
	Rules  []Rule `yaml:"rules"`
}

// ParseFile decodes one rules file (YAML, schema 1) without validating the
// rules. Unknown keys are refused, so a typo is not a silently inert rule.
func ParseFile(data []byte) ([]Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: the file is not a rules file (YAML with schema and rules; a key is unknown or a value has the wrong type)", ErrInvalid)
	}
	if f.Schema != 1 {
		return nil, fmt.Errorf("%w: schema must be 1", ErrInvalid)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("%w: the file holds no rules", ErrInvalid)
	}
	if len(f.Rules) > MaxRulesPerPack {
		return nil, fmt.Errorf("%w: more than %d rules", ErrInvalid, MaxRulesPerPack)
	}
	return f.Rules, nil
}

// Validate checks a rule for its kind. It returns every problem found,
// joined, so an editor can show them all.
func (r *Rule) Validate(kind Kind) error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if !kind.IsValid() {
		return shared.NewDomainError(CodeInvalidRule, "unknown rule kind", ErrInvalid)
	}
	if !ruleIDPattern.MatchString(r.ID) {
		add("id must be 2-64 of a-z 0-9 . _ - and start with a letter or digit")
	}
	if !cleanString(r.Name, MaxNameLen) || strings.TrimSpace(r.Name) == "" {
		add("name is required (at most %d characters, no control characters)", MaxNameLen)
	}
	if !cleanString(r.Description, MaxDescriptionLen) {
		add("description is at most %d characters, no control characters", MaxDescriptionLen)
	}
	switch r.Condition {
	case "", ConditionAny, ConditionAll:
	default:
		add("condition must be any or all")
	}
	if len(r.Matchers) == 0 || len(r.Matchers) > MaxMatchers {
		add("a rule has 1-%d matchers", MaxMatchers)
	}
	switch kind {
	case KindFingerprint:
		if r.Secret != nil {
			add("a fingerprint rule has no secret block")
		}
		validateTechnology(r.Technology, add)
		if r.Confidence < 0 || r.Confidence > 100 {
			add("confidence is 1-100")
		}
	case KindSecret:
		if r.Technology != nil || r.Confidence != 0 {
			add("a secret rule has no technology or confidence")
		}
		switch {
		case r.Secret == nil:
			add("a secret rule needs a secret block (category, severity)")
		default:
			if !secretCategories[r.Secret.Category] {
				add("secret category must be one of credential, token, private_key, internal_host, pii, debug")
			}
			if !severities[r.Secret.Severity] {
				add("secret severity must be info, low, medium, high or critical")
			}
		}
		if r.Condition == ConditionAll {
			add("a secret rule matches on one matcher; condition all is not allowed")
		}
	}
	for i := range r.Matchers {
		for _, e := range r.Matchers[i].validate(kind) {
			add("matcher %d: %s", i+1, e)
		}
	}
	if len(errs) > 0 {
		return shared.NewDomainError(CodeInvalidRule, strings.Join(errs, "; "), ErrInvalid)
	}
	return nil
}

// CodeInvalidRule is the error code of a rule that fails validation.
const CodeInvalidRule = "DETECTION_RULE_INVALID"

func validateTechnology(t *Technology, add func(string, ...any)) {
	if t == nil {
		add("a fingerprint rule needs a technology block (name)")
		return
	}
	if assettech.Key(t.Name) == "" || len(t.Name) > assettech.MaxNameLen {
		add("technology name is required (at most %d characters)", assettech.MaxNameLen)
	}
	if t.Category != "" && !assettech.Category(t.Category).IsValid() {
		add("technology category must be one of the technology categories")
	}
	if t.CPE != "" {
		if len(t.CPE) > MaxCPELen || !strings.HasPrefix(t.CPE, "cpe:2.3:") || strings.Count(t.CPE, ":") != 12 || !cleanString(t.CPE, MaxCPELen) {
			add("technology cpe must be a CPE 2.3 name (13 parts); {version} marks the version")
		}
	}
}

func (m *Matcher) validate(kind Kind) []string {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if !m.Location.valid() {
		return []string{"location must be one of body, url, title, header, cookie, favicon, script"}
	}
	if kind == KindSecret && !m.Location.secretLocation() {
		add("a secret rule reads body, url, title, header or script")
	}
	if m.Location == LocHeader {
		if !headerNamePattern.MatchString(m.Header) {
			add("header names the header in lower case (a-z 0-9 -)")
		}
	} else if m.Header != "" {
		add("header is only for a header matcher")
	}
	if m.Location == LocFavicon {
		if len(m.Hashes) == 0 || len(m.Hashes) > MaxFaviconHashes {
			add("a favicon matcher has 1-%d hashes", MaxFaviconHashes)
		}
		for _, h := range m.Hashes {
			if !faviconPattern.MatchString(h) {
				add("favicon hash %q is not a 32-bit decimal", clipForMessage(h))
			}
		}
		if m.Pattern != "" || len(m.Keywords) > 0 {
			add("a favicon matcher has hashes only")
		}
		return errs
	}
	if len(m.Hashes) > 0 {
		add("hashes are only for a favicon matcher")
	}
	if len(m.Keywords) > MaxKeywords {
		add("at most %d keywords", MaxKeywords)
	}
	for _, k := range m.Keywords {
		if len(k) < MinKeywordLen || len(k) > MaxKeywordLen || !cleanString(k, MaxKeywordLen) || strings.TrimSpace(k) != k {
			add("keyword %q must be %d-%d characters without control characters or surrounding space", clipForMessage(k), MinKeywordLen, MaxKeywordLen)
		}
	}
	if (m.Location == LocBody || m.Location == LocScript) && len(m.Keywords) == 0 {
		add("a body or script matcher needs at least one keyword: the pattern runs only near one")
	}
	if m.Pattern == "" && len(m.Keywords) == 0 {
		add("a matcher needs a pattern or keywords")
	}
	if kind == KindSecret && m.Pattern == "" {
		add("a secret matcher needs a pattern")
	}
	if m.Pattern != "" {
		if err := CheckPattern(m.Pattern); err != nil {
			add("%s", strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
		}
	}
	return errs
}

// cleanString reports whether s is valid UTF-8 without control characters
// and at most n bytes.
func cleanString(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func clipForMessage(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}
