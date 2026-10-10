// Package bountyprogram holds bug-bounty and disclosure programs a person in
// the organization tests under the program's published rules: the program,
// its rules, its parsed scope and the terms a person attests to.
// Design: docs/rfcs/RFC-065-bug-bounty-programs.md.
package bountyprogram

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status of a program.
type Status string

// Statuses.
const (
	StatusActive Status = "active"
	StatusPaused Status = "paused"
	StatusEnded  Status = "ended"
)

// ScopeSourcePaste: the scope was pasted by a person (not authoritative).
const ScopeSourcePaste = "paste"

// ScopeSourceFileImport is a scope read from a file the person imported
// (RFC-065 §15.2).
const ScopeSourceFileImport = "file_import"

// Bounds.
const (
	MaxNameLength     = 200
	MaxPlatformLength = 50
	MaxHandleLength   = 100
	MaxURLLength      = 500
	MaxHeaders        = 10
	MaxHeaderName     = 64
	MaxHeaderValue    = 200
	MaxUserAgent      = 200
	MaxNotes          = 4000
	MaxRateLimitRPS   = 1000
	// MaxTermsText bounds the program terms a person pastes (policy,
	// confidentiality terms).
	MaxTermsText = 20000
)

// Visibility of a program (RFC-065 §15.3).
type Visibility string

// Visibilities. A private program, its scope, rules and terms are visible
// only to its members and the organization's owners, and every view of its
// details is audited; a public one follows the program data scope.
const (
	VisibilityPrivate Visibility = "private"
	VisibilityPublic  Visibility = "public"
)

// ParseVisibility reads a visibility; "" is private (the safe default).
func ParseVisibility(s string) (Visibility, error) {
	switch Visibility(strings.TrimSpace(s)) {
	case "", VisibilityPrivate:
		return VisibilityPrivate, nil
	case VisibilityPublic:
		return VisibilityPublic, nil
	}
	return "", fmt.Errorf("%w: visibility must be private or public", shared.ErrValidation)
}

// Forbidden techniques a program may list.
const (
	ForbidDoS               = "dos"
	ForbidAutomatedScanning = "automated_scanning"
	ForbidIntrusive         = "intrusive"
	ForbidSocialEngineering = "social_engineering"
	ForbidPhysical          = "physical"
	ForbidBruteforce        = "bruteforce"
)

var knownForbidden = []string{ForbidDoS, ForbidAutomatedScanning, ForbidIntrusive,
	ForbidSocialEngineering, ForbidPhysical, ForbidBruteforce}

// Header is a request header the program asks researchers to send.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Rules are the program's testing rules (RFC-065 §5.3).
type Rules struct {
	RateLimitRPS    int      `json:"rate_limit_rps,omitempty"`
	RequiredHeaders []Header `json:"required_headers,omitempty"`
	UserAgent       string   `json:"user_agent,omitempty"`
	Forbidden       []string `json:"forbidden,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	// TestingWindows: when the program allows testing (none: any time).
	TestingWindows []TestingWindow `json:"testing_windows,omitempty"`
}

// Normalize trims the rules and sorts the forbidden list (the terms hash
// must not depend on the order a person typed them).
func (r Rules) Normalize() Rules {
	out := Rules{RateLimitRPS: r.RateLimitRPS, UserAgent: strings.TrimSpace(r.UserAgent), Notes: strings.TrimSpace(r.Notes)}
	for _, w := range r.TestingWindows {
		w.Timezone = strings.TrimSpace(w.Timezone)
		w.Days = lower(w.Days)
		out.TestingWindows = append(out.TestingWindows, w)
	}
	for _, h := range r.RequiredHeaders {
		out.RequiredHeaders = append(out.RequiredHeaders, Header{Name: strings.TrimSpace(h.Name), Value: strings.TrimSpace(h.Value)})
	}
	seen := map[string]bool{}
	for _, f := range r.Forbidden {
		f = strings.ToLower(strings.TrimSpace(f))
		if f != "" && !seen[f] {
			seen[f] = true
			out.Forbidden = append(out.Forbidden, f)
		}
	}
	slices.Sort(out.Forbidden)
	return out
}

// Validate checks the bounds. Header names are HTTP tokens; no value may
// carry a control character (no header injection into a sensor's request).
func (r Rules) Validate() error {
	switch {
	case r.RateLimitRPS < 0 || r.RateLimitRPS > MaxRateLimitRPS:
		return fmt.Errorf("%w: rate_limit_rps must be between 0 and %d", shared.ErrValidation, MaxRateLimitRPS)
	case len(r.RequiredHeaders) > MaxHeaders:
		return fmt.Errorf("%w: at most %d required headers", shared.ErrValidation, MaxHeaders)
	case len(r.UserAgent) > MaxUserAgent || hasControl(r.UserAgent):
		return fmt.Errorf("%w: user_agent must be at most %d printable characters", shared.ErrValidation, MaxUserAgent)
	case len(r.Notes) > MaxNotes:
		return fmt.Errorf("%w: notes must be at most %d characters", shared.ErrValidation, MaxNotes)
	}
	for _, h := range r.RequiredHeaders {
		if h.Name == "" || len(h.Name) > MaxHeaderName || !isToken(h.Name) {
			return fmt.Errorf("%w: header name %q is not a valid HTTP header name", shared.ErrValidation, clip(h.Name))
		}
		if refusedHeader(h.Name) {
			return fmt.Errorf("%w: header %s cannot be required (credentials and connection headers are refused)", shared.ErrValidation, h.Name)
		}
		if len(h.Value) > MaxHeaderValue || hasControl(h.Value) {
			return fmt.Errorf("%w: header %s: the value must be at most %d printable characters", shared.ErrValidation, h.Name, MaxHeaderValue)
		}
	}
	if len(r.TestingWindows) > MaxTestingWindows {
		return fmt.Errorf("%w: at most %d testing windows", shared.ErrValidation, MaxTestingWindows)
	}
	for _, w := range r.TestingWindows {
		if err := w.Validate(); err != nil {
			return err
		}
	}
	for _, f := range r.Forbidden {
		if !slices.Contains(knownForbidden, f) {
			return fmt.Errorf("%w: unknown forbidden technique %q", shared.ErrValidation, clip(f))
		}
	}
	return nil
}

// Forbids reports whether the program forbids a technique.
func (r Rules) Forbids(t string) bool { return slices.Contains(r.Forbidden, t) }

// MaxTier is the highest probe tier a program's entries allow: T1, or T0
// when the program forbids automated scanning (RFC-065 B6). T2 is never
// allowed for a program entry.
func (r Rules) MaxTier() scope.Tier {
	if r.Forbids(ForbidAutomatedScanning) {
		return scope.TierPassive
	}
	return scope.TierActive
}

func isToken(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII || !(unicode.IsLetter(c) || unicode.IsDigit(c) || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// Program is one program the organization follows.
type Program struct {
	ID         shared.ID
	TenantID   shared.ID
	Name       string
	Platform   string
	Handle     string
	ProgramURL string
	Visibility Visibility
	// TermsText is the program's own terms as the person pasted them
	// (policy, confidentiality terms); part of the attested terms.
	TermsText     string
	Status        Status
	ScopeSource   string
	Rules         Rules
	ScopeItems    []Item
	TermsSHA256   string
	AcceptedBy    *shared.ID
	AcceptedAt    *time.Time
	GroupID       *shared.ID
	CreatedBy     *shared.ID
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Authoritative bool
	// Sync is the scope source settings and state (program_api,
	// program_file; RFC-065 §14).
	Sync Sync
	// Pending is a widening a sync found, waiting for a member.
	Pending *PendingTerms
}

// Program errors.
var (
	ErrNotFound      = shared.NewDomainError("PROGRAM_NOT_FOUND", "program not found", shared.ErrNotFound)
	ErrNameTaken     = shared.NewDomainError("PROGRAM_NAME_TAKEN", "a program with this name already exists", shared.ErrConflict)
	ErrTermsChanged  = shared.NewDomainError("PROGRAM_TERMS_CHANGED", "the program's terms differ from the ones you accepted; review the preview and accept again", shared.ErrConflict)
	ErrTermsRequired = shared.NewDomainError("PROGRAM_TERMS_REQUIRED", "accept the program's terms (accept_terms_sha256 from the preview)", shared.ErrValidation)
	ErrNotActive     = shared.NewDomainError("PROGRAM_NOT_ACTIVE", "the program is not active", shared.ErrConflict)
	ErrEnded         = shared.NewDomainError("PROGRAM_ENDED", "the program has ended", shared.ErrConflict)
	// ErrAttestationRequired: a private program's details need the
	// caller's own acceptance of its current terms (RFC-065 §15.3).
	ErrAttestationRequired = shared.NewDomainError("PROGRAM_ATTESTATION_REQUIRED",
		"accept this program's terms and confidentiality before working with it", shared.ErrConflict)
)

// IsPrivate reports whether the program is private (anything but public).
func (p *Program) IsPrivate() bool { return p.Visibility != VisibilityPublic }

// ValidateDetails checks the descriptive fields of a program.
func ValidateDetails(name, platform, handle, programURL string) error {
	switch {
	case strings.TrimSpace(name) == "" || len(name) > MaxNameLength || hasControl(name):
		return fmt.Errorf("%w: name is required (at most %d characters)", shared.ErrValidation, MaxNameLength)
	case len(platform) > MaxPlatformLength || hasControl(platform):
		return fmt.Errorf("%w: platform must be at most %d characters", shared.ErrValidation, MaxPlatformLength)
	case len(handle) > MaxHandleLength || hasControl(handle):
		return fmt.Errorf("%w: handle must be at most %d characters", shared.ErrValidation, MaxHandleLength)
	case len(programURL) > MaxURLLength:
		return fmt.Errorf("%w: program_url must be at most %d characters", shared.ErrValidation, MaxURLLength)
	}
	if strings.TrimSpace(programURL) == "" {
		// A private program's page is behind its platform's login; the
		// link is optional.
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(programURL))
	if err != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: program_url must be an https:// link to the program's policy", shared.ErrValidation)
	}
	return nil
}

// ValidateTermsText checks the pasted terms.
func ValidateTermsText(s string) error {
	if len(s) > MaxTermsText || strings.ContainsRune(s, 0) {
		return fmt.Errorf("%w: terms must be at most %d characters", shared.ErrValidation, MaxTermsText)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Terms
// ---------------------------------------------------------------------------

// Terms are what a person attests to (RFC-065 §5.4).
type Terms struct {
	ProgramURL string   `json:"program_url"`
	Rules      Rules    `json:"rules"`
	InScope    []string `json:"in_scope"`
	OutOfScope []string `json:"out_of_scope"`
	// Text is the program's own terms text; absent when there is none, so
	// programs without one keep their hash.
	Text string `json:"text,omitempty"`
}

// WithText adds the program's terms text.
func (t Terms) WithText(text string) Terms {
	t.Text = strings.TrimSpace(text)
	return t
}

// NewTerms builds the terms of a program from its parsed items.
func NewTerms(programURL string, rules Rules, items []Item) Terms {
	t := Terms{ProgramURL: strings.TrimSpace(programURL), Rules: rules.Normalize(), InScope: []string{}, OutOfScope: []string{}}
	for _, it := range items {
		key := it.Raw
		if it.Pattern != "" {
			key = string(it.TargetType) + ":" + it.Pattern
		}
		if it.InScope {
			t.InScope = append(t.InScope, key)
		} else {
			t.OutOfScope = append(t.OutOfScope, key)
		}
	}
	slices.Sort(t.InScope)
	slices.Sort(t.OutOfScope)
	return t
}

// SHA256 is the hex SHA-256 of the canonical JSON of the terms.
func (t Terms) SHA256() string {
	b, _ := json.Marshal(t) // struct of strings and ints: never fails
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Plan: items -> entries and program exclusions
// ---------------------------------------------------------------------------

// Planned is one scope entry or program exclusion an import creates.
type Planned struct {
	TargetType scope.TargetType `json:"target_type"`
	Pattern    string           `json:"pattern"`
	// Reason says why a program exclusion exists.
	Reason string `json:"reason,omitempty"`
}

// Plan is what an import creates.
type Plan struct {
	Entries      []Planned `json:"entries"`
	Exclusions   []Planned `json:"exclusions"`
	NotScannable []Item    `json:"not_scannable"`
}

// Reasons of program exclusions.
const (
	ReasonOutOfScope    = "out of scope for the program"
	ReasonApexNotListed = "the program lists the wildcard but not the domain itself"
)

// PlanScope turns parsed items into entries and program exclusions. A
// wildcard *.x whose apex x is not listed in scope gets a program exclusion
// of exactly x (RFC-065 B8).
func PlanScope(items []Item) Plan {
	p := Plan{Entries: []Planned{}, Exclusions: []Planned{}, NotScannable: []Item{}}
	inDomains := map[string]bool{}
	excluded := map[string]bool{}
	for _, it := range items {
		if it.InScope && it.Kind == KindDomain {
			inDomains[it.Pattern] = true
		}
		if !it.InScope && it.Scannable() {
			excluded[string(it.TargetType)+":"+it.Pattern] = true
		}
	}
	for _, it := range items {
		switch {
		case !it.Scannable():
			p.NotScannable = append(p.NotScannable, it)
		case it.InScope:
			p.Entries = append(p.Entries, Planned{TargetType: it.TargetType, Pattern: it.Pattern})
			if it.Kind == KindWildcard {
				apex := strings.TrimPrefix(it.Pattern, "*.")
				key := string(scope.TargetTypeDomain) + ":" + apex
				if !inDomains[apex] && !excluded[key] {
					excluded[key] = true
					p.Exclusions = append(p.Exclusions, Planned{TargetType: scope.TargetTypeDomain, Pattern: apex, Reason: ReasonApexNotListed})
				}
			}
		default:
			p.Exclusions = append(p.Exclusions, Planned{TargetType: it.TargetType, Pattern: it.Pattern, Reason: ReasonOutOfScope})
		}
	}
	return p
}

// refusedHeaders cannot be required by a program: credentials and the
// headers the HTTP client and the forwarder own (the sensor refuses them
// too).
var refusedHeaders = map[string]bool{"authorization": true, "cookie": true, "host": true, "content-length": true,
	"transfer-encoding": true, "connection": true, "upgrade": true, "te": true, "trailer": true, "keep-alive": true}

func refusedHeader(name string) bool {
	n := strings.ToLower(name)
	return refusedHeaders[n] || strings.HasPrefix(n, "proxy-")
}
