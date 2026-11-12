// Package scanident holds the scan identification markers: the User-Agent
// (one value or a rotation list), the request headers and one query
// parameter a sensor's tools send to targets, so the targets' WAF, SIEM and
// logs can tell the organization's scan traffic apart. Any layer may require
// identification: a job then never leaves without a header or the query
// parameter, and the sensor refuses a task whose requests could not carry
// them.
//
// Markers come from layers that are merged, never replaced: the platform
// (an instance-wide default, each header optionally enforced), the
// organization, and bug-bounty program rules over them. Every distinct name
// is kept; on a clash (names are case-insensitive) the more specific layer
// wins, except that an enforced platform header is never overridden. The
// platform writes the merged set into a job's http_policy at delivery; the
// sensor adds its host owner's local layer and may not change a locked name.
//
// The rules here mirror the sensor's (sdk-go core.OrgHTTPPolicy.Validate):
// a value the platform accepts is one the sensor accepts.
//
// Design: docs/architecture/scan-identification.md.
package scanident

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/openctemio/contract/identity"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bounds of the markers.
const (
	// MaxHeaders is the most headers a job carries after the merge (the
	// sensor refuses more).
	MaxHeaders = 10
	// MaxPlatformHeaders and MaxOrganizationHeaders bound each layer, so
	// the two always fit in MaxHeaders together.
	MaxPlatformHeaders     = 4
	MaxOrganizationHeaders = 6
	MaxHeaderName          = 64
	MaxHeaderValue         = 200
	MaxUserAgent           = 256
)

// Sources of a merged marker.
const (
	SourcePlatform         = "platform"
	SourcePlatformEnforced = "platform_enforced"
	SourceOrganization     = "organization"
	SourceProgram          = "program"
)

// Header is one request header of a layer. Enforced is meaningful only on
// the platform layer.
type Header struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Enforced bool   `json:"enforced,omitempty"`
}

// refused are the names no layer may set: the headers the HTTP client and
// the forwarder own (setting them breaks the transport or the proxy chain),
// and credentials, which never travel as a plain marker.
var refused = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"keep-alive": true, "te": true, "trailer": true, "upgrade": true,
	"authorization": true, "cookie": true,
}

// IsToken reports whether s is a non-empty RFC 7230 token.
func IsToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// PrintableASCII reports whether s is printable ASCII only (0x20-0x7e): no
// CR, LF or other control character can reach a request line.
func PrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// RefusedName reports whether name may not be set as a marker.
func RefusedName(name string) bool {
	n := strings.ToLower(name)
	return refused[n] || strings.HasPrefix(n, "proxy-")
}

// CheckHeader validates one header's name and value.
func CheckHeader(name, value string) error {
	switch {
	case len(name) > MaxHeaderName || !IsToken(name):
		return fmt.Errorf("%w: header name %q must be 1-%d letters, digits or !#$%%&'*+-.^_`|~ (no space or colon)",
			shared.ErrValidation, clip(name), MaxHeaderName)
	case RefusedName(name):
		return fmt.Errorf("%w: header %s cannot be set (connection, proxy and credential headers are refused)",
			shared.ErrValidation, name)
	case len(value) > MaxHeaderValue || !PrintableASCII(value):
		return fmt.Errorf("%w: header %s: the value must be at most %d printable ASCII characters (no line breaks)",
			shared.ErrValidation, name, MaxHeaderValue)
	}
	return nil
}

// CheckUserAgent validates a User-Agent (empty: none).
func CheckUserAgent(ua string) error {
	if len(ua) > MaxUserAgent || !PrintableASCII(ua) {
		return fmt.Errorf("%w: the User-Agent must be at most %d printable ASCII characters", shared.ErrValidation, MaxUserAgent)
	}
	return nil
}

// CheckUserAgents validates a layer's User-Agent setting: one value or a
// rotation list (contract identity.CheckUserAgents: at most 200 distinct
// values of 1-256 printable ASCII characters), never both.
func CheckUserAgents(single string, list []string) error {
	if err := CheckUserAgent(single); err != nil {
		return err
	}
	if single != "" && len(list) > 0 {
		return fmt.Errorf("%w: set either one User-Agent or a rotation list, not both (clear the single User-Agent to rotate over the list)",
			shared.ErrValidation)
	}
	if err := identity.CheckUserAgents(list); err != nil {
		return fmt.Errorf("%w: %s", shared.ErrValidation, strings.Replace(err.Error(), identity.ErrInvalid.Error()+": ", "", 1))
	}
	return nil
}

// NormalizeUserAgents trims every value and drops the empty ones (a blank
// line of the console's text area). A nil or empty result is nil.
func NormalizeUserAgents(list []string) []string {
	var out []string
	for _, v := range list {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// UserAgentConfig is a layer's User-Agent setting as one list: its rotation
// list, else its single value, else none.
func UserAgentConfig(single string, list []string) []string {
	if len(list) > 0 {
		return slices.Clone(list)
	}
	if single != "" {
		return []string{single}
	}
	return nil
}

// Query is the identification query parameter added to every request URL.
type Query struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MaxQueryPart bounds the query parameter's name and value.
const MaxQueryPart = 64

// queryPartRE: characters that need no percent-encoding anywhere in a URL
// (the sensor's rule, sdk-go core.HTTPQuery).
var queryPartRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// CheckQuery validates the query parameter (nil: none).
func CheckQuery(q *Query) error {
	if q == nil {
		return nil
	}
	if !queryPartRE.MatchString(q.Name) || !queryPartRE.MatchString(q.Value) {
		return fmt.Errorf("%w: the query parameter's name and value must each be 1-%d letters, digits or . _ ~ -",
			shared.ErrValidation, MaxQueryPart)
	}
	return nil
}

// NormalizeQuery trims the parameter; one with neither a name nor a value
// is none.
func NormalizeQuery(q *Query) *Query {
	if q == nil {
		return nil
	}
	out := Query{Name: strings.TrimSpace(q.Name), Value: strings.TrimSpace(q.Value)}
	if out.Name == "" && out.Value == "" {
		return nil
	}
	return &out
}

// Normalize trims every name and value. A nil list stays nil.
func Normalize(hs []Header) []Header {
	if hs == nil {
		return nil
	}
	out := make([]Header, 0, len(hs))
	for _, h := range hs {
		out = append(out, Header{Name: strings.TrimSpace(h.Name), Value: strings.TrimSpace(h.Value), Enforced: h.Enforced})
	}
	return out
}

// CheckHeaders validates a layer's list: each header, at most limit of
// them, no name twice (case-insensitive). allowEnforced is true only for
// the platform layer.
func CheckHeaders(hs []Header, limit int, allowEnforced bool) error {
	if len(hs) > limit {
		return fmt.Errorf("%w: at most %d headers", shared.ErrValidation, limit)
	}
	seen := make(map[string]bool, len(hs))
	for _, h := range hs {
		if err := CheckHeader(h.Name, h.Value); err != nil {
			return err
		}
		if h.Enforced && !allowEnforced {
			return fmt.Errorf("%w: header %s: only the platform can enforce a header", shared.ErrValidation, h.Name)
		}
		key := strings.ToLower(h.Name)
		if seen[key] {
			return fmt.Errorf("%w: header %s is listed twice (names are case-insensitive)", shared.ErrValidation, h.Name)
		}
		seen[key] = true
	}
	return nil
}

// PlatformLayer is the instance-wide layer an administrator sets.
type PlatformLayer struct {
	UserAgent string `json:"user_agent,omitempty"`
	// UserAgents is a rotation list (instead of UserAgent).
	UserAgents []string `json:"user_agents,omitempty"`
	// UserAgentEnforced: no organization or program replaces the
	// User-Agent or the list, and the sensor's local policy may not either.
	UserAgentEnforced bool     `json:"user_agent_enforced,omitempty"`
	Headers           []Header `json:"headers,omitempty"`
	// Query is the identification query parameter; QueryEnforced: no
	// organization replaces it.
	Query         *Query `json:"query,omitempty"`
	QueryEnforced bool   `json:"query_enforced,omitempty"`
	// IdentificationRequired: every organization's jobs must carry a header
	// or the query parameter on every request (no lower layer clears it).
	IdentificationRequired bool `json:"identification_required,omitempty"`
}

// Normalized returns the layer trimmed.
func (p PlatformLayer) Normalized() PlatformLayer {
	p.UserAgent = strings.TrimSpace(p.UserAgent)
	p.UserAgents = NormalizeUserAgents(p.UserAgents)
	if p.UserAgent == "" && len(p.UserAgents) == 0 {
		p.UserAgentEnforced = false
	}
	p.Headers = Normalize(p.Headers)
	p.Query = NormalizeQuery(p.Query)
	if p.Query == nil {
		p.QueryEnforced = false
	}
	return p
}

// Validate checks the layer.
func (p PlatformLayer) Validate() error {
	if err := CheckUserAgents(p.UserAgent, p.UserAgents); err != nil {
		return err
	}
	if err := CheckQuery(p.Query); err != nil {
		return err
	}
	return CheckHeaders(p.Headers, MaxPlatformHeaders, true)
}

// OrganizationLayer is the organization's own layer.
type OrganizationLayer struct {
	UserAgent              string
	UserAgents             []string
	Headers                []Header
	Query                  *Query
	IdentificationRequired bool
}

// Marker is one merged header with the layer it came from.
type Marker struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
	// Locked: the sensor's local layer may not change it (an enforced
	// platform header or a program's).
	Locked bool `json:"locked,omitempty"`
}

// Effective is the merged identity a job carries.
type Effective struct {
	// UserAgent is the first value of UserAgents (what a sensor without
	// rotation sends); UserAgents is the winning layer's whole list (one
	// value when it set a single User-Agent).
	UserAgent       string   `json:"user_agent,omitempty"`
	UserAgents      []string `json:"user_agents,omitempty"`
	UserAgentSource string   `json:"user_agent_source,omitempty"`
	UserAgentLocked bool     `json:"user_agent_locked,omitempty"`
	Headers         []Marker `json:"headers"`
	Query           *Query   `json:"query,omitempty"`
	QuerySource     string   `json:"query_source,omitempty"`
	QueryLocked     bool     `json:"query_locked,omitempty"`
	// IdentificationRequired is the OR of every layer; RequiredBy names the
	// layers that ask for it.
	IdentificationRequired bool     `json:"identification_required,omitempty"`
	RequiredBy             []string `json:"required_by,omitempty"`
}

// HasIdentification reports whether the identity carries a header or the
// query parameter. The User-Agent does not count: it may rotate and is
// copied by anyone.
func (e Effective) HasIdentification() bool {
	return len(e.Headers) > 0 || e.Query != nil
}

func (e *Effective) setUserAgents(list []string, source string, locked bool) {
	e.UserAgents, e.UserAgent, e.UserAgentSource, e.UserAgentLocked = list, list[0], source, locked
}

func (e *Effective) require(source string) {
	e.IdentificationRequired = true
	if !slices.Contains(e.RequiredBy, source) {
		e.RequiredBy = append(e.RequiredBy, source)
	}
}

// Merge combines the platform and organization layers: the union of their
// headers, the organization's value winning a clash unless the platform
// enforces the header. Order: the platform's headers first (in their
// order), then the organization's new ones.
func Merge(p PlatformLayer, org OrganizationLayer) Effective {
	var out Effective
	idx := map[string]int{}
	for _, h := range p.Headers {
		src := SourcePlatform
		if h.Enforced {
			src = SourcePlatformEnforced
		}
		idx[strings.ToLower(h.Name)] = len(out.Headers)
		out.Headers = append(out.Headers, Marker{Name: h.Name, Value: h.Value, Source: src, Locked: h.Enforced})
	}
	for _, h := range org.Headers {
		key := strings.ToLower(h.Name)
		if i, ok := idx[key]; ok {
			if out.Headers[i].Locked {
				continue
			}
			out.Headers[i] = Marker{Name: h.Name, Value: h.Value, Source: SourceOrganization}
			continue
		}
		idx[key] = len(out.Headers)
		out.Headers = append(out.Headers, Marker{Name: h.Name, Value: h.Value, Source: SourceOrganization})
	}
	// The winning layer's User-Agent setting is used whole, never merged.
	platUA, orgUA := UserAgentConfig(p.UserAgent, p.UserAgents), UserAgentConfig(org.UserAgent, org.UserAgents)
	switch {
	case len(platUA) > 0 && p.UserAgentEnforced:
		out.setUserAgents(platUA, SourcePlatformEnforced, true)
	case len(orgUA) > 0:
		out.setUserAgents(orgUA, SourceOrganization, false)
	case len(platUA) > 0:
		out.setUserAgents(platUA, SourcePlatform, false)
	}
	switch {
	case p.Query != nil && p.QueryEnforced:
		q := *p.Query
		out.Query, out.QuerySource, out.QueryLocked = &q, SourcePlatformEnforced, true
	case org.Query != nil:
		q := *org.Query
		out.Query, out.QuerySource = &q, SourceOrganization
	case p.Query != nil:
		q := *p.Query
		out.Query, out.QuerySource = &q, SourcePlatform
	}
	if p.IdentificationRequired {
		out.require(SourcePlatform)
	}
	if org.IdentificationRequired {
		out.require(SourceOrganization)
	}
	return out
}

// OverlayLayer is what a more specific layer (a bug-bounty program's rules)
// puts over a merged identity.
type OverlayLayer struct {
	Headers map[string]string
	// UserAgents is the layer's User-Agent setting (UserAgentConfig).
	UserAgents             []string
	IdentificationRequired bool
}

// Overlay puts a more specific layer's headers, User-Agent setting and
// requirement over e (a bug-bounty program's rules): locked names and a
// locked User-Agent are kept; every other clash takes the overlay's value,
// and the overlay's names and list become locked. The requirement only adds.
// It fails when the result would carry more than MaxHeaders.
func (e Effective) Overlay(o OverlayLayer, source string) (Effective, error) {
	headers := o.Headers
	out := e
	out.Headers = slices.Clone(e.Headers)
	out.UserAgents = slices.Clone(e.UserAgents)
	out.RequiredBy = slices.Clone(e.RequiredBy)
	if e.Query != nil {
		q := *e.Query
		out.Query = &q
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	slices.Sort(names) // deterministic order
	for _, n := range names {
		i := slices.IndexFunc(out.Headers, func(m Marker) bool { return strings.EqualFold(m.Name, n) })
		switch {
		case i >= 0 && out.Headers[i].Locked && out.Headers[i].Source == SourcePlatformEnforced:
			continue
		case i >= 0:
			out.Headers[i] = Marker{Name: n, Value: headers[n], Source: source, Locked: true}
		default:
			out.Headers = append(out.Headers, Marker{Name: n, Value: headers[n], Source: source, Locked: true})
		}
	}
	if len(out.Headers) > MaxHeaders {
		return e, fmt.Errorf("%w: the job would carry %d identification headers (platform, organization and program together); at most %d",
			shared.ErrValidation, len(out.Headers), MaxHeaders)
	}
	if len(o.UserAgents) > 0 && !out.UserAgentLocked {
		out.setUserAgents(slices.Clone(o.UserAgents), source, true)
	}
	if o.IdentificationRequired {
		out.require(source)
	}
	return out, nil
}

// HeaderMap is the headers as the job's http_policy carries them.
func (e Effective) HeaderMap() map[string]string {
	if len(e.Headers) == 0 {
		return nil
	}
	m := make(map[string]string, len(e.Headers))
	for _, h := range e.Headers {
		m[h.Name] = h.Value
	}
	return m
}

// LockedNames are the header names the sensor's local layer may not change.
func (e Effective) LockedNames() []string {
	var out []string
	for _, h := range e.Headers {
		if h.Locked {
			out = append(out, h.Name)
		}
	}
	return out
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
