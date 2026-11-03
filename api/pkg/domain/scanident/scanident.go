// Package scanident holds the scan identification markers: the User-Agent
// and request headers a sensor's tools send to targets, so the targets' WAF,
// SIEM and logs can tell the organization's scan traffic apart.
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
	"slices"
	"strings"

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
	// UserAgentEnforced: no organization or program replaces the
	// User-Agent, and the sensor's local policy may not either.
	UserAgentEnforced bool     `json:"user_agent_enforced,omitempty"`
	Headers           []Header `json:"headers,omitempty"`
}

// Normalized returns the layer trimmed.
func (p PlatformLayer) Normalized() PlatformLayer {
	p.UserAgent = strings.TrimSpace(p.UserAgent)
	if p.UserAgent == "" {
		p.UserAgentEnforced = false
	}
	p.Headers = Normalize(p.Headers)
	return p
}

// Validate checks the layer.
func (p PlatformLayer) Validate() error {
	if err := CheckUserAgent(p.UserAgent); err != nil {
		return err
	}
	return CheckHeaders(p.Headers, MaxPlatformHeaders, true)
}

// OrganizationLayer is the organization's own layer.
type OrganizationLayer struct {
	UserAgent string
	Headers   []Header
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
	UserAgent       string   `json:"user_agent,omitempty"`
	UserAgentSource string   `json:"user_agent_source,omitempty"`
	UserAgentLocked bool     `json:"user_agent_locked,omitempty"`
	Headers         []Marker `json:"headers"`
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
	switch {
	case p.UserAgent != "" && p.UserAgentEnforced:
		out.UserAgent, out.UserAgentSource, out.UserAgentLocked = p.UserAgent, SourcePlatformEnforced, true
	case org.UserAgent != "":
		out.UserAgent, out.UserAgentSource = org.UserAgent, SourceOrganization
	case p.UserAgent != "":
		out.UserAgent, out.UserAgentSource = p.UserAgent, SourcePlatform
	}
	return out
}

// Overlay puts a more specific layer's headers and User-Agent over e (a
// bug-bounty program's rules): locked names and a locked User-Agent are
// kept; every other clash takes the overlay's value, and the overlay's
// names become locked. It fails when the result would carry more than
// MaxHeaders.
func (e Effective) Overlay(headers map[string]string, userAgent, source string) (Effective, error) {
	out := Effective{UserAgent: e.UserAgent, UserAgentSource: e.UserAgentSource, UserAgentLocked: e.UserAgentLocked,
		Headers: slices.Clone(e.Headers)}
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
	if userAgent != "" && !out.UserAgentLocked {
		out.UserAgent, out.UserAgentSource, out.UserAgentLocked = userAgent, source, true
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
