// Package aimask pseudonymises the context the platform sends to an AI model
// and turns the model's output back into real values.
//
// Every sensitive value in a bundle becomes a typed placeholder (DOMAIN_K3F9QA,
// IP_PRIV_7QK2M4, EMAIL_..., SECRET_1). The same value gets the same token
// within one run; the token suffix is a keyed hash (HMAC-SHA256 under a random
// per-run key), so a token says nothing about its value and the same value is a
// different token in another run or organization. Secrets are replaced by a
// counter token and are never kept in the mapping, so nothing can put them back.
// The mapping stays on the platform; only masked text leaves it.
//
// Design: docs/architecture/ai-context-masking.md.
package aimask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Class is the kind of value a placeholder stands for. It is also the token
// prefix, except for IP and CIDR, whose token carries the address class.
type Class string

const (
	ClassDomain  Class = "DOMAIN"
	ClassHost    Class = "HOST"
	ClassIP      Class = "IP"
	ClassCIDR    Class = "CIDR"
	ClassEmail   Class = "EMAIL"
	ClassUser    Class = "USER"
	ClassID      Class = "ID"
	ClassParam   Class = "PARAM"
	ClassOrg     Class = "ORG"
	ClassTicket  Class = "TICKET"
	ClassSecret  Class = "SECRET"
	ClassLiteral Class = "LIT"
)

// KeySize is the length of a run key in bytes.
const KeySize = 32

// suffixLen is the default token suffix length (30 bits of the keyed hash);
// a collision inside one run lengthens the suffix up to maxSuffixLen.
const (
	suffixLen    = 6
	maxSuffixLen = 16
)

// MaxTerms and MaxTermLen bound the organization's extra terms.
const (
	MaxTerms   = 200
	MaxTermLen = 128
	MinTermLen = 3
)

// ErrKey is returned for a run key of the wrong size.
var ErrKey = errors.New("aimask: run key must be 32 bytes")

// Policy says which classes are masked. Secrets and token-shaped input are
// always masked and are not part of the policy.
type Policy struct {
	Hosts     bool `json:"hosts"`      // registrable domains and internal host names
	IPs       bool `json:"ips"`        // addresses and CIDRs
	Emails    bool `json:"emails"`     // e-mail addresses
	Users     bool `json:"users"`      // user names (seeded only)
	URLParams bool `json:"url_params"` // id-like URL path segments and query values
	Orgs      bool `json:"orgs"`       // organization, customer and term names
	Tickets   bool `json:"tickets"`    // ticket ids such as KEY-123
	// MaskSubdomainLabels masks the labels left of the registrable domain
	// too: the whole name becomes one DOMAIN token.
	MaskSubdomainLabels bool `json:"mask_subdomain_labels"`
	// Terms are extra names (customers, project code names) masked as ORG.
	Terms []string `json:"terms,omitempty"`
}

// FullPolicy masks every class; the platform default and the policy for
// restricted data.
func FullPolicy() Policy {
	return Policy{Hosts: true, IPs: true, Emails: true, Users: true, URLParams: true, Orgs: true, Tickets: true}
}

// Placeholder is a token and its class, without the value (for previews).
type Placeholder struct {
	Token string `json:"token"`
	Class Class  `json:"class"`
}

// Binding ties one token to its real value. The investigation grant carries
// bindings for the job's subject only, so a tool boundary can resolve the
// subject's token and nothing else.
type Binding struct {
	Token string `json:"token"`
	Value string `json:"value"`
}

type secretInfo struct {
	kind   string
	length int
}

type seed struct {
	class Class
	value string
}

// Masker masks the text of one run. Not safe for concurrent use.
type Masker struct {
	key    []byte
	policy Policy

	byKey   map[string]string // class + 0x00 + normalised value -> token
	values  map[string]string // token -> value as first seen
	classes map[string]Class  // token -> class
	seeds   []seed
	secrets []secretInfo
	cidrs   map[string]netip.Prefix // token -> prefix (for membership facts)
	ips     map[string]netip.Addr   // token -> address
}

// New returns a masker for one run. runKey is 32 random bytes made for the
// run; it never leaves the platform.
func New(runKey []byte, p Policy) (*Masker, error) {
	if len(runKey) != KeySize {
		return nil, ErrKey
	}
	m := &Masker{
		key:     append([]byte(nil), runKey...),
		policy:  p,
		byKey:   map[string]string{},
		values:  map[string]string{},
		classes: map[string]Class{},
		cidrs:   map[string]netip.Prefix{},
		ips:     map[string]netip.Addr{},
	}
	for _, t := range p.Terms {
		t = strings.TrimSpace(t)
		if len(t) >= MinTermLen && len(t) <= MaxTermLen {
			m.seeds = append(m.seeds, seed{class: ClassOrg, value: t})
		}
	}
	return m, nil
}

// Policy returns the masker's policy.
func (m *Masker) Policy() Policy { return m.policy }

// enabled reports whether the policy masks a class.
func (m *Masker) enabled(c Class) bool {
	switch c {
	case ClassDomain, ClassHost:
		return m.policy.Hosts
	case ClassIP, ClassCIDR:
		return m.policy.IPs
	case ClassEmail:
		return m.policy.Emails
	case ClassUser:
		return m.policy.Users
	case ClassID, ClassParam:
		return m.policy.URLParams
	case ClassOrg:
		return m.policy.Orgs
	case ClassTicket:
		return m.policy.Tickets
	case ClassSecret, ClassLiteral:
		return true
	}
	return false
}

// Seed registers a known identifier of the subject (asset name, host, IP,
// owner, tenant name). Seeded values are masked exactly wherever they appear,
// before pattern detection runs. A value of a class the policy does not mask
// is kept but masked only by MaskStrict. Classes: DOMAIN or HOST (both use the host rule), IP, EMAIL,
// USER, ORG, TICKET.
func (m *Masker) Seed(c Class, value string) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 {
		return
	}
	if c == ClassDomain {
		c = ClassHost
	}
	switch c {
	case ClassHost, ClassIP, ClassEmail, ClassUser, ClassOrg, ClassTicket:
	default:
		return
	}
	if c == ClassUser || c == ClassOrg || c == ClassTicket {
		if len(value) < MinTermLen && c != ClassTicket {
			return
		}
	}
	m.seeds = append(m.seeds, seed{class: c, value: value})
}

// normalise is the form a value is hashed in: same value, same token.
func normalise(c Class, v string) string {
	switch c {
	case ClassDomain, ClassHost, ClassEmail:
		return strings.TrimSuffix(strings.ToLower(v), ".")
	case ClassUser, ClassOrg, ClassTicket:
		return strings.ToLower(strings.TrimSpace(v))
	case ClassIP:
		if a, err := netip.ParseAddr(v); err == nil {
			return a.Unmap().String()
		}
	case ClassCIDR:
		if p, err := netip.ParsePrefix(v); err == nil {
			return p.Masked().Addr().String()
		}
	}
	return v
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// token returns the placeholder for value under prefix (DOMAIN, IP_PRIV, ...).
// The class decides normalisation; prefix is what the model sees.
func (m *Masker) token(c Class, prefix, value string) string {
	norm := normalise(c, value)
	k := prefix + "\x00" + norm
	if t, ok := m.byKey[k]; ok {
		return t
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(prefix))
	mac.Write([]byte{0})
	mac.Write([]byte(norm))
	sum := b32.EncodeToString(mac.Sum(nil))
	for n := suffixLen; n <= maxSuffixLen; n++ {
		t := prefix + "_" + withDigit(sum[:n], sum[n])
		if _, taken := m.values[t]; !taken {
			m.byKey[k] = t
			m.values[t] = value
			m.classes[t] = c
			return t
		}
	}
	// 16 base32 characters of HMAC output colliding inside one run does
	// not happen; fall back to a counter suffix rather than fail.
	t := fmt.Sprintf("%s_%s%d", prefix, sum[:maxSuffixLen], len(m.values))
	m.byKey[k] = t
	m.values[t] = value
	m.classes[t] = c
	return t
}

// secretToken records a secret's type and length and returns SECRET_<n>.
// The value is not kept anywhere.
func (m *Masker) secretToken(kind string, length int) string {
	m.secrets = append(m.secrets, secretInfo{kind: kind, length: length})
	return fmt.Sprintf("SECRET_%d", len(m.secrets))
}

// Mapping returns a copy of token -> value for the reversible tokens. Secrets
// are never in it.
func (m *Masker) Mapping() map[string]string {
	out := make(map[string]string, len(m.values))
	for k, v := range m.values {
		out[k] = v
	}
	return out
}

// SecretCount is the number of SECRET_n tokens issued.
func (m *Masker) SecretCount() int { return len(m.secrets) }

// Placeholders lists every token issued, with its class and without values,
// sorted by token. SECRET tokens are included.
func (m *Masker) Placeholders() []Placeholder {
	out := make([]Placeholder, 0, len(m.values)+len(m.secrets))
	for t, c := range m.classes {
		out = append(out, Placeholder{Token: t, Class: c})
	}
	for i := range m.secrets {
		out = append(out, Placeholder{Token: fmt.Sprintf("SECRET_%d", i+1), Class: ClassSecret})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// Facts are trusted lines the platform states about the placeholders: which
// masked address is inside which masked network, and each secret's type and
// length. They go in the bundle as platform data, not as untrusted text.
func (m *Masker) Facts() []string {
	out := make([]string, 0, len(m.secrets))
	ipTokens := make([]string, 0, len(m.ips))
	for t := range m.ips {
		ipTokens = append(ipTokens, t)
	}
	sort.Strings(ipTokens)
	cidrTokens := make([]string, 0, len(m.cidrs))
	for t := range m.cidrs {
		cidrTokens = append(cidrTokens, t)
	}
	sort.Strings(cidrTokens)
	for _, it := range ipTokens {
		for _, ct := range cidrTokens {
			if m.cidrs[ct].Contains(m.ips[it]) {
				out = append(out, fmt.Sprintf("%s is in %s/%d", it, ct, m.cidrs[ct].Bits()))
			}
		}
	}
	for i, s := range m.secrets {
		out = append(out, fmt.Sprintf("SECRET_%d: %s, %d chars", i+1, s.kind, s.length))
	}
	return out
}

// Snapshot is what the platform stores (encrypted) to unmask a run's output
// later: the reversible mapping and the number of secrets issued.
type Snapshot struct {
	Tokens      map[string]string `json:"tokens"`
	Classes     map[string]Class  `json:"classes"`
	SecretCount int               `json:"secret_count"`
}

// Snapshot returns the run's mapping for storage.
func (m *Masker) Snapshot() Snapshot {
	cl := make(map[string]Class, len(m.classes))
	for k, v := range m.classes {
		cl[k] = v
	}
	return Snapshot{Tokens: m.Mapping(), Classes: cl, SecretCount: len(m.secrets)}
}

// BindingsFor returns the bindings for the subject's own targets, for the
// investigation grant: each value (a host name or an address) with the exact
// masked form the model sees for it ("db01.corp.DOMAIN_K3F9QA",
// "IP_PRIV_7QK2M4"). The tool boundary resolves only these whole forms, so
// "other.DOMAIN_K3F9QA" never resolves even though it shares the domain token.
func (m *Masker) BindingsFor(values ...string) []Binding {
	seen := map[string]bool{}
	out := make([]Binding, 0, len(values))
	for _, v := range values {
		v = strings.TrimSuffix(strings.TrimSpace(v), ".")
		if v == "" {
			continue
		}
		var masked string
		if a, err := netip.ParseAddr(v); err == nil {
			if !m.enabled(ClassIP) {
				continue
			}
			masked = m.ipToken(a)
		} else {
			if !m.enabled(ClassHost) {
				continue
			}
			masked = m.maskHost(v)
		}
		if !seen[masked] {
			seen[masked] = true
			out = append(out, Binding{Token: masked, Value: v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// withDigit makes sure a suffix holds a digit (base32 digits are 2-7), so a
// token is never an ordinary upper-case word; the replaced character is
// derived from the hash, so the suffix stays deterministic.
func withDigit(suffix string, next byte) string {
	if strings.ContainsAny(suffix, "234567") {
		return suffix
	}
	return suffix[:len(suffix)-1] + string(rune('2'+next%6))
}
