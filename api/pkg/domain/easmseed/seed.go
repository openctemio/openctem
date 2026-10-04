// Package easmseed holds EASM seeds: what the organization says is its own,
// from which discovery expands (RFC-036 §5.1, §6.3).
//
// A seed is an assertion by the tenant, recorded with who attested it and
// when. Proof of ownership is separate: a root_domain seed counts as verified
// only while the tenant has a verified DNS TXT record for that domain or a
// parent (verified_domains, the SSO flow), computed when read and never taken
// from the client.
//
// Only kinds that something consumes are accepted. root_domain feeds the
// Certificate Transparency monitor and the fqdn_under_asserted_root rule;
// the other RFC kinds (cidr, asn, org_name, ...) are accepted once their
// collectors exist, so no seed sits in the table doing nothing.
package easmseed

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is a seed kind.
type Kind string

const (
	// KindRootDomain: a domain the organization owns; discovery covers it
	// and everything below it.
	KindRootDomain Kind = "root_domain"
)

// AcceptedKinds are the kinds the API accepts today.
var AcceptedKinds = []Kind{KindRootDomain}

// Accepted reports whether k is accepted.
func (k Kind) Accepted() bool {
	for _, a := range AcceptedKinds {
		if k == a {
			return true
		}
	}
	return false
}

// MaxLabelLength bounds a seed's label.
const MaxLabelLength = 200

// MaxPerTenant bounds how many seeds one tenant keeps.
const MaxPerTenant = 500

// ErrInvalid is returned for a value that is not a valid seed of its kind.
var ErrInvalid = errors.New("invalid seed")

// Seed is one seed.
type Seed struct {
	ID               shared.ID
	TenantID         shared.ID
	Kind             Kind
	Value            string
	Label            string
	DiscoveryEnabled bool
	AttestedBy       *shared.ID
	AttestedAt       time.Time
	CreatedBy        *shared.ID
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Normalize validates value for kind and returns its canonical form.
func Normalize(kind Kind, value string) (string, error) {
	if !kind.Accepted() {
		return "", fmt.Errorf("%w: kind %q is not accepted", ErrInvalid, kind)
	}
	if kind == KindRootDomain {
		return normalizeDomain(value)
	}
	return "", fmt.Errorf("%w: kind %q is not accepted", ErrInvalid, kind)
}

// normalizeDomain lowercases, strips a trailing dot and a leading "*.",
// converts to ASCII (IDNA) and requires a name under an ICANN public suffix
// that is not itself a public suffix: discovery under "com" or
// "azurewebsites.net" would claim other organizations' names.
func normalizeDomain(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " /:@\\") {
		return "", fmt.Errorf("%w: not a domain name", ErrInvalid)
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("%w: not a domain name", ErrInvalid)
	}
	// icann is false under a private suffix: x.azurewebsites.net is a name at
	// a provider, never an organization's root.
	ps, icann := publicsuffix.PublicSuffix(ascii)
	if !icann || ps == ascii || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("%w: the domain must be under a public suffix and not be one", ErrInvalid)
	}
	return ascii, nil
}

// CleanLabel trims and bounds a label and refuses control characters.
func CleanLabel(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxLabelLength {
		return "", fmt.Errorf("%w: label must be at most %d characters", ErrInvalid, MaxLabelLength)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: label has control characters", ErrInvalid)
		}
	}
	return s, nil
}

// CoversName reports whether a root_domain seed value covers name (equal or
// a subdomain).
func CoversName(root, name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == root || strings.HasSuffix(name, "."+root)
}
