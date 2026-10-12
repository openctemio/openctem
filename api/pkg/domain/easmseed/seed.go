// Package easmseed holds the network seeds of external attack surface
// discovery: autonomous system numbers and organization names the tenant
// asserts are its own. Design: docs/rfcs/RFC-082-network-seeds.md.
//
// A network seed never authorizes a probe: only scope entries do (RFC-054).
// An ASN seed is expanded into the prefixes it announces (public routing
// data) and those are offered as CIDR scope entries for a person to add
// through the normal scope flow; an organization seed is expanded into
// candidate ASNs. Both make the review queue offer the range around an
// address in the tenant's networks.
package easmseed

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind is the kind of a network seed.
type Kind string

const (
	// KindASN is an autonomous system number, stored as "AS<n>".
	KindASN Kind = "asn"
	// KindOrgName is an organization name as registries know it.
	KindOrgName Kind = "org_name"
)

// Caps.
const (
	MaxSeedsPerTenant    = 50
	MaxPrefixesPerSeed   = 1000
	MaxSuggestionsPerOrg = 50
	MaxLabelBytes        = 200
	MinOrgNameLen        = 3
	MaxOrgNameBytes      = 200
	// RefreshInterval is how often seeds are expanded again.
	RefreshInterval = 7 * 24 * time.Hour
	// ExpandCooldown is the shortest time between two expansions of a seed.
	ExpandCooldown = 15 * time.Minute
)

// ErrInvalid marks a seed value that cannot be accepted.
var ErrInvalid = errors.New("invalid network seed")

// NormalizeASN accepts "AS13335", "as13335" or "13335" and returns "AS13335".
// Reserved, private and documentation numbers are refused: they never
// identify an organization's public network.
func NormalizeASN(v string) (string, error) {
	s := strings.TrimSpace(strings.ToUpper(v))
	s = strings.TrimPrefix(s, "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return "", fmt.Errorf("%w: an AS number is AS followed by 1 to 4294967294", ErrInvalid)
	}
	switch {
	case n == 23456, n == 65535, n == 4294967295,
		n >= 64496 && n <= 64511, // documentation
		n >= 64512 && n <= 65534, // private
		n >= 65536 && n <= 65551, // documentation
		n >= 4200000000:          // private
		return "", fmt.Errorf("%w: AS%d is reserved or private", ErrInvalid, n)
	}
	return "AS" + strconv.FormatUint(n, 10), nil
}

// NormalizeOrgName trims and checks an organization name.
func NormalizeOrgName(v string) (string, error) {
	s := strings.Join(strings.Fields(v), " ")
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) < MinOrgNameLen || len(s) > MaxOrgNameBytes {
		return "", fmt.Errorf("%w: an organization name has 3 to 200 characters", ErrInvalid)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: control characters", ErrInvalid)
		}
	}
	return s, nil
}

// Normalize validates a value of the kind.
func Normalize(kind Kind, value string) (string, error) {
	switch kind {
	case KindASN:
		return NormalizeASN(value)
	case KindOrgName:
		return NormalizeOrgName(value)
	}
	return "", fmt.Errorf("%w: kind must be asn or org_name", ErrInvalid)
}

// ASNSuggestion is an ASN a registry search found for an organization seed.
type ASNSuggestion struct {
	ASN         string `json:"asn"`
	Description string `json:"description"`
}

// Seed is one stored network seed.
type Seed struct {
	ID             string          `json:"id"`
	Kind           Kind            `json:"kind"`
	Value          string          `json:"value"`
	Label          string          `json:"label,omitempty"`
	Holder         string          `json:"holder,omitempty"`
	Prefixes       []string        `json:"prefixes"`
	Suggestions    []ASNSuggestion `json:"suggestions"`
	LastExpandedAt *time.Time      `json:"last_expanded_at,omitempty"`
	ExpandError    string          `json:"expand_error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Ref identifies a seed of a tenant.
type Ref struct {
	TenantID shared.ID
	ID       string
}

// Networks are the tenant's seeded networks, for attribution.
type Networks struct {
	ASNs     map[string]bool
	OrgNames []string
	Prefixes []string
}
