// Package edgeaddr tells whose an internet address or host name is: a CDN or
// WAF edge, a SaaS hosting platform, a cloud provider's shared front end, or
// an address that may be dedicated to one organization (research/259
// addendum "edge addresses").
//
// Edge, SaaS-hosting and cloud-shared addresses are never the
// organization's: they need no ownership decision, their open ports are the
// provider's, and they are never offered as scope entries. A dedicated
// address may still carry a provider label (a cloud static address): it is
// decided by a person like any other.
//
// The classifier reads one versioned dataset (published edge ranges,
// provider network names, provider host suffixes). The built-in dataset is
// the floor; a refreshed, signed dataset replaces it through New.
package edgeaddr

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// Class is what an address or host is.
type Class string

// Address classes.
const (
	Edge        Class = "edge"         // CDN or WAF edge
	SaaSHosting Class = "saas_hosting" // site builders, static and code hosting pages
	CloudShared Class = "cloud_shared" // cloud load balancers and managed front ends that rotate
	Dedicated   Class = "dedicated"    // everything else, cloud static addresses included
)

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	switch c {
	case Edge, SaaSHosting, CloudShared, Dedicated:
		return true
	}
	return false
}

// Basis is what the class was read from.
type Basis string

// Bases of a classification.
const (
	BasisRange   Basis = "range"   // inside a published range of the provider
	BasisCDN     Basis = "cdn"     // the address's own record names a CDN
	BasisNetwork Basis = "network" // the network's holder is the provider
	BasisHost    Basis = "host"    // the host name is under the provider's suffix
	BasisNone    Basis = ""
)

// Result is a classification. Provider is empty for an address no dataset
// entry knows.
type Result struct {
	Class    Class
	Provider string
	Basis    Basis
}

// Shared reports whether the address is not the organization's (edge,
// SaaS hosting or cloud shared).
func (r Result) Shared() bool { return r.Class != Dedicated && r.Class != "" }

// ProviderSpace reports whether the address sits in a provider's space,
// shared or not: never grouped into a range rule.
func (r Result) ProviderSpace() bool { return r.Provider != "" }

// Dataset is the classifier's data.
type Dataset struct {
	Version string       `json:"version"`
	Ranges  []RangeEntry `json:"ranges"`
	Orgs    []OrgEntry   `json:"orgs"`
	Apexes  []ApexEntry  `json:"apexes"`
}

// RangeEntry is a provider's published ranges.
type RangeEntry struct {
	Provider string   `json:"provider"`
	Class    Class    `json:"class"`
	Prefixes []string `json:"prefixes"`
}

// OrgEntry matches a network holder's name: Match is a lowercase word
// prefix ("amazon" matches "Amazon.com, Inc." and "AMAZON-02").
type OrgEntry struct {
	Match    string `json:"match"`
	Provider string `json:"provider"`
	Class    Class  `json:"class"`
}

// ApexEntry matches a host name at or under Suffix.
type ApexEntry struct {
	Suffix   string `json:"suffix"`
	Provider string `json:"provider"`
	Class    Class  `json:"class"`
}

type prefixEntry struct {
	p        netip.Prefix
	provider string
	class    Class
}

type orgEntry struct {
	re       *regexp.Regexp
	provider string
	class    Class
}

// Classifier classifies addresses and host names. Safe for concurrent use.
type Classifier struct {
	version string
	ranges  []prefixEntry
	orgs    []orgEntry
	apexes  []ApexEntry
}

// New builds a classifier from a dataset; an entry with an unknown class or
// an unparsable prefix refuses the whole dataset.
func New(d Dataset) (*Classifier, error) {
	c := &Classifier{version: d.Version}
	for _, r := range d.Ranges {
		if !r.Class.Valid() || r.Provider == "" {
			return nil, fmt.Errorf("edgeaddr: range entry %q: bad class or provider", r.Provider)
		}
		for _, s := range r.Prefixes {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("edgeaddr: range %q: %w", s, err)
			}
			c.ranges = append(c.ranges, prefixEntry{p: p.Masked(), provider: r.Provider, class: r.Class})
		}
	}
	for _, o := range d.Orgs {
		m := strings.ToLower(strings.TrimSpace(o.Match))
		if m == "" || !o.Class.Valid() || o.Provider == "" {
			return nil, fmt.Errorf("edgeaddr: org entry %q: bad match, class or provider", o.Match)
		}
		c.orgs = append(c.orgs, orgEntry{re: regexp.MustCompile(`(^|[^a-z0-9])` + regexp.QuoteMeta(m)), provider: o.Provider, class: o.Class})
	}
	for _, a := range d.Apexes {
		a.Suffix = strings.ToLower(strings.Trim(strings.TrimSpace(a.Suffix), "."))
		if a.Suffix == "" || !a.Class.Valid() || a.Provider == "" {
			return nil, fmt.Errorf("edgeaddr: apex entry %q: bad suffix, class or provider", a.Suffix)
		}
		c.apexes = append(c.apexes, a)
	}
	return c, nil
}

//go:embed dataset.json
var builtinDataset []byte

var (
	defaultOnce sync.Once
	defaultC    *Classifier
)

// Default is the classifier on the built-in dataset.
func Default() *Classifier {
	defaultOnce.Do(func() {
		var d Dataset
		if err := json.Unmarshal(builtinDataset, &d); err != nil {
			panic("edgeaddr: built-in dataset: " + err.Error())
		}
		c, err := New(d)
		if err != nil {
			panic(err.Error())
		}
		defaultC = c
	})
	return defaultC
}

// Version is the dataset's version.
func (c *Classifier) Version() string { return c.version }

// Address classifies an address from what we hold about it: cdn is the
// CDN its own record names, org the holder of its network (both may be
// empty). A published range wins; then the record's CDN (an edge); then the
// network holder. An address nothing knows is Dedicated with no provider:
// unknown is never read as safe by callers, they keep their own checks.
func (c *Classifier) Address(addr, cdn, org string) Result {
	if a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(addr), "[]")); err == nil {
		a = a.Unmap()
		for _, r := range c.ranges {
			if r.p.Contains(a) {
				return Result{Class: r.class, Provider: r.provider, Basis: BasisRange}
			}
		}
	}
	if cdn = strings.TrimSpace(cdn); cdn != "" {
		provider := cdn
		if r := c.org(cdn); r.Provider != "" {
			provider = r.Provider
		}
		return Result{Class: Edge, Provider: provider, Basis: BasisCDN}
	}
	if r := c.org(org); r.Provider != "" {
		return r
	}
	return Result{Class: Dedicated}
}

func (c *Classifier) org(name string) Result {
	l := strings.ToLower(strings.TrimSpace(name))
	if l == "" {
		return Result{}
	}
	for _, o := range c.orgs {
		if o.re.MatchString(l) {
			return Result{Class: o.class, Provider: o.provider, Basis: BasisNetwork}
		}
	}
	return Result{}
}

// Host classifies a host name (a name, or a CNAME target) by the provider
// suffix it is at or under; Dedicated with no provider when none matches.
func (c *Classifier) Host(name string) Result {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, a := range c.apexes {
		if h == a.Suffix || strings.HasSuffix(h, "."+a.Suffix) {
			return Result{Class: a.Class, Provider: a.Provider, Basis: BasisHost}
		}
	}
	return Result{Class: Dedicated}
}
