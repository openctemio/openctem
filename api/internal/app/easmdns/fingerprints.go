package easmdns

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// can-i-take-over-xyz fingerprints (CC BY 4.0, see fingerprints/NOTICE.md).
//
//go:embed fingerprints/can-i-take-over-xyz.json
var fingerprintsJSON []byte

// Provider is a hosting service whose CNAME suffixes the fingerprint list
// names.
type Provider struct {
	Service string
	// Status is the list's verdict: "Vulnerable", "Edge case" or
	// "Not vulnerable".
	Status string
	// NXDomain is true when the list says a dangling CNAME to this provider is
	// claimable from DNS alone (the target answers NXDOMAIN until someone
	// registers it).
	NXDomain bool
}

// Takeoverable reports whether the list marks the provider vulnerable.
func (p Provider) Takeoverable() bool { return strings.EqualFold(p.Status, "Vulnerable") }

type fingerprintRow struct {
	Service  string   `json:"service"`
	CNAME    []string `json:"cname"`
	Status   string   `json:"status"`
	NXDomain bool     `json:"nxdomain"`
}

var (
	providersOnce sync.Once
	providers     map[string]Provider // suffix -> provider
	suffixes      []string            // longest first
	providersErr  error
)

func loadProviders() (map[string]Provider, []string, error) {
	providersOnce.Do(func() {
		var rows []fingerprintRow
		if err := json.Unmarshal(fingerprintsJSON, &rows); err != nil {
			providersErr = fmt.Errorf("parse takeover fingerprints: %w", err)
			return
		}
		providers = map[string]Provider{}
		for _, r := range rows {
			for _, c := range r.CNAME {
				s := strings.Trim(strings.ToLower(strings.TrimSpace(c)), ".")
				// Entries are DNS suffixes; the list also holds a few IPs and
				// URLs (an A-record target, a probe URL), which a CNAME can
				// never match.
				if s == "" || strings.ContainsAny(s, "/:") || !strings.Contains(s, ".") || isIPLiteral(s) {
					continue
				}
				// When two services claim one suffix, keep the more
				// actionable verdict.
				cur, ok := providers[s]
				if !ok || rank(r.Status, r.NXDomain) > rank(cur.Status, cur.NXDomain) {
					providers[s] = Provider{Service: r.Service, Status: r.Status, NXDomain: r.NXDomain}
				}
			}
		}
		for s := range providers {
			suffixes = append(suffixes, s)
		}
		sort.Slice(suffixes, func(i, j int) bool {
			if len(suffixes[i]) != len(suffixes[j]) {
				return len(suffixes[i]) > len(suffixes[j])
			}
			return suffixes[i] < suffixes[j]
		})
	})
	return providers, suffixes, providersErr
}

func rank(status string, nx bool) int {
	r := 0
	switch strings.ToLower(status) {
	case "vulnerable":
		r = 2
	case "edge case":
		r = 1
	}
	if nx {
		r += 3
	}
	return r
}

func isIPLiteral(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// providerFor returns the provider whose suffix the target falls under.
func providerFor(target string) (Provider, bool) {
	ps, sfx, err := loadProviders()
	if err != nil {
		return Provider{}, false
	}
	t := strings.Trim(strings.ToLower(target), ".")
	for _, s := range sfx {
		if t == s || strings.HasSuffix(t, "."+s) {
			return ps[s], true
		}
	}
	return Provider{}, false
}
