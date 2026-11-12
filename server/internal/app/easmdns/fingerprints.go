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

// The project's own provider list (fingerprints/NOTICE.md): hosting
// services the list above does not know, measured by this project. An entry
// here wins over the same suffix in the list above.
//
//go:embed fingerprints/openctem-providers.json
var ownProvidersJSON []byte

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
	// Hosted is true for a provider that serves every customer name from
	// shared front ends: a name it no longer serves still resolves (the
	// CNAME target exists), so the DNS answer alone shows nothing and the
	// provider's own answer for the name (its "not configured" page, a
	// refused connection, a stale certificate) is the evidence.
	Hosted bool
}

// Takeoverable reports whether the list marks the provider vulnerable.
func (p Provider) Takeoverable() bool { return strings.EqualFold(p.Status, "Vulnerable") }

type fingerprintRow struct {
	Service  string   `json:"service"`
	CNAME    []string `json:"cname"`
	Status   string   `json:"status"`
	NXDomain bool     `json:"nxdomain"`
	Hosted   bool     `json:"hosted"`
}

var (
	providersOnce sync.Once
	providers     map[string]Provider // suffix -> provider
	suffixes      []string            // longest first
	providersErr  error
)

func loadProviders() (map[string]Provider, []string, error) {
	providersOnce.Do(func() {
		var rows, own []fingerprintRow
		if err := json.Unmarshal(fingerprintsJSON, &rows); err != nil {
			providersErr = fmt.Errorf("parse takeover fingerprints: %w", err)
			return
		}
		if err := json.Unmarshal(ownProvidersJSON, &own); err != nil {
			providersErr = fmt.Errorf("parse own provider list: %w", err)
			return
		}
		providers = map[string]Provider{}
		addRows(rows, false)
		addRows(own, true)
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

// addRows adds a list's suffixes. Entries are DNS suffixes; the list also
// holds a few IPs and URLs (an A-record target, a probe URL), which a CNAME
// can never match. When two services of one list claim a suffix, the more
// actionable verdict is kept; an entry of the own list (override) replaces
// whatever the third-party list said.
func addRows(rows []fingerprintRow, override bool) {
	for _, r := range rows {
		for _, c := range r.CNAME {
			s := strings.Trim(strings.ToLower(strings.TrimSpace(c)), ".")
			if s == "" || strings.ContainsAny(s, "/:") || !strings.Contains(s, ".") || isIPLiteral(s) {
				continue
			}
			cur, ok := providers[s]
			if override || !ok || rank(r.Status, r.NXDomain) > rank(cur.Status, cur.NXDomain) {
				providers[s] = Provider{Service: r.Service, Status: r.Status, NXDomain: r.NXDomain, Hosted: r.Hosted}
			}
		}
	}
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
