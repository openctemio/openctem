package certmonitor

import (
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Where a monitored root came from. A root can come from several places; the
// strongest origin wins (verified > asset > scope) because it decides how far
// the platform may trust what CT says lives under it.
const (
	OriginVerified = "verified_domain"
	OriginAsset    = "domain_asset"
	OriginSeed     = "easm_seed" // a root_domain seed (RFC-036 §6.3): asserted, like an asset
	OriginScope    = "scope_target"
)

func originRank(o string) int {
	switch o {
	case OriginVerified:
		return 3
	case OriginAsset, OriginSeed:
		return 2
	case OriginScope:
		return 1
	default:
		return 0
	}
}

// rootDomain is one name the sweep may query, with where it came from.
type rootDomain struct {
	name    string
	origin  string
	assetID *shared.ID // the domain asset with this exact name, when there is one
}

// DomainState is the per-tenant, per-domain rotation record the sweep keeps
// between runs (table ct_monitor_state).
type DomainState struct {
	Domain              string
	LastCheckedAt       *time.Time
	LastSuccessAt       *time.Time
	LastSource          string
	LastError           string
	ConsecutiveFailures int
	NextAttemptAt       *time.Time
	SubdomainsSeen      int
}

// mergeRoots normalises and de-duplicates the candidate names from every
// origin, then drops any name already covered by a parent in the set: the
// crt.sh query for "%.example.com" returns every certificate for
// "api.example.com" too, so querying the child as well only doubles the load
// on the log aggregator. Names that cannot have public certificates (no ICANN
// public suffix: .local, .internal, .corp, .test …) are dropped, since a CT
// query for them can only fail.
func mergeRoots(in []rootDomain) []rootDomain {
	byName := make(map[string]rootDomain, len(in))
	for _, r := range in {
		r.name = normalizeDomain(r.name)
		if !isPublicDomain(r.name) {
			continue
		}
		cur, ok := byName[r.name]
		if !ok {
			byName[r.name] = r
			continue
		}
		if originRank(r.origin) > originRank(cur.origin) {
			cur.origin = r.origin
		}
		if cur.assetID == nil && r.assetID != nil {
			cur.assetID = r.assetID
		}
		byName[r.name] = cur
	}

	out := make([]rootDomain, 0, len(byName))
	for name, r := range byName {
		covered := false
		for p := parentOf(name); p != ""; p = parentOf(p) {
			parent, ok := byName[p]
			if !ok {
				continue
			}
			// A verified child under an unverified parent stays its own root,
			// so the names under it keep the verified origin.
			covered = r.origin != OriginVerified || parent.origin == OriginVerified
			break
		}
		if !covered {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// validHostname reports whether s is a syntactically valid DNS hostname in
// the normalized form: lowercase LDH labels (underscore allowed, as in
// _dmarc or SRV-style names), 1–63 characters each, at most 253 in total, no
// leading or trailing hyphen.
func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// parentOf returns the name without its first label, or "" at a public
// suffix boundary (we never query "com" or "co.uk").
func parentOf(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return ""
	}
	p := name[i+1:]
	if !isPublicDomain(p) {
		return ""
	}
	return p
}

// isPublicDomain reports whether name sits under an ICANN public suffix and is
// not itself a bare suffix ("com", "co.uk").
func isPublicDomain(name string) bool {
	if name == "" || !strings.Contains(name, ".") {
		return false
	}
	suffix, icann := publicsuffix.PublicSuffix(name)
	if !icann || suffix == name {
		return false
	}
	// Reserved for documentation and testing (RFC 2606 / RFC 6761). example.*
	// stays allowed: it has real public CT entries and is the safe test domain.
	switch suffix {
	case "test", "invalid", "localhost", "local", "internal":
		return false
	}
	return true
}

// selectDue picks, from the merged roots, which domains this run queries:
//
//   - a domain in back-off (NextAttemptAt in the future) waits;
//   - a domain whose last success is younger than recheckAfter is not due
//     (an API restart must not re-query everything);
//   - the rest are ordered never-succeeded first, then oldest success, then
//     oldest attempt, then name, and the first max are taken.
//
// That order is the rotation cursor: with 120 domains and max 50, every
// domain is queried within three runs, and a domain that keeps failing never
// takes more than its one slot per run.
func selectDue(roots []rootDomain, states map[string]DomainState, now time.Time, recheckAfter time.Duration, maxPerRun int) (due []rootDomain, deferred int) {
	type cand struct {
		r rootDomain
		s DomainState
	}
	cands := make([]cand, 0, len(roots))
	for _, r := range roots {
		s := states[r.name]
		if s.NextAttemptAt != nil && s.NextAttemptAt.After(now) {
			continue
		}
		if s.LastSuccessAt != nil && recheckAfter > 0 && now.Sub(*s.LastSuccessAt) < recheckAfter {
			continue
		}
		cands = append(cands, cand{r: r, s: s})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i].s, cands[j].s
		if c := cmpTimePtr(a.LastSuccessAt, b.LastSuccessAt); c != 0 {
			return c < 0
		}
		if c := cmpTimePtr(a.LastCheckedAt, b.LastCheckedAt); c != 0 {
			return c < 0
		}
		return cands[i].r.name < cands[j].r.name
	})
	if maxPerRun > 0 && len(cands) > maxPerRun {
		deferred = len(cands) - maxPerRun
		cands = cands[:maxPerRun]
	}
	due = make([]rootDomain, len(cands))
	for i, c := range cands {
		due[i] = c.r
	}
	return due, deferred
}

// cmpTimePtr orders nil (never) before any time, then ascending.
func cmpTimePtr(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case a.Before(*b):
		return -1
	case b.Before(*a):
		return 1
	default:
		return 0
	}
}

// failureBackoff is how long a domain waits after its n-th consecutive failed
// query (both CT sources failed): 12 h, 24 h, 48 h … capped at 7 days. The
// first value is below the daily sweep interval, so one bad night never costs
// a day.
func failureBackoff(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	d := 12 * time.Hour
	for i := 1; i < n && d < 7*24*time.Hour; i++ {
		d *= 2
	}
	if d > 7*24*time.Hour {
		d = 7 * 24 * time.Hour
	}
	return d
}
