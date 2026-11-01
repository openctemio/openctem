// Package addrowner assesses how likely an internet address that the
// organization's in-scope names resolve to is the organization's own, from
// named pieces of evidence (signals), and places it in a confidence band.
//
// The band is a rule, not a learned number (RFC-054 §20):
//
//	High     at least one anchor, and another anchor or a corroborator, and no blocker
//	Medium   an anchor alone, two or more corroborators, or High held back by a blocker
//	Low      anything else with network data or a corroborator
//	Unknown  no network data and no positive signal
//
// An anchor is something the organization itself established about a network
// (a network seed: its announced prefix or its AS number). Nothing an outside
// party controls is an anchor: a reverse name, a network holder's free-text
// name and the number of names pointing at an address can be steered by
// whoever holds the address or the DNS, so they only corroborate. Blockers
// stop the usual steering paths (a brand-new address, names of other
// organizations on the same address).
//
// The assessment only explains and orders suggestions: it authorizes nothing.
// An address becomes scannable only through an exact scope entry.
package addrowner

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Band is the confidence that the address is the organization's.
type Band string

// Bands, strongest first.
const (
	High    Band = "high"
	Medium  Band = "medium"
	Low     Band = "low"
	Unknown Band = "unknown"
)

// Kind is how a signal counts.
type Kind string

// Signal kinds.
const (
	Anchor       Kind = "anchor"
	Corroborator Kind = "corroborator"
	Blocker      Kind = "blocker"
)

// Signal ids (stable: the web console keys its text by them).
const (
	SignalOwnPrefix     = "own_prefix"
	SignalOwnASN        = "own_asn"
	SignalHolderMatches = "holder_matches"
	SignalReverseName   = "reverse_name"
	SignalManyNames     = "many_names"
	SignalStable        = "stable"
	SignalNewAddress    = "new_address"
	SignalForeignNames  = "foreign_names"
)

// Thresholds.
const (
	// ManyNames: this many in-scope names pointing at the address corroborate.
	ManyNames = 3
	// StableAfter: in-scope names have pointed at it at least this long.
	StableAfter = 14 * 24 * time.Hour
	// NewWithin: an address first seen this recently is held back (cloud
	// addresses change hands; a day of waiting catches most churn).
	NewWithin = 24 * time.Hour
)

// Input is what is known about one address. Every field comes from the
// organization's own data (tenant-scoped reads); nothing is looked up here.
type Input struct {
	Address string
	// ASN and Holder: the address's network, when enrichment or a scan
	// reported it ("" when unknown).
	ASN    string
	Holder string
	// HolderMatches: the holder name matches the organization's name or a
	// holder name of its network seeds (decided by the caller).
	HolderMatches bool
	// SeedASNs and SeedPrefixes: the organization's network seeds.
	SeedASNs     map[string]bool
	SeedPrefixes []string
	// ReverseName: the address's reverse DNS name ("" when unknown).
	ReverseName string
	// InScopeNames: the organization's in-scope names resolving to it.
	InScopeNames []string
	// OtherNames: names resolving to it that no scope entry covers.
	OtherNames []string
	// FirstSeen: when the address was first seen (zero when unknown).
	FirstSeen time.Time
	Now       time.Time
}

// Signal is one piece of evidence. Params fill the plain-language text.
type Signal struct {
	ID     string            `json:"id"`
	Kind   Kind              `json:"kind"`
	Params map[string]string `json:"params,omitempty"`
}

// Assessment is the result for one address.
type Assessment struct {
	Band Band `json:"band"`
	// Score orders addresses inside and across bands (0-100); it is never
	// shown as a verdict.
	Score   int      `json:"score"`
	Signals []Signal `json:"signals"`
}

// Assess places one address in a band.
func Assess(in Input) Assessment {
	var sig []Signal
	add := func(id string, k Kind, params map[string]string) {
		sig = append(sig, Signal{ID: id, Kind: k, Params: params})
	}
	asn := normASN(in.ASN)

	// Anchors: what the organization established about its networks.
	if p := containingPrefix(in.Address, in.SeedPrefixes); p != "" {
		params := map[string]string{"prefix": p}
		if asn != "" {
			params["asn"] = asn
		}
		add(SignalOwnPrefix, Anchor, params)
	} else if asn != "" && seedHas(in.SeedASNs, asn) {
		add(SignalOwnASN, Anchor, map[string]string{"asn": asn})
	}

	// Corroborators.
	if in.HolderMatches && strings.TrimSpace(in.Holder) != "" {
		add(SignalHolderMatches, Corroborator, map[string]string{"holder": clip(in.Holder, 80)})
	}
	roots := registrables(in.InScopeNames)
	if rn := normName(in.ReverseName); rn != "" && roots[registrable(rn)] {
		params := map[string]string{"name": clip(rn, 253)}
		for _, n := range in.InScopeNames {
			if normName(n) == rn {
				params["confirmed"] = "true" // the reverse name resolves back to it
				break
			}
		}
		add(SignalReverseName, Corroborator, params)
	}
	if n := len(in.InScopeNames); n >= ManyNames && len(roots) <= 2 {
		add(SignalManyNames, Corroborator, map[string]string{"count": strconv.Itoa(n)})
	}
	if !in.FirstSeen.IsZero() && !in.Now.IsZero() {
		age := in.Now.Sub(in.FirstSeen)
		switch {
		case age >= StableAfter:
			add(SignalStable, Corroborator, map[string]string{"days": strconv.Itoa(int(age.Hours() / 24))})
		case age < NewWithin && age >= 0:
			add(SignalNewAddress, Blocker, map[string]string{"hours": strconv.Itoa(int(age.Hours()))})
		}
	}

	// Blockers: names of other organizations point at the same address.
	foreign := map[string]bool{}
	for _, n := range in.OtherNames {
		if r := registrable(normName(n)); r != "" && !roots[r] {
			foreign[r] = true
		}
	}
	if len(foreign) > 0 {
		add(SignalForeignNames, Blocker, map[string]string{"count": strconv.Itoa(len(foreign))})
	}

	return decide(sig, asn != "" || strings.TrimSpace(in.Holder) != "")
}

// decide turns signals into a band and a score.
func decide(sig []Signal, networkKnown bool) Assessment {
	var anchors, corr, blockers int
	for _, s := range sig {
		switch s.Kind {
		case Anchor:
			anchors++
		case Corroborator:
			corr++
		case Blocker:
			blockers++
		}
	}
	var band Band
	switch {
	case anchors >= 1 && (anchors >= 2 || corr >= 1) && blockers == 0:
		band = High
	case anchors >= 1 || corr >= 2:
		band = Medium
	case networkKnown || corr >= 1:
		band = Low
	default:
		band = Unknown
	}
	score := 20 + 35*min(anchors, 2) + 12*corr - 25*blockers
	lo, hi := bandRange(band)
	score = max(lo, min(hi, score))
	if sig == nil {
		sig = []Signal{}
	}
	// Anchors first, then corroborators, then blockers: the first two are
	// what the console shows as the reason.
	sort.SliceStable(sig, func(i, j int) bool { return kindRank(sig[i].Kind) < kindRank(sig[j].Kind) })
	return Assessment{Band: band, Score: score, Signals: sig}
}

func bandRange(b Band) (int, int) {
	switch b {
	case High:
		return 80, 100
	case Medium:
		return 50, 79
	case Low:
		return 20, 49
	default:
		return 0, 19
	}
}

// Rank orders bands, strongest first (High = 0).
func Rank(b Band) int {
	switch b {
	case High:
		return 0
	case Medium:
		return 1
	case Low:
		return 2
	default:
		return 3
	}
}

func kindRank(k Kind) int {
	switch k {
	case Anchor:
		return 0
	case Corroborator:
		return 1
	default:
		return 2
	}
}

// containingPrefix is the most specific prefix of prefixes holding addr.
func containingPrefix(addr string, prefixes []string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	a = a.Unmap()
	best := netip.Prefix{}
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !p.Contains(a) {
			continue
		}
		if !best.IsValid() || p.Bits() > best.Bits() {
			best = p.Masked()
		}
	}
	if !best.IsValid() {
		return ""
	}
	return best.String()
}

// seedHas: asn (normalized) is one of the seed AS numbers, whatever their
// spelling ("AS64500", "as64500", "64500").
func seedHas(seeds map[string]bool, asn string) bool {
	if seeds[asn] {
		return true
	}
	for k, ok := range seeds {
		if ok && normASN(k) == asn {
			return true
		}
	}
	return false
}

// normASN returns "AS<number>" or "".
func normASN(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "AS")
	if s == "" {
		return ""
	}
	if _, err := strconv.ParseUint(s, 10, 32); err != nil {
		return ""
	}
	return "AS" + s
}

func normName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func registrable(name string) string {
	if name == "" {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	r, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return r
}

func registrables(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		if r := registrable(normName(n)); r != "" {
			out[r] = true
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}
