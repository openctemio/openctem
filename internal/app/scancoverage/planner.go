// Package scancoverage holds the pure, IO-free planning logic for license-aware
// rolling scan coverage (RFC-007): how big a batch may be under a scanner's
// license, and which assets to scan next.
//
// It is deliberately decoupled from any scanner/transport so it can be unit
// tested in isolation and reused by both execution modes (direct + agent) and by
// the coverage scheduler. See docs/rfcs/RFC-007-license-aware-scan-coverage.md.
package scancoverage

import (
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

// LicenseMode describes how a scan engine is licensed.
type LicenseMode string

const (
	// LicenseUnlimited — Nessus Professional: unlimited IPs; batching is for
	// scan duration/load only, there is no cap to respect.
	LicenseUnlimited LicenseMode = "unlimited"

	// LicenseActiveIPCap — Tenable.sc: a fixed number of active IPs may carry
	// live results at once; batches must fit the remaining headroom.
	LicenseActiveIPCap LicenseMode = "active_ip_cap"
)

// LicensePolicy is the per-engine licensing rule the scheduler reads to size a
// batch.
type LicensePolicy struct {
	Mode LicenseMode

	// Cap is the maximum active IPs (LicenseActiveIPCap only).
	Cap int

	// SafetyMargin keeps the scheduler a few IPs below Cap so a slow reclaim
	// can't tip the account over the limit (LicenseActiveIPCap only).
	SafetyMargin int
}

// Headroom returns how many IPs may be added to a new batch right now.
//
//   - Unlimited: returns defaultBatch (the caller's performance/time batch size).
//   - ActiveIPCap: Cap − SafetyMargin − activeIPs, clamped at 0.
//
// activeIPs is the count the scheduler currently believes are live on the engine
// (it tracks this itself rather than trusting instant reclaim — RFC-007 §3.2).
func (p LicensePolicy) Headroom(activeIPs, defaultBatch int) int {
	if p.Mode == LicenseUnlimited {
		if defaultBatch < 0 {
			return 0
		}
		return defaultBatch
	}
	h := p.Cap - p.SafetyMargin - activeIPs
	if h < 0 {
		return 0
	}
	return h
}

// Candidate is an asset eligible for the next coverage batch.
type Candidate struct {
	AssetID string
	// Target is the IP / CIDR / hostname that will be scanned. Used to count
	// how many license IPs it consumes.
	Target string
	// Criticality: critical|high|medium|low|none (case-insensitive).
	Criticality string
	// LastScannedAt is nil for never-scanned assets (which sort first).
	LastScannedAt *time.Time
}

// SelectBatch picks the next batch from candidates, ordered by
// (criticality DESC, LastScannedAt ASC, nulls first) and greedily filled until
// adding the next candidate would exceed maxIPs. It returns the selected
// candidates and the total IP count they consume.
//
// If maxIPs > 0 the first (highest-priority) candidate is always taken even when
// it alone exceeds maxIPs — otherwise a single oversized CIDR at the front would
// stall the rotation forever. Callers should surface that over-budget case.
// maxIPs <= 0 selects nothing.
func SelectBatch(candidates []Candidate, maxIPs int) (selected []Candidate, ips int) {
	if maxIPs <= 0 || len(candidates) == 0 {
		return nil, 0
	}

	ordered := make([]Candidate, len(candidates))
	copy(ordered, candidates)
	sort.SliceStable(ordered, func(i, j int) bool {
		wi, wj := criticalityWeight(ordered[i].Criticality), criticalityWeight(ordered[j].Criticality)
		if wi != wj {
			return wi > wj // higher criticality first
		}
		return lessLastScanned(ordered[i].LastScannedAt, ordered[j].LastScannedAt)
	})

	selected = make([]Candidate, 0, len(ordered))
	for _, c := range ordered {
		n := CountIPs(c.Target)
		if len(selected) == 0 {
			// Always take the top candidate (avoid starvation), even if oversized.
			selected = append(selected, c)
			ips += n
			continue
		}
		if ips+n > maxIPs {
			continue // skip; a smaller later candidate may still fit
		}
		selected = append(selected, c)
		ips += n
	}
	return selected, ips
}

// criticalityWeight maps a criticality label to a sortable weight.
func criticalityWeight(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default: // none / unknown
		return 0
	}
}

// lessLastScanned orders by oldest-scanned first; never-scanned (nil) sorts
// before any timestamp so fresh assets get covered first.
func lessLastScanned(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return false
	case a == nil:
		return true
	case b == nil:
		return false
	default:
		return a.Before(*b)
	}
}

// CountIPs returns how many license IPs a target consumes:
//   - a CIDR consumes its full block size (2^hostbits), capped at MaxInt32;
//   - a single IP or hostname consumes 1.
//
// The full block (incl. network/broadcast) is counted because that is how
// active-IP licenses account for a scanned range.
func CountIPs(target string) int {
	target = strings.TrimSpace(target)
	if target == "" {
		return 0
	}
	if _, ipnet, err := net.ParseCIDR(target); err == nil {
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones
		if hostBits <= 0 {
			return 1
		}
		if hostBits >= 31 {
			return math.MaxInt32 // /1../0 or any IPv6 block: effectively "too big"
		}
		return 1 << uint(hostBits)
	}
	// Single IP or hostname.
	return 1
}
