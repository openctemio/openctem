package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/api/internal/app/scope"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
)

// maxResolvedTargets bounds how many targets one scan run may dispatch. Larger
// sets must be split (zone routing with TargetsPerJob batching, RFC-023).
const maxResolvedTargets = 10000

// listTargetScanners are the scanners whose executors on deployed agents read
// the full `targets` list from the payload (nuclei via the vulnscan executor,
// the Tenable bridge). Every other scanner reads only the single `target`
// field, so a multi-target scan sent to it can only ever cover the first
// target until per-target commands land (RFC-023 Phase 1).
var listTargetScanners = map[string]bool{
	"nuclei":  true,
	"tenable": true,
	"nessus":  true,
}

func scannerAcceptsTargetList(scanner string) bool {
	return listTargetScanners[strings.ToLower(strings.TrimSpace(scanner))]
}

// resolvedTargets is what a scan run actually dispatches.
type resolvedTargets struct {
	Targets  []string
	Excluded int
	Warnings []string
}

// resolveScanTargets builds the target list server-side: the scan's direct
// targets plus the members of its asset group (agents do not resolve asset
// groups themselves, so a group-only scan used to dispatch nothing), minus
// every target matching an active scope exclusion. Exclusions are enforced
// here, on the server, for every scan, and a failed exclusion lookup stops the
// dispatch (fail closed) instead of scanning everything.
func (s *Service) resolveScanTargets(ctx context.Context, sc *scan.Scan) (*resolvedTargets, error) {
	seen := make(map[string]bool)
	var candidates []scope.ExclusionCandidate
	names := make(map[shared.ID]string)

	add := func(id shared.ID, value string) {
		v := strings.TrimSpace(value)
		if v == "" || seen[strings.ToLower(v)] {
			return
		}
		seen[strings.ToLower(v)] = true
		candidates = append(candidates, scope.ExclusionCandidate{ID: id, Values: []string{v}})
		names[id] = v
	}

	for _, t := range sc.Targets {
		add(shared.NewID(), t)
	}
	if !sc.AssetGroupID.IsZero() && s.assetGroupRepo != nil {
		members, err := s.listGroupExclusionCandidates(ctx, sc.AssetGroupID)
		if err != nil {
			return nil, fmt.Errorf("list asset group members: %w", err)
		}
		for _, m := range members {
			for _, v := range m.Values {
				add(m.ID, v)
			}
		}
	}

	excluded := map[shared.ID]bool{}
	if s.scopeExclusions != nil && len(candidates) > 0 {
		var err error
		excluded, err = s.scopeExclusions.ExcludedTargets(ctx, sc.TenantID.String(), candidates)
		if err != nil {
			return nil, fmt.Errorf("scope exclusion check failed, scan not dispatched: %w", err)
		}
	}

	out := &resolvedTargets{Targets: make([]string, 0, len(candidates))}
	for _, c := range candidates {
		if excluded[c.ID] {
			out.Excluded++
			continue
		}
		out.Targets = append(out.Targets, names[c.ID])
	}
	if len(out.Targets) > maxResolvedTargets {
		return nil, fmt.Errorf("%w: scan resolves to %d targets, more than the %d allowed per run",
			shared.ErrValidation, len(out.Targets), maxResolvedTargets)
	}
	if len(out.Targets) > 1 && !scannerAcceptsTargetList(sc.ScannerName) {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"scanner %q takes one target per job: only %q is scanned in this run, %d other target(s) are not",
			sc.ScannerName, out.Targets[0], len(out.Targets)-1))
	}
	return out, nil
}

// applyTargetsToPayload writes the dispatch targets in the protocol-v1 shape
// every deployed agent and SDK understands: `targets` always carries the full
// list; `target` is set only when it is the whole job (one target, or a
// scanner that reads nothing else). Sending `target` alongside a list would
// make nuclei scan just that one, because it prefers `target`.
func applyTargetsToPayload(payload map[string]any, scanner string, targets []string) {
	if len(targets) == 0 {
		return
	}
	payload["targets"] = targets
	if len(targets) == 1 || !scannerAcceptsTargetList(scanner) {
		payload["target"] = targets[0]
	}
}

// hasInternalTarget reports whether any target is (or names) a private,
// loopback, link-local or unspecified address. Such targets must never be
// routed to shared platform agents.
func hasInternalTarget(targets []string) bool {
	for _, t := range targets {
		if isInternalTarget(t) {
			return true
		}
	}
	return false
}

func isInternalTarget(target string) bool {
	host := strings.TrimSpace(target)
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			host = u.Hostname()
		}
	}
	if p, err := netip.ParsePrefix(host); err == nil {
		return isInternalAddr(p.Addr())
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		return isInternalAddr(a)
	}
	lower := strings.ToLower(host)
	return lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal")
}

func isInternalAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsUnspecified() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a) // carrier-grade NAT
}
