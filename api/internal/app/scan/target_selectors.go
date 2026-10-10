package scan

// Dynamic target selectors (RFC-068, docs/rfcs/RFC-068-dynamic-scan-targets.md;
// architecture: docs/architecture/scan-targets.md).
//
// A scan's targets may hold two selectors besides literal hosts:
//
//   - a wildcard domain "*.example.com": the apex and every name the
//     inventory holds at or under it;
//   - a CIDR in inventory mode (target_options.cidr_mode = inventory): the
//     address assets the inventory holds inside the range. In sweep mode (the
//     default) a CIDR is a literal target, handed to the scanner whole.
//
// They are expanded at the start of every run, never when the scan is
// saved, so a scheduled scan picks up what was discovered since its last
// run. A tool that enumerates subdomains (discover.subdomains) gets the
// apex only: enumerating from known children would repeat the work.
//
// Security: a selector authorizes nothing. Each expanded name is dispatched
// as the inventory asset it is (by id), so the one dispatch gate
// (ResolveDispatchTargets) decides it exactly as it decides an asset-group
// member: exclusions, ownership, the act scope of whoever runs the scan, the
// private-range rule and the tier ceiling; the claim-time re-check, scan
// windows and the signer ledger follow downstream. The inventory read is
// pinned to the scan's tenant. A missing reader refuses the run (fail
// closed) instead of quietly scanning the apex alone.

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// SelectorAssets lists the inventory assets a selector covers
// (*postgres.ScanSelectorRepository).
type SelectorAssets interface {
	ListSelectorAssets(ctx context.Context, q scan.SelectorQuery) ([]*assetgroup.ScanMember, error)
}

// SetSelectorAssets wires the inventory reader behind dynamic selectors.
func (s *Service) SetSelectorAssets(r SelectorAssets) { s.selectorAssets = r }

// MaxSelectorTargets bounds what one selector adds to a run: the stage
// catalogue's per-parent cap, past which a domain is a suspected wildcard
// DNS zone. The run cap (maxResolvedTargets) still applies to the total.
const MaxSelectorTargets = stage.DefaultPerParent

// maxExpansionSample bounds the names a run records per selector.
const maxExpansionSample = 10

// Selector kinds.
const (
	SelectorKindWildcard = "wildcard"
	SelectorKindCIDR     = "cidr"
)

// Run context keys written by the expansion. Both are platform bookkeeping:
// StepRunContext keeps them away from sensors.
const (
	// RunContextKeyTargetExpansion holds []TargetExpansion.
	RunContextKeyTargetExpansion = "target_expansion"
	// RunContextKeySelectorRoots holds the apexes of the run's wildcard
	// selectors, so a subdomain discovery step gets the apex alone.
	RunContextKeySelectorRoots = "selector_roots"
)

// CodeSelectorUnavailable refuses a run whose selectors cannot be read.
const CodeSelectorUnavailable = "TARGET_SELECTOR_UNAVAILABLE"

// TargetExpansion is what one selector added to one run.
type TargetExpansion struct {
	Selector string `json:"selector"`
	Kind     string `json:"kind"`
	// Matched is the number of inventory assets the selector covered
	// (at most the cap).
	Matched int `json:"matched"`
	// Capped: the inventory held more than MaxSelectorTargets; the ones
	// seen most recently were kept.
	Capped bool `json:"capped,omitempty"`
	// Sample names a few of them, most recently seen first.
	Sample []string `json:"sample,omitempty"`
}

// selectorExpansion is the scan's targets with its selectors expanded.
type selectorExpansion struct {
	// Literal are the targets dispatched by name, in the scan's order: plain
	// targets, swept CIDRs and the apex of each wildcard.
	Literal []string
	// Members are the inventory assets the selectors added.
	Members []groupScanMember
	Report  []TargetExpansion
	// Roots are the wildcard apexes.
	Roots []string
}

// rootsOnlyTool reports whether tool enumerates subdomains from a root
// domain (discover.subdomains): it takes a wildcard as its apex alone.
func rootsOnlyTool(tool string) bool {
	return slices.ContainsFunc(stage.ForTool(tool), func(st stage.Stage) bool {
		return st.Key == stage.DiscoverSubdomains
	})
}

// isCIDRTarget reports whether t is an address range (a.b.c.d/n, v6 too).
func isCIDRTarget(t string) bool {
	_, err := netip.ParsePrefix(strings.TrimSpace(t))
	return err == nil
}

// validateSelectorTargets refuses a wildcard whose root is not a domain the
// platform lets anyone cover (a public suffix, a shared provider apex, a
// denied name), at create and edit. The scope gate would refuse every name
// under it at dispatch anyway; this says so when the scan is saved.
func validateSelectorTargets(targets []string) error {
	g := scopedom.DefaultGuardrails()
	for _, t := range targets {
		if !IsWildcardTarget(t) {
			continue
		}
		p := strings.ToLower(strings.TrimSpace(t))
		if err := scopedom.ValidatePattern(scopedom.TargetTypeDomain, p); err != nil || strings.HasPrefix(p, "*.*") {
			return shared.NewDomainError(CodeWildcardTarget,
				fmt.Sprintf("Target %q is not a valid wildcard domain: write *.example.com.", t), shared.ErrValidation)
		}
		if err := g.CheckPattern(scopedom.TargetTypeDomain, p); err != nil {
			return shared.NewDomainError(CodeWildcardTarget,
				fmt.Sprintf("Target %q cannot be a scan target: %v.", t, err), shared.ErrValidation)
		}
	}
	return nil
}

// expandSelectors expands the scan's selectors from the inventory as it is
// now. Literal targets come back unchanged, in order.
func (s *Service) expandSelectors(ctx context.Context, sc *scan.Scan) (*selectorExpansion, error) {
	out := &selectorExpansion{}
	inventoryCIDR := sc.TargetOptions.EffectiveCIDRMode() == scan.CIDRModeInventory
	var seenSince *time.Time
	if d := sc.TargetOptions.SeenWithinDays; d > 0 {
		t := time.Now().UTC().AddDate(0, 0, -d)
		seenSince = &t
	}
	seenRoot := map[string]bool{}
	for _, raw := range sc.Targets {
		t := strings.TrimSpace(raw)
		var q scan.SelectorQuery
		var kind string
		switch {
		case IsWildcardTarget(t):
			root := WildcardRoot(t)
			if seenRoot[root] {
				continue
			}
			seenRoot[root] = true
			out.Literal = append(out.Literal, root)
			out.Roots = append(out.Roots, root)
			q, kind = scan.SelectorQuery{UnderDomain: root}, SelectorKindWildcard
		case inventoryCIDR && isCIDRTarget(t):
			q, kind = scan.SelectorQuery{InCIDR: t}, SelectorKindCIDR
		default:
			out.Literal = append(out.Literal, t)
			continue
		}
		if s.selectorAssets == nil {
			return nil, shared.NewDomainError(CodeSelectorUnavailable,
				fmt.Sprintf("Target %q is resolved from the inventory, which this server cannot read; the run was not started.", t),
				shared.ErrValidation)
		}
		q.TenantID, q.SeenSince, q.IncludeStale = sc.TenantID, seenSince, sc.TargetOptions.IncludeStale
		q.Limit = MaxSelectorTargets + 1
		members, err := s.selectorAssets.ListSelectorAssets(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("expand target %q: %w", t, err)
		}
		rep := TargetExpansion{Selector: t, Kind: kind}
		if len(members) > MaxSelectorTargets {
			members, rep.Capped = members[:MaxSelectorTargets], true
		}
		rep.Matched = len(members)
		for _, m := range members {
			if m == nil {
				continue
			}
			out.Members = append(out.Members, groupScanMember{
				ID:          m.ID,
				Name:        m.Name,
				MatchValues: scope.AssetExclusionValues(m.Type, m.Name, m.Properties),
				Type:        asset.TypeRef{Type: asset.AssetType(m.Type), SubType: m.SubType},
			})
			if len(rep.Sample) < maxExpansionSample {
				rep.Sample = append(rep.Sample, m.Name)
			}
		}
		outcome := "expanded"
		switch {
		case rep.Capped:
			outcome = "capped"
		case rep.Matched == 0:
			outcome = "empty"
		}
		metrics.ScanTargetSelectorExpansions.WithLabelValues(kind, outcome).Inc()
		out.Report = append(out.Report, rep)
	}
	return out, nil
}

// expansionWarnings names the selectors that hit the cap.
func expansionWarnings(report []TargetExpansion) []string {
	var w []string
	for _, r := range report {
		if r.Capped {
			w = append(w, fmt.Sprintf(
				"%s covers more than %d inventory assets; the %d seen most recently were taken (narrow it, or set a freshness window)",
				r.Selector, MaxSelectorTargets, MaxSelectorTargets))
		}
	}
	return w
}

// DiscoverySeeds is what a workflow step of the given tool takes from the
// run's seed targets: a subdomain discovery step enumerates from the apex of
// each wildcard selector, not from the names the inventory already knows
// under it; every other step takes the seeds as they are. seeds nil reads
// the run's targets.
func DiscoverySeeds(tool string, seeds *StepTargets, runContext map[string]any) *StepTargets {
	roots := contextStrings(runContext, RunContextKeySelectorRoots)
	if len(roots) == 0 || !rootsOnlyTool(tool) {
		return seeds
	}
	out := &StepTargets{}
	targets := contextTargets(runContext)
	if seeds != nil {
		*out = *seeds
		targets = seeds.Targets
	}
	out.Targets = dropUnderRoots(targets, roots)
	return out
}

// dropUnderRoots leaves out of a subdomain discovery step the names strictly
// under one of the run's wildcard apexes: the tool enumerates from the apex.
func dropUnderRoots(targets, roots []string) []string {
	if len(roots) == 0 {
		return targets
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		h := strings.ToLower(strings.TrimSuffix(asset.HostOf(strings.TrimSpace(t)), "."))
		under := false
		for _, r := range roots {
			if strings.HasSuffix(h, "."+r) {
				under = true
				break
			}
		}
		if !under {
			out = append(out, t)
		}
	}
	return out
}
