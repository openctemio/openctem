package scan

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// maxResolvedTargets bounds how many targets one scan run may dispatch. Larger
// sets must be split (zone routing with TargetsPerJob batching, RFC-023).
const maxResolvedTargets = 10000

// legacyListScanners are scanner names outside the stage catalog whose
// sensor executors read the full `targets` list (the Tenable bridge). The
// catalog's tools say it themselves (stage.AcceptsTargetList); every other
// scanner reads only the single `target` field, so a run of such a scanner
// gets one command per target, zoned or not (RFC-030 B4).
var legacyListScanners = map[string]bool{
	"tenable": true,
	"nessus":  true,
}

func scannerAcceptsTargetList(scanner string) bool {
	return stage.AcceptsTargetList(scanner) || legacyListScanners[strings.ToLower(strings.TrimSpace(scanner))]
}

// singleTargetWarningPrefix starts the warning for a single-target scanner in
// a run without zones; a zoned run creates one job per target instead.
const singleTargetWarningPrefix = "scanner "

// resolvedTargets is what a scan run actually dispatches.
type resolvedTargets struct {
	Targets       []string
	Excluded      int
	ExcludedNames []string // the targets scope exclusions removed, in order
	// Unconfirmed counts group members skipped because their attribution is
	// not confirmed (needs review, candidate, dependency, monitor only,
	// rejected).
	Unconfirmed int
	// Archived counts group members left out because the asset is archived.
	Archived int
	// Incompatible counts group members left out because the run's scanner
	// cannot scan their type (RFC-042 §6.3.8 O6); IncompatibleReason names
	// them.
	Incompatible       int
	IncompatibleReason string
	// TargetTypes is the stored pair of every dispatched group member
	// (target name -> "type" or "type/sub_type"), for the workflow step gate.
	TargetTypes map[string]string
	// OutOfScope counts targets left out because the actor may not scan them
	// (research/15 L-06, D9).
	OutOfScope int
	// TierExceeded counts targets left out because the scope entries
	// covering them allow a lower tier than the scanner probes at
	// (RFC-054 §4.2 step 6, tier_ceiling.go).
	TierExceeded int
	// InternalOutsideZones counts internal-address targets left out because
	// no scan zone of the tenant covers them (refuseInternalOutsideZones).
	InternalOutsideZones int
	Warnings             []string
}

// resolveScanTargets builds the target list server-side: the scan's direct
// targets plus the members of every one of its asset groups (sensors do not
// resolve asset groups themselves, so a group-only scan used to dispatch
// nothing), deduplicated, then puts it through the one target gate
// (ResolveDispatchTargets): scope exclusions, ownership, the act scope of
// whoever runs the scan, the private-range policy and the tier ceiling. A
// check that cannot run (a failed or unwired lookup) stops the dispatch
// (fail closed) instead of scanning everything. The per-run cap counts all
// groups together.
//
// A group member is one asset, identified by its id. It is dispatched by name,
// but exclusions are tested against every value that names it (its addresses
// and repository URLs too), so a host whose address is excluded is skipped.
// Archived members are not scanned. Zone routing is planned by the trigger
// itself (planZoneDispatch).
func (s *Service) resolveScanTargets(ctx context.Context, sc *scan.Scan) (*resolvedTargets, error) {
	seen := make(map[string]int) // lower-cased target -> index in names
	var names []string
	assets := make(map[string]DispatchAsset)
	var warnings []string
	archived := 0
	types := make(map[string]asset.TypeRef) // member name -> stored type
	// A single-scanner run hands every target to one tool: members whose
	// type it cannot scan are left out here. A workflow gates each step at
	// its own dispatch (FilterStepTargets).
	gate, err := s.newScannerTypeGate(ctx, sc.TenantID, sc.ScannerName)
	if err != nil {
		return nil, err
	}

	add := func(value string) bool {
		v := strings.TrimSpace(value)
		if v == "" {
			return false
		}
		if _, dup := seen[strings.ToLower(v)]; dup {
			return false
		}
		seen[strings.ToLower(v)] = len(names)
		names = append(names, v)
		return true
	}
	// alsoMatch adds an asset's other values to the target dispatched under
	// its name, whichever came first (a direct target with the same name
	// included), so an exclusion of any of them removes the target. A direct
	// target stays a typed target: its ownership and act scope are decided
	// by name.
	alsoMatch := func(name string, values []string) {
		i, ok := seen[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return
		}
		a := assets[names[i]]
		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" && !strings.EqualFold(v, strings.TrimSpace(name)) {
				a.AlsoMatch = append(a.AlsoMatch, v)
			}
		}
		if len(a.IDs) > 0 || len(a.AlsoMatch) > 0 {
			assets[names[i]] = a
		}
	}

	for _, t := range sc.Targets {
		add(t)
	}
	// Group members, by asset id, for the ownership and act-scope checks. A
	// member whose name is also a direct target was added as the direct
	// target first.
	if s.assetGroupRepo != nil {
		listed := make(map[shared.ID]bool)
		for _, groupID := range sc.GetAllAssetGroupIDs() {
			if groupID.IsZero() || listed[groupID] {
				continue
			}
			listed[groupID] = true
			members, archivedInGroup, err := s.listGroupScanMembers(ctx, sc.TenantID, groupID)
			if err != nil {
				return nil, fmt.Errorf("list asset group %s members: %w", groupID, err)
			}
			archived += archivedInGroup
			if len(members) == 0 {
				warnings = append(warnings, fmt.Sprintf("asset group %s has no assets that can be scanned; nothing from it is scanned", groupID))
			}
			for _, m := range members {
				if !gate.admits(m.Type) {
					continue
				}
				if add(m.Name) {
					name := names[len(names)-1]
					assets[name] = DispatchAsset{IDs: []string{m.ID.String()}}
					types[name] = m.Type
				}
				alsoMatch(m.Name, m.MatchValues)
			}
			// Bound the work before the checks: they only remove targets,
			// so far more candidates than the cap cannot fit.
			if len(names) > 2*maxResolvedTargets {
				return nil, fmt.Errorf("%w: scan resolves to more than %d targets, more than the %d allowed per run",
					shared.ErrValidation, len(names), maxResolvedTargets)
			}
		}
	}

	// A workflow (no scanner) is tier-checked per step, at its dispatch.
	tier := scopedom.TierPassive
	if sc.ScannerName != "" {
		tier = ProbeTier(sc.ScannerName)
	}
	gated, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID:               sc.TenantID,
		Targets:                names,
		Assets:                 assets,
		ActScope:               true,
		FallbackUser:           sc.CreatedBy,
		Tier:                   &tier,
		AllowNonNetworkTargets: true,
		SkipZoneRouting:        true,
		TakeoverOnly:           IsTakeoverOnlyProbe(sc.ScannerName, sc.ScannerConfig),
		ActScopeAssetsByID:     true,
		MaxTargets:             2 * maxResolvedTargets,
		Path:                   "scan_run",
	})
	if err != nil {
		return nil, fmt.Errorf("scan not dispatched: %w", err)
	}

	if archived > 0 {
		warnings = append(warnings, fmt.Sprintf("%d archived asset(s) in the group(s) were skipped", archived))
	}
	out := &resolvedTargets{
		Targets:       append(make([]string, 0, len(gated.Allowed)), gated.Allowed...),
		Excluded:      len(gated.Excluded),
		ExcludedNames: gated.Excluded,
		Archived:      archived,
		Warnings:      warnings,
	}
	if n := gate.total(); n > 0 {
		out.Incompatible = n
		out.IncompatibleReason = gate.describe()
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d asset(s) in the group(s) were skipped: %s", n, out.IncompatibleReason))
	}
	if err := countRefusals(out, gated.Refused); err != nil {
		return nil, err
	}
	for _, t := range out.Targets {
		if ref, typed := types[t]; typed && ref.Type != "" {
			if out.TargetTypes == nil {
				out.TargetTypes = make(map[string]string)
			}
			out.TargetTypes[t] = typeLabel(ref)
		}
	}
	if out.OutOfScope > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d target(s) were skipped: they are outside the data scope of whoever runs this scan, or not scope targets", out.OutOfScope))
	}
	if out.Unconfirmed > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d target(s) were skipped: %s", out.Unconfirmed, ReasonOwnershipNotConfirmed))
	}
	if out.InternalOutsideZones > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d internal address target(s) were skipped: %s", out.InternalOutsideZones, ReasonInternalOutsideZones))
	}
	if out.TierExceeded > 0 {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%d target(s) were skipped: %s runs %s probes and the scope entries covering them allow less (raise the entry's tier in Scoping > Targets)",
			out.TierExceeded, sc.ScannerName, tier))
	}
	if len(out.Targets) > maxResolvedTargets {
		return nil, fmt.Errorf("%w: scan resolves to %d targets, more than the %d allowed per run",
			shared.ErrValidation, len(out.Targets), maxResolvedTargets)
	}
	// A single-scanner run of a one-target scanner dispatches one command
	// per target (perTargetPlan, or the zone batches); refuse up front what
	// would exceed the per-run job cap. A workflow (no scanner name) plans
	// its targets per step and never had the one-target caveat: it used to
	// be warned that only the first target would be scanned.
	if sc.ScannerName != "" && !scannerAcceptsTargetList(sc.ScannerName) && len(out.Targets) > maxZoneJobsPerRun {
		return nil, tooManyJobsError(sc, len(out.Targets))
	}
	return out, nil
}

// countRefusals counts the gate's refusals of a run by check. The gate runs
// with the validator off and zone routing left to the trigger, so a refusal
// is ownership, act scope, the private-range rule or the tier ceiling; any
// other stops the run (a check this count does not know of).
func countRefusals(out *resolvedTargets, refused []RefusedTarget) error {
	for _, r := range refused {
		switch {
		case r.Reason == ReasonOwnershipNotConfirmed:
			out.Unconfirmed++
		case r.Reason == ReasonInternalOutsideZones && r.Code == scopedom.RefusalZoneNone:
			out.InternalOutsideZones++
		case r.Code == scopedom.RefusalTierExceeds:
			out.TierExceeded++
		case r.Code == scopedom.RefusalOutOfDataScope, r.Code == scopedom.RefusalNotAnAsset, r.Code == scopedom.RefusalNoEntry:
			out.OutOfScope++
		default:
			return fmt.Errorf("scan not dispatched: target refused with an unexpected code %q", r.Code)
		}
	}
	return nil
}

// applyTargetsToPayload writes the dispatch targets in the protocol-v1 shape
// every deployed sensor and SDK understands: `targets` always carries the full
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
// routed to shared platform sensors.
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
	host = asset.HostOf(host)
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
