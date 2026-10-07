package scan

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
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
	Warnings     []string
}

// resolveScanTargets builds the target list server-side: the scan's direct
// targets plus the members of every one of its asset groups (sensors do not
// resolve asset groups themselves, so a group-only scan used to dispatch
// nothing), deduplicated, minus every target matching an active scope
// exclusion. Exclusions are enforced here, on the server, for every scan, and
// a failed exclusion lookup stops the dispatch (fail closed) instead of
// scanning everything. The per-run cap counts all groups together.
//
// A group member is one asset, identified by its id. It is dispatched by name,
// but exclusions are tested against every value that names it (its addresses
// and repository URLs too), so a host whose address is excluded is skipped.
// Archived members are not scanned.
func (s *Service) resolveScanTargets(ctx context.Context, sc *scan.Scan) (*resolvedTargets, error) {
	seen := make(map[string]int) // lower-cased target -> index in candidates
	var candidates []scope.ExclusionCandidate
	names := make(map[shared.ID]string)
	var warnings []string
	archived := 0
	types := make(map[shared.ID]asset.TypeRef)
	// A single-scanner run hands every target to one tool: members whose
	// type it cannot scan are left out here. A workflow gates each step at
	// its own dispatch (FilterStepTargets).
	gate, err := s.newScannerTypeGate(ctx, sc.TenantID, sc.ScannerName)
	if err != nil {
		return nil, err
	}

	add := func(id shared.ID, value string) {
		v := strings.TrimSpace(value)
		if v == "" {
			return
		}
		if _, dup := seen[strings.ToLower(v)]; dup {
			return
		}
		seen[strings.ToLower(v)] = len(candidates)
		candidates = append(candidates, scope.ExclusionCandidate{ID: id, Values: []string{v}})
		names[id] = v
	}
	// alsoMatch adds an asset's other values to the candidate dispatched
	// under its name, whichever came first (a direct target with the same
	// name included), so an exclusion of any of them removes the target.
	alsoMatch := func(name string, values []string) {
		i, ok := seen[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return
		}
		for _, v := range values {
			if v = strings.TrimSpace(v); v != "" && !strings.EqualFold(v, strings.TrimSpace(name)) {
				candidates[i].Values = append(candidates[i].Values, v)
			}
		}
	}

	for _, t := range sc.Targets {
		add(shared.NewID(), t)
	}
	// Group members, by asset id, for the attribution gate. A member whose
	// name is also a direct target was added as the direct target first.
	memberIDs := map[shared.ID]bool{}
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
				before := len(candidates)
				add(m.ID, m.Name)
				if len(candidates) > before {
					memberIDs[m.ID] = true
					types[m.ID] = m.Type
				}
				alsoMatch(m.Name, m.MatchValues)
			}
			// Bound the work before the exclusion lookup: exclusions only
			// remove targets, so far more candidates than the cap cannot fit.
			if len(candidates) > 2*maxResolvedTargets {
				return nil, fmt.Errorf("%w: scan resolves to more than %d targets, more than the %d allowed per run",
					shared.ErrValidation, len(candidates), maxResolvedTargets)
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

	blocked, err := s.blockedCandidates(ctx, sc.TenantID, candidates, names, memberIDs, excluded, IsTakeoverOnlyProbe(sc.ScannerName, sc.ScannerConfig))
	if err != nil {
		return nil, err
	}

	outOfScope, err := s.runActScopeSkips(ctx, sc, candidates, names, memberIDs, excluded, blocked)
	if err != nil {
		return nil, err
	}

	if archived > 0 {
		warnings = append(warnings, fmt.Sprintf("%d archived asset(s) in the group(s) were skipped", archived))
	}
	out := &resolvedTargets{Targets: make([]string, 0, len(candidates)), Archived: archived, Warnings: warnings}
	if n := gate.total(); n > 0 {
		out.Incompatible = n
		out.IncompatibleReason = gate.describe()
		out.Warnings = append(out.Warnings, fmt.Sprintf("%d asset(s) in the group(s) were skipped: %s", n, out.IncompatibleReason))
	}
	for _, c := range candidates {
		if excluded[c.ID] {
			out.Excluded++
			out.ExcludedNames = append(out.ExcludedNames, names[c.ID])
			continue
		}
		if state, no := blocked[c.ID.String()]; no {
			out.Unconfirmed++
			s.logRefusedTarget(ctx, sc.TenantID, "scan_run", names[c.ID], state)
			continue
		}
		if outOfScope[c.ID] {
			out.OutOfScope++
			continue
		}
		out.Targets = append(out.Targets, names[c.ID])
		if ref, typed := types[c.ID]; typed && ref.Type != "" {
			if out.TargetTypes == nil {
				out.TargetTypes = make(map[string]string)
			}
			out.TargetTypes[names[c.ID]] = typeLabel(ref)
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
	if err := s.dropTierExceeded(ctx, sc.TenantID, sc.ScannerName, out); err != nil {
		return nil, err
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
