package scan

// Resolve before active (docs/rfcs/RFC-088-scope-aware-target-allocation.md,
// decision A5; architecture: docs/architecture/scan-targets.md). The
// platform decides from its freshest evidence which names an active stage
// takes: a name whose last proof of resolving is older than the TTL is
// skipped (not_resolving) and its enrichment is requested, so the next run
// knows. A name the platform holds no evidence for is handed on: the
// sensor resolves it and reports it back when it does not.

import (
	"context"
	"fmt"
	"strings"
	"time"

	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	scanpkg "github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ReasonNotResolving is the skip reason of a name without recent
// resolution evidence.
const ReasonNotResolving = "not_resolving"

// StaleRefresher requests the enrichment of assets whose evidence went
// stale (*assetfreshness.Enricher).
type StaleRefresher interface {
	RequestStale(ctx context.Context, tenantID shared.ID, ids []shared.ID)
}

// SetResolveEvidence wires the evidence reader and the refresher. Without a
// reader every name is handed on (no evidence is not proof of anything).
func (s *Service) SetResolveEvidence(r freshdom.NameEvidenceReader, refresh StaleRefresher) {
	s.resolveEvidence, s.staleRefresher = r, refresh
}

// SetResolutionStore wires the resolution states (asset_resolution): an
// active stage leaves out a name in the not_resolving state, whatever older
// evidence says. Passive stages are not filtered, so the name comes back by
// itself once a resolution (or a tool reaching it) records it resolving.
func (s *Service) SetResolutionStore(st assetresolution.Store) { s.resolutionStore = st }

// DropStaleNames keeps the targets an active stage may take: every target
// that is not a host name, every name without evidence, and every name
// whose freshest evidence is within freshdom.ResolveTTL. It returns the
// names it left out. A failed read is returned (fail closed).
func (s *Service) DropStaleNames(ctx context.Context, tenantID shared.ID, targets []string) (kept, stale []string, err error) {
	return s.dropNamesWithoutEvidence(ctx, tenantID, targets, nil)
}

// dropNamesWithoutEvidence is DropStaleNames where the names in
// requireProof (lower case: the names a selector or an asset group added,
// with their asset) are also left out when the platform holds no evidence
// for them at all, and their enrichment is requested. A typed name without
// evidence is still handed on.
func (s *Service) dropNamesWithoutEvidence(ctx context.Context, tenantID shared.ID, targets []string, requireProof map[string]shared.ID) (kept, stale []string, err error) {
	if (s.resolveEvidence == nil && s.resolutionStore == nil) || len(targets) == 0 {
		return targets, nil, nil
	}
	names := make([]string, 0, len(targets))
	seen := map[string]bool{}
	for _, t := range targets {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
		if stage.ClassifyTarget(n) != stage.KindName || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	if len(names) == 0 {
		return targets, nil, nil
	}
	var ev []freshdom.NameEvidence
	if s.resolveEvidence != nil {
		var err error
		ev, err = s.resolveEvidence.FreshestByName(ctx, tenantID, names, freshdom.ResolveEvidenceClasses)
		if err != nil {
			return nil, nil, fmt.Errorf("resolution evidence check failed, nothing dispatched: %w", err)
		}
	}
	// Names the platform knows do not resolve (a resolve stage or a sensor
	// said so more than once in a row).
	var notResolving map[string]bool
	if s.resolutionStore != nil {
		var err error
		notResolving, err = s.resolutionStore.NotResolving(ctx, tenantID, names)
		if err != nil {
			return nil, nil, fmt.Errorf("resolution state check failed, nothing dispatched: %w", err)
		}
	}
	freshest := map[string]time.Time{}
	ids := map[string][]shared.ID{}
	for _, e := range ev {
		n := strings.ToLower(e.Name)
		if e.ObservedAt.After(freshest[n]) {
			freshest[n] = e.ObservedAt
		}
		ids[n] = append(ids[n], e.AssetID)
	}
	cutoff := time.Now().Add(-freshdom.ResolveTTL)
	staleSet := map[string]bool{}
	var refresh []shared.ID
	for n := range notResolving {
		staleSet[n] = true
	}
	for n, at := range freshest {
		if at.Before(cutoff) && !notResolving[n] {
			staleSet[n] = true
			refresh = append(refresh, ids[n]...)
		}
	}
	// No evidence at all: never seen resolving. Its enrichment is asked
	// for, and the resolve.dns coverage of the asset checks it too.
	for _, n := range names {
		if id, need := requireProof[n]; need && !notResolving[n] {
			if _, known := freshest[n]; !known {
				staleSet[n] = true
				refresh = append(refresh, id)
			}
		}
	}
	if len(staleSet) == 0 {
		return targets, nil, nil
	}
	kept = make([]string, 0, len(targets))
	for _, t := range targets {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
		if staleSet[n] {
			stale = append(stale, t)
			continue
		}
		kept = append(kept, t)
	}
	if s.staleRefresher != nil && len(refresh) > 0 {
		s.staleRefresher.RequestStale(ctx, tenantID, refresh)
	}
	return kept, stale, nil
}

// RunContextKeyNotResolving counts the names a run left out for lack of
// recent resolution evidence.
const RunContextKeyNotResolving = "not_resolving_target_count"

// CodeNoResolvingTargets: every target of an active single-scanner run is a
// name without recent resolution evidence.
const CodeNoResolvingTargets = "NO_RESOLVING_TARGETS"

// dropStaleRunNames applies DropStaleNames to a single-scanner run's
// targets, records how many it left out, and refuses a run left with none.
//
// The names a selector or an asset group added need proof that they
// resolve, unless the scan's target options include names that do not
// (TargetOptions.IncludeUnresolved): a wildcard over passive discovery
// holds many historical names with no DNS answer.
func (s *Service) dropStaleRunNames(ctx context.Context, sc *scanpkg.Scan, r *resolvedTargets, runContext map[string]any) error {
	var requireProof map[string]shared.ID
	if !sc.TargetOptions.IncludeUnresolved {
		requireProof = r.Inventory
	}
	kept, stale, err := s.dropNamesWithoutEvidence(ctx, sc.TenantID, r.Targets, requireProof)
	if err != nil {
		return err
	}
	r.NotResolving = stale
	if len(stale) == 0 {
		return nil
	}
	runContext[RunContextKeyNotResolving] = len(stale)
	r.Warnings = append(r.Warnings, fmt.Sprintf(
		"%d name(s) left out: no proof they resolved in DNS in the last %d days (for example %s); their DNS is checked again by coverage",
		len(stale), int(freshdom.ResolveTTL.Hours()/24), stale[0]))
	if len(kept) == 0 {
		return shared.NewDomainError(CodeNoResolvingTargets,
			fmt.Sprintf("No target of this scan has resolved in DNS in the last %d days; their DNS is checked again by coverage. Run it later, scan addresses, or include names that do not resolve in the scan's target options.", int(freshdom.ResolveTTL.Hours()/24)),
			shared.ErrValidation)
	}
	r.Targets = kept
	return nil
}
