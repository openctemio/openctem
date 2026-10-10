package ingest

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/ctis"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// DedupReviewEnqueuer enqueues a duplicate-asset review for admin approval when
// the correlator finds multiple existing assets that should be consolidated.
// Implementations must be idempotent (one pending review per keep asset).
type DedupReviewEnqueuer interface {
	UpsertReview(ctx context.Context,
		tenantID, normalizedName, assetType, keepID, keepName string, keepFindingCount int,
		mergeIDs, mergeNames []string, mergeFindingCount int) error
}

// AssetProcessor handles batch asset processing.
type AssetProcessor struct {
	repo          asset.Repository
	repoExtRepo   asset.RepositoryExtensionRepository
	relRepo       asset.RelationshipRepository
	stateHistory  asset.StateHistoryRepository // optional: records appeared/recovered on discovery (nil = disabled)
	correlator    *AssetCorrelator             // RFC-001: IP-based correlation (nil = disabled)
	dedupEnqueuer DedupReviewEnqueuer          // RFC-001: enqueue multi-match dupes for review (nil = disabled)
	exclusions    ExclusionSource              // scope exclusions: new excluded assets are not added (nil = not checked)
	// Asset identity model: identifier matching (nil = name and IP only).
	identityStore    IdentityStore
	identityReviewer IdentityReviewer
	propsValidator   *validator.PropertiesValidator
	logger           *logger.Logger
	// trackSets: set attributes (IP addresses, technologies, open ports)
	// are reconciled per source (attribute_sets.go), so a merge leaves the
	// sets of an existing asset to that reconciliation.
	trackSets bool

	// assetsDiscoveredCallback receives the assets THIS ingest actually
	// inserted (nil = disabled). It drives the `asset_discovered` workflow
	// trigger and the new-internet-facing-asset notification.
	assetsDiscoveredCallback AssetsDiscoveredCallback

	// assetsExposedCallback receives EXISTING assets a re-scan turned
	// internet-facing (nil = disabled). Drives the newly-exposed notification.
	assetsExposedCallback AssetsDiscoveredCallback
}

// AssetsDiscoveredCallback is invoked once per ingest batch with the assets the
// batch newly created. It never sees an asset that already existed (a re-scan
// merge) or one whose insert lost a concurrent-create race, so each asset is
// announced exactly once. Implementations must not block: ingest calls it
// inline.
type AssetsDiscoveredCallback func(ctx context.Context, tenantID shared.ID, assets []*asset.Asset)

// SetAssetsDiscoveredCallback wires the consumer of newly-created assets.
func (p *AssetProcessor) SetAssetsDiscoveredCallback(cb AssetsDiscoveredCallback) {
	p.assetsDiscoveredCallback = cb
}

// SetAssetsExposedCallback wires the consumer of existing assets that a re-scan
// turned internet-facing (they were not before). Same batching and
// non-blocking contract as the discovered callback.
func (p *AssetProcessor) SetAssetsExposedCallback(cb AssetsDiscoveredCallback) {
	p.assetsExposedCallback = cb
}

// NewAssetProcessor creates a new asset processor.
func NewAssetProcessor(repo asset.Repository, log *logger.Logger) *AssetProcessor {
	return &AssetProcessor{
		repo:           repo,
		propsValidator: validator.NewPropertiesValidator(),
		logger:         log.With("processor", "assets"),
	}
}

// SetRepositoryExtensionRepository sets the repository extension repository.
func (p *AssetProcessor) SetRepositoryExtensionRepository(repo asset.RepositoryExtensionRepository) {
	p.repoExtRepo = repo
}

// SetRelationshipRepository sets the asset relationship repository.
func (p *AssetProcessor) SetRelationshipRepository(repo asset.RelationshipRepository) {
	p.relRepo = repo
}

// SetStateHistoryRepository wires the asset state-history store. When set, the
// discovery scan workflow records an `appeared` entry for each newly-created asset
// and a `recovered` entry when a scan re-observes a stale/inactive asset
// (reactivating it). Optional: nil → no history (preserves prior behaviour).
func (p *AssetProcessor) SetStateHistoryRepository(repo asset.StateHistoryRepository) {
	p.stateHistory = repo
}

// SetCorrelator sets the asset correlator for IP-based deduplication.
// When nil (default), IP correlation is disabled.
func (p *AssetProcessor) SetCorrelator(c *AssetCorrelator) {
	p.correlator = c
}

// SetDedupEnqueuer wires the duplicate-review enqueuer. When nil (default),
// multi-match duplicates detected during correlation are not enqueued.
func (p *AssetProcessor) SetDedupEnqueuer(e DedupReviewEnqueuer) {
	p.dedupEnqueuer = e
}

// enqueueDedupReview records a pending review when the correlator found several
// existing assets sharing identity. Best-effort: a failure is logged and never
// aborts ingestion.
func (p *AssetProcessor) enqueueDedupReview(ctx context.Context, tenantID shared.ID, normalizedName, assetType string, keep *asset.Asset, mergeTargets []*asset.Asset) {
	if p.dedupEnqueuer == nil || keep == nil || len(mergeTargets) == 0 {
		return
	}
	mergeIDs := make([]string, 0, len(mergeTargets))
	mergeNames := make([]string, 0, len(mergeTargets))
	mergeFindings := 0
	for _, m := range mergeTargets {
		mergeIDs = append(mergeIDs, m.ID().String())
		mergeNames = append(mergeNames, m.Name())
		mergeFindings += m.FindingCount()
	}
	if err := p.dedupEnqueuer.UpsertReview(ctx, tenantID.String(), normalizedName, assetType,
		keep.ID().String(), keep.Name(), keep.FindingCount(),
		mergeIDs, mergeNames, mergeFindings); err != nil {
		p.logger.Warn("failed to enqueue dedup review",
			"keep_id", keep.ID().String(), "merge_count", len(mergeTargets), "error", err)
	}
}

// recordDiscoveryHistory appends `appeared` rows for newly-created assets and
// `recovered` rows for assets a scan re-observed after they went stale. Without
// it, scanner-discovered assets produce no state history, leaving the activity
// timeline + shadow-IT/recovery analytics blind to the bulk of discovery.
// Best-effort: a failure is logged and never aborts ingestion.
func (p *AssetProcessor) recordDiscoveryHistory(ctx context.Context, tenantID shared.ID, appeared []*asset.Asset, recoveredIDs []shared.ID) {
	if p.stateHistory == nil || (len(appeared) == 0 && len(recoveredIDs) == 0) {
		return
	}
	changes := make([]*asset.AssetStateChange, 0, len(appeared)+len(recoveredIDs))
	for _, a := range appeared {
		changes = append(changes, asset.RecordAssetAppeared(tenantID, a.ID(), asset.ChangeSourceScan, "discovered by scan"))
	}
	for _, id := range recoveredIDs {
		changes = append(changes, asset.RecordAssetRecovered(tenantID, id, asset.ChangeSourceScan, "re-observed by scan"))
	}
	if err := p.stateHistory.CreateBatch(ctx, changes); err != nil {
		p.logger.Warn("failed to record asset discovery state-history",
			"tenant_id", tenantID.String(), "count", len(changes), "error", err)
	}
}

// insertedAssets keeps the locally-created assets whose id is the one the
// database persisted for their name. persistedIDs maps name -> authoritative id;
// when it is nil (older repository implementations) every candidate is kept.
func insertedAssets(candidates []*asset.Asset, persistedIDs map[string]shared.ID) []*asset.Asset {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]*asset.Asset, 0, len(candidates))
	for _, a := range candidates {
		if persistedIDs != nil {
			pid, ok := persistedIDs[a.Name()]
			if !ok {
				continue // refused by the database: never stored
			}
			if !pid.Equals(a.ID()) {
				continue // lost a concurrent-create race: the row already existed
			}
		}
		out = append(out, a)
	}
	return out
}

// dropRefusedAssets removes from assetMap and existingMap every new asset the
// upsert did not store (absent from persistedIDs) and adds an error for each.
// A nil persistedIDs means the repository did not say, and nothing is dropped.
func dropRefusedAssets(newAssets []*asset.Asset, persistedIDs map[string]shared.ID,
	assetMap map[string]shared.ID, existingMap map[string]*asset.Asset, output *Output) {
	if persistedIDs == nil {
		return
	}
	for _, a := range newAssets {
		if _, ok := persistedIDs[a.Name()]; ok {
			continue
		}
		for ctisID, id := range assetMap {
			if id.Equals(a.ID()) {
				delete(assetMap, ctisID)
				addError(output, fmt.Sprintf("asset %s (%s): refused by the database", ctisID, shortName(a.Name())))
			}
		}
		if existingMap[a.Name()] == a {
			delete(existingMap, a.Name())
		}
	}
}

// unmapAssets removes every assetMap entry that points at one of assets.
func unmapAssets(assets []*asset.Asset, assetMap map[string]shared.ID) {
	ids := make(map[shared.ID]bool, len(assets))
	for _, a := range assets {
		ids[a.ID()] = true
	}
	for ctisID, id := range assetMap {
		if ids[id] {
			delete(assetMap, ctisID)
		}
	}
}

// shortName keeps an asset name readable in an error message: a refused name
// can be arbitrarily long.
func shortName(name string) string {
	const maxRunes = 80
	if utf8.RuneCountInString(name) <= maxRunes {
		return name
	}
	r := []rune(name)
	return string(r[:maxRunes]) + "…"
}

// mergeTrackingExposure merges a re-observed CTIS asset into the existing one
// and returns the state-history rows for any exposure transition the merge
// caused (scanner signal or inferred exposure). Without these rows the
// exposure-change and newly-exposed views had nothing to show: the only writer
// of internet_exposure_changed was a finding/asset inconsistency trigger.
// An asset that was not internet-facing before the merge and is after it is
// appended to becameExposed (when non-nil).
func (p *AssetProcessor) mergeTrackingExposure(
	tenantID shared.ID,
	existing *asset.Asset,
	ctisAsset *ctis.Asset,
	tool *ctis.Tool,
	observedAt time.Time,
	recovered *[]shared.ID,
	becameExposed *[]*asset.Asset,
) []*asset.AssetStateChange {
	oldExposure := existing.Exposure()
	oldInternet := existing.IsInternetAccessible()
	wasFacing := oldInternet || oldExposure == asset.ExposurePublic

	p.mergeCTISIntoAsset(existing, ctisAsset, tool, observedAt, recovered)

	if becameExposed != nil && !wasFacing &&
		(existing.IsInternetAccessible() || existing.Exposure() == asset.ExposurePublic) {
		*becameExposed = append(*becameExposed, existing)
	}
	return exposureTransitions(tenantID, existing, oldExposure, oldInternet)
}

// exposureTransitions builds the scan-sourced state-history rows describing
// how an asset's exposure moved from (oldExposure, oldInternet) to its current
// values.
func exposureTransitions(tenantID shared.ID, a *asset.Asset, oldExposure asset.Exposure, oldInternet bool) []*asset.AssetStateChange {
	var changes []*asset.AssetStateChange
	if a.Exposure() != oldExposure {
		changes = append(changes, asset.RecordFieldChange(tenantID, a.ID(),
			asset.StateChangeExposureChanged, "exposure",
			string(oldExposure), string(a.Exposure()), asset.ChangeSourceScan, nil))
	}
	if a.IsInternetAccessible() != oldInternet {
		changes = append(changes, asset.RecordFieldChange(tenantID, a.ID(),
			asset.StateChangeInternetExposureChanged, "is_internet_accessible",
			strconv.FormatBool(oldInternet), strconv.FormatBool(a.IsInternetAccessible()), asset.ChangeSourceScan, nil))
	}
	return changes
}

// recordExposureHistory persists exposure transitions caused by a re-scan.
// Best-effort: a failure is logged and never aborts ingestion.
func (p *AssetProcessor) recordExposureHistory(ctx context.Context, tenantID shared.ID, changes []*asset.AssetStateChange) {
	if p.stateHistory == nil || len(changes) == 0 {
		return
	}
	if err := p.stateHistory.CreateBatch(ctx, changes); err != nil {
		p.logger.Warn("failed to record asset exposure state-history",
			"tenant_id", tenantID.String(), "count", len(changes), "error", err)
	}
}

// defaultCorrelationConfig returns the system default correlation config.
func (p *AssetProcessor) defaultCorrelationConfig() CorrelationConfig {
	if p.correlator != nil {
		return p.correlator.config
	}
	return CorrelationConfig{StaleAssetDays: DefaultIPTrustWindowDays, MaxIPsPerAsset: DefaultMaxIPsPerAsset}
}

// ProcessBatch processes all assets using batch operations.
// Returns a map of asset ID (from CTIS) -> domain asset ID for finding association.
//
// If no explicit assets are provided in the report but findings exist,
// it will attempt to auto-create an asset using a priority chain:
//  1. BranchInfo.RepositoryURL in report metadata (most reliable for CI/CD)
//  2. Unique AssetValue from findings (if all findings reference same asset)
//  3. Scope.Name from report metadata
//  4. Inferred repository from file path patterns (e.g., github.com/org/repo)
//  5. Tool+ScanID fallback (ensures findings are never orphaned)
func (p *AssetProcessor) ProcessBatch(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	output *Output,
	tenantCfg *CorrelationConfig, // nil = use system defaults
) (map[string]shared.ID, error) {
	return p.processBatch(ctx, tenantID, report, output, tenantCfg, false, fullScope())
}

// processBatch is ProcessBatch; noAutoAsset (protocol v2,
// Options.RequireAssetForFindings) skips the metadata-derived asset a report
// with findings but no assets would otherwise get. scope says which existing
// assets the report may change (RFC-040 §5.3); an existing asset outside it
// is only marked seen, and only while it is active. scope.allowed is filled
// with the persisted ids of the assets the report may change.
//
//nolint:gocognit,cyclop // the existing batch scan workflow, unchanged apart from the gate
func (p *AssetProcessor) processBatch(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	output *Output,
	tenantCfg *CorrelationConfig,
	noAutoAsset bool,
	scope *alterScope,
) (map[string]shared.ID, error) {
	assetMap := make(map[string]shared.ID)
	// CTIS ids of the report assets this report created or may change.
	alterRefs := map[string]bool{}
	defer func() {
		for ref := range alterRefs {
			if id, ok := assetMap[ref]; ok {
				scope.allow(id)
			}
		}
	}()

	// Open ports listed on an address become open_port assets that go
	// through the rules below like any reported asset (research/22 P0-6).
	if n := expandOpenPorts(report); n > 0 {
		p.logger.Debug("expanded open ports into port assets", "count", n)
	}
	// One key per concept, and a key on the wrong asset (a port on a
	// domain) moved to the asset it belongs on (RFC-042 §6.3.9).
	if added, dropped, unknown := routeMisplacedProperties(report); added > 0 || dropped > 0 || len(unknown) > 0 {
		p.logger.Warn("report asset properties outside the asset type schema",
			"routed_services", added, "dropped_keys", dropped,
			"unknown_keys", logger.SanitizeValue(strings.Join(unknown, ",")))
	}

	p.logger.Debug("starting asset processing",
		"explicit_assets_count", len(report.Assets),
		"findings_count", len(report.Findings),
	)

	// If no explicit assets but there are findings, try to auto-create from metadata
	if len(report.Assets) == 0 {
		if len(report.Findings) > 0 && !noAutoAsset {
			// Try to create asset from report metadata (BranchInfo)
			autoAsset := p.createAssetFromMetadata(report)
			if autoAsset != nil {
				report.Assets = append(report.Assets, *autoAsset)
				p.logger.Info("auto-created asset from report metadata",
					"asset_name", getAssetName(autoAsset),
					"asset_type", autoAsset.Type,
					"asset_id", autoAsset.ID,
				)
			} else {
				p.logger.Warn("failed to auto-create asset from metadata - all priority chains failed",
					"has_branch_info", report.Metadata.Branch != nil,
					"has_scope", report.Metadata.Scope != nil,
					"has_tool", report.Tool != nil,
					"findings_count", len(report.Findings),
				)
			}
		}

		// Still no assets after auto-creation attempt. Only worth a warning
		// when there are findings to lose; a report with neither assets nor
		// findings (a clean scan, an empty chunk) has nothing to orphan.
		if len(report.Assets) == 0 {
			if len(report.Findings) > 0 {
				p.logger.Warn("no assets after auto-creation attempt - findings will be orphaned",
					"findings_count", len(report.Findings),
				)
			}
			return assetMap, nil
		}
	}

	// Step 1: Collect all asset names for batch lookup
	// Names are normalized via NormalizeName inside getAssetName → NewAsset constructor
	names := make([]string, 0, len(report.Assets))
	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		name := getAssetName(ctisAsset)
		if name == "" {
			p.logger.Warn("asset has no name/value",
				"asset_index", i,
				"asset_id", ctisAsset.ID,
				"asset_type", ctisAsset.Type,
			)
			addError(output, fmt.Sprintf("asset %d: name/value is required", i))
			continue
		}
		// Normalize name before lookup so it matches existing normalized assets
		rt := resolveCTISAssetType(ctisAsset)
		name = asset.NormalizeName(name, rt.normType, rt.normSubType)
		if name == "" {
			continue
		}
		names = append(names, name)
	}

	p.logger.Debug("collected asset names for lookup",
		"report_assets_count", len(report.Assets),
		"valid_names_count", len(names),
	)

	// Scope exclusions in effect: a new asset that matches one is not added
	// (exclusions.go). Without them nothing is created (fail closed).
	excl, err := p.loadExclusions(ctx, tenantID)
	if err != nil {
		return assetMap, err
	}

	// Step 2: Batch lookup existing assets
	existingMap, err := p.repo.GetByNames(ctx, tenantID, names)
	if err != nil {
		return assetMap, fmt.Errorf("failed to batch lookup assets: %w", err)
	}

	p.logger.Debug("batch lookup complete",
		"total", len(names),
		"existing", len(existingMap),
	)

	// Step 3: Separate new vs existing assets
	// With IP correlation: if name doesn't match but IPs do, merge into existing.
	newAssets := make([]*asset.Asset, 0)
	updateAssets := make([]*asset.Asset, 0)
	// Assets a scan re-observed after they had gone stale/inactive (reactivated
	// by MarkSeen) — recorded as `recovered` state history after the upsert.
	var recoveredIDs []shared.ID
	// Exposure transitions a re-scan caused on existing assets — recorded as
	// exposure_changed / internet_exposure_changed state history.
	var exposureChanges []*asset.AssetStateChange
	// Every asset this ingest actually inserted, announced once at the end.
	var discovered []*asset.Asset
	// Existing assets this re-scan turned internet-facing.
	var becameExposed []*asset.Asset
	// Set once the upsert persisted the merges, so a failed upsert never
	// announces an exposure that was not saved.
	var exposedPersisted []*asset.Asset

	cfg := p.defaultCorrelationConfig()
	if tenantCfg != nil {
		cfg = *tenantCfg
	}
	// Identifier matching (nil when no identity store is wired or the lookup
	// failed: name and IP matching only, as before).
	idx := p.prepareIdentity(ctx, tenantID, report, cfg)
	source := ""
	if report.Tool != nil {
		source = report.Tool.Name
	}
	allKinds := len(asset.AllIdentifierKinds())
	// When the report's source saw what it reports: last_seen and the
	// property merge keep the newer observation, whatever the arrival order.
	observedAt := reportObservedAt(report, time.Now())
	isNew := map[string]bool{}
	queued := map[string]bool{}
	var renames []pendingRename

	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		name := getAssetName(ctisAsset)
		if name == "" {
			continue
		}

		// Normalize name (same as Step 1)
		rt := resolveCTISAssetType(ctisAsset)
		normalizedName := asset.NormalizeName(name, rt.normType, rt.normSubType)
		coreType := rt.stored.Type
		if normalizedName == "" {
			continue
		}

		// mergeInto folds this report asset into an existing one. A report
		// that may not change the asset (RFC-040 §5.3) only marks it seen,
		// and only while it is active: no flags, exposure, classification,
		// ownership, identifiers or reactivation.
		mergeInto := func(existing *asset.Asset) {
			id := existing.ID().String()
			// An upload's actor may not touch an existing asset outside
			// their data scope at all (Options.Actor).
			if !isNew[id] && scope.actorDenies(existing.ID()) {
				skipOutOfScope(output, ctisAsset.ID)
				return
			}
			alterable := isNew[id] || scope.mayAlter(existing)
			if alterable {
				exposureChanges = append(exposureChanges, p.mergeTrackingExposure(tenantID, existing, ctisAsset, report.Tool, observedAt, &recoveredIDs, &becameExposed)...)
				alterRefs[ctisAsset.ID] = true
			} else {
				output.AssetsLimited++
				if existing.Status() != asset.StatusActive {
					assetMap[ctisAsset.ID] = existing.ID()
					return
				}
				existing.MarkSeenAt(observedAt)
			}
			if !isNew[id] && !queued[id] {
				updateAssets = append(updateAssets, existing)
				queued[id] = true
			}
			assetMap[ctisAsset.ID] = existing.ID()
			if idx != nil && alterable {
				idx.attach(i, existing, coreType, normalizedName, source)
			}
		}
		// rename gives a matched asset the name the report uses now.
		rename := func(existing *asset.Asset, via string) {
			if !isNew[existing.ID().String()] && !scope.mayAlter(existing) {
				return
			}
			oldName := existing.Name()
			if err := existing.UpdateName(normalizedName); err != nil || existing.Name() == oldName {
				return
			}
			renames = append(renames, pendingRename{a: existing, old: oldName, new: existing.Name(), via: via})
			p.logger.Info("asset renamed by identity match",
				"id", existing.ID().String(), "old_name", oldName, "new_name", logger.SanitizeValue(existing.Name()), "matched_by", via)
		}
		// createNew inserts this report asset as a new asset.
		createNew := func() {
			// A restricted upload's actor creates no asset: it could not see
			// it, and skipping it answers like a hidden existing asset.
			if scope.actorRestricted() {
				skipOutOfScope(output, ctisAsset.ID)
				return
			}
			newAsset, createErr := p.createAssetFromCTIS(tenantID, ctisAsset, report.Tool)
			if createErr == nil && (scope == nil || !scope.all) {
				sensorProvenance(newAsset)
			}
			if createErr != nil {
				addError(output, fmt.Sprintf("asset %s (%s): %v", ctisAsset.ID, shortName(normalizedName), createErr))
				return
			}
			scope.dropUntrustedClaims(newAsset)
			// Seen when its source saw it, so a later report observed earlier
			// cannot pass it.
			newAsset.MarkSeenAt(observedAt)
			if skipExcluded(excl, newAsset, ctisAsset.ID, output) {
				return
			}
			newAssets = append(newAssets, newAsset)
			assetMap[ctisAsset.ID] = newAsset.ID()
			alterRefs[ctisAsset.ID] = true
			existingMap[normalizedName] = newAsset
			isNew[newAsset.ID().String()] = true
			if idx != nil {
				idx.attach(i, newAsset, coreType, normalizedName, source)
			}
		}

		nameMatch, hasNameMatch := existingMap[normalizedName]

		// 1. Strong identifiers, strongest first, with the conflict veto.
		if idx != nil {
			if m, conflicts := idx.resolveStrong(i, coreType); m != nil {
				existing := m.a
				for _, c := range conflicts {
					idx.review(existing, c.a, asset.DuplicateReasonIdentifierConflict,
						map[string]any{"kind": string(c.kind), "value": c.value}, normalizedName, coreType)
				}
				nameTaken := hasNameMatch && !nameMatch.ID().Equals(existing.ID())
				if nameTaken && !idx.vetoed(nameMatch, idx.incoming[i], allKinds) {
					// The name belongs to another asset with no conflicting
					// identifier: likely the same machine recorded twice.
					idx.review(existing, nameMatch, asset.DuplicateReasonIdentifierConflict,
						map[string]any{"kind": string(m.kind), "value": m.value, "name": normalizedName}, normalizedName, coreType)
				}
				mergeInto(existing)
				if !nameTaken && shouldAdoptName(existing, normalizedName, true) {
					rename(existing, string(m.kind))
				}
				if !nameTaken {
					existingMap[normalizedName] = existing
				}
				continue
			}
		}

		// 2. Exact name.
		if hasNameMatch {
			if idx != nil {
				if k, vetoed := idx.vetoKind(nameMatch, idx.incoming[i], allKinds); vetoed {
					// Names are unique per tenant, so the report still lands on
					// this asset; its conflicting identifier is not recorded.
					p.logger.Warn("asset name matches an asset with a different identifier",
						"name", logger.SanitizeValue(normalizedName), "asset_id", nameMatch.ID().String(), "kind", string(k))
				}
			}
			mergeInto(nameMatch)
			continue
		}

		// 3. A hostname or FQDN the asset was recently seen with.
		if idx != nil {
			if existing := idx.resolveAlias(i, coreType, normalizedName); existing != nil {
				mergeInto(existing)
				if shouldAdoptName(existing, normalizedName, true) {
					rename(existing, "hostname")
				}
				existingMap[normalizedName] = existing
				continue
			}
		}

		switch {
		case p.correlator != nil && hostFamily(coreType):
			// 4. An unambiguous IP seen within the trust window.
			props := p.buildPropertiesFromCTIS(ctisAsset)
			var recency IPRecency
			if idx != nil {
				recency = idx.ipRecency(i)
			}
			result, corrErr := p.correlator.CorrelateHostRecent(ctx, tenantID, normalizedName, props, cfg, recency)
			if corrErr != nil {
				p.logger.Warn("IP correlation failed, creating new asset",
					"name", logger.SanitizeValue(normalizedName), "error", corrErr)
			}
			if result != nil && len(result.Ambiguous) > 1 {
				// Several assets share the IP: no match, and a review for
				// the operator (RFC-001).
				p.enqueueDedupReview(ctx, tenantID, normalizedName, string(coreType), result.Ambiguous[0], result.Ambiguous[1:])
			}
			if result != nil && result.Matched != nil &&
				(idx == nil || !idx.vetoed(result.Matched, idx.incoming[i], allKinds)) {
				existing := result.Matched
				mergeInto(existing)
				if result.ShouldRename {
					rename(existing, result.CorrelationType)
				}
				// Cache for later assets in same batch
				existingMap[normalizedName] = existing
				continue
			}
			createNew()

		case p.correlator != nil:
			// Extended correlation for other asset types (RFC-001 Phase 3)
			var result *CorrelationResult
			var corrErr error

			switch coreType {
			case asset.AssetTypeRepository:
				result, corrErr = p.correlator.CorrelateRepository(ctx, tenantID, normalizedName, "")
			case asset.AssetTypeCloudAccount, asset.AssetTypeIdentity:
				// Try external_id from properties (account_id, arn, etc.)
				props := p.buildPropertiesFromCTIS(ctisAsset)
				externalID := ""
				if v, ok := props["account_id"].(string); ok && v != "" {
					externalID = v
				} else if v, ok := props["arn"].(string); ok && v != "" {
					externalID = v
				}
				result, corrErr = p.correlator.CorrelateByExternalID(ctx, tenantID, externalID)
			case asset.AssetTypeCertificate:
				props := p.buildPropertiesFromCTIS(ctisAsset)
				result, corrErr = p.correlator.CorrelateCertificate(ctx, tenantID, props)
			}

			if corrErr != nil {
				p.logger.Warn("extended correlation failed", "name", logger.SanitizeValue(normalizedName), "type", coreType, "error", corrErr)
			}

			if result != nil && result.Matched != nil {
				mergeInto(result.Matched)
				existingMap[normalizedName] = result.Matched
			} else {
				createNew()
			}

		default:
			// Correlator disabled → create new
			createNew()
		}
	}

	// Step 4: Batch upsert assets
	if len(newAssets) > 0 || len(updateAssets) > 0 {
		allAssets := make([]*asset.Asset, 0, len(newAssets)+len(updateAssets))
		allAssets = append(allAssets, newAssets...)
		allAssets = append(allAssets, updateAssets...)
		created, updated, persistedIDs, err := p.repo.UpsertBatch(ctx, allAssets)
		if err != nil {
			// None of the new assets was stored: do not hand out their local
			// ids, or findings are linked to rows that do not exist and v2
			// reports the assets as accepted.
			unmapAssets(newAssets, assetMap)
			return assetMap, fmt.Errorf("failed to batch upsert assets: %w", err)
		}
		output.AssetsCreated = created
		output.AssetsUpdated = updated

		// A new asset the database refused (the repository skips just that
		// row) was never stored: unmap it so its findings are not linked to
		// a row that does not exist, and report it as this asset's error.
		dropRefusedAssets(newAssets, persistedIDs, assetMap, existingMap, output)

		// Reconcile assetMap to the ids the DB actually persisted. ON CONFLICT
		// (tenant_id, name) keeps the pre-existing row's id, so an asset we created
		// locally may have lost a concurrent create race — its local UUID was never
		// written. Findings are linked (after this function returns) via assetMap, so
		// any entry still pointing at a non-persisted id would orphan them / break the
		// asset FK. Remap by name to the authoritative id before that linkage happens.
		if len(persistedIDs) > 0 {
			localToName := make(map[string]string, len(allAssets))
			for _, a := range allAssets {
				localToName[a.ID().String()] = a.Name()
			}
			for ctisID, localID := range assetMap {
				name, ok := localToName[localID.String()]
				if !ok {
					continue
				}
				if pid, ok := persistedIDs[name]; ok && !pid.Equals(localID) {
					assetMap[ctisID] = pid
				}
			}
		}

		// Only the assets this batch actually inserted are "new". A local asset
		// whose (tenant_id, name) was inserted concurrently by another ingest
		// kept the other row's id, so it is an update here, not a discovery.
		inserted := insertedAssets(newAssets, persistedIDs)

		// Record discovery state history (appeared for new assets, recovered
		// for reactivated ones, exposure transitions on re-scan). Best-effort —
		// never fails ingestion.
		p.recordDiscoveryHistory(ctx, tenantID, inserted, recoveredIDs)
		p.recordExposureHistory(ctx, tenantID, exposureChanges)

		// The database keeps the existing row's id on a (tenant_id, name)
		// conflict, so map each asset to the id that was persisted.
		// A new asset the database refused has no id at all.
		finalID := func(a *asset.Asset) shared.ID {
			if pid, ok := persistedIDs[a.Name()]; ok {
				return pid
			}
			if persistedIDs != nil && isNew[a.ID().String()] {
				return shared.ID{}
			}
			return a.ID()
		}
		p.recordRenames(ctx, tenantID, renames, finalID)
		p.flushIdentity(ctx, idx, finalID)
		discovered = append(discovered, inserted...)
		exposedPersisted = becameExposed
	}

	// Step 5: Create/update repository extensions for repository assets
	if p.repoExtRepo != nil {
		for i := range report.Assets {
			ctisAsset := &report.Assets[i]
			if ctisAsset.Type != ctis.AssetTypeRepository {
				continue
			}

			name := getAssetName(ctisAsset)
			if name == "" {
				continue
			}

			domainAsset, ok := existingMap[name]
			if !ok {
				continue
			}

			// Create or update repository extension with web_url
			if err := p.ensureRepositoryExtension(ctx, domainAsset, name); err != nil {
				p.logger.Warn("failed to create repository extension",
					"asset_id", domainAsset.ID(),
					"asset_name", name,
					"error", err,
				)
			}
		}
	}

	// Step 5.5: Auto-create root domain assets for orphaned subdomains
	p.ensureRootDomainAssets(ctx, tenantID, report, existingMap, output, &discovered, excl)

	// Step 6: Create subdomain-to-domain relationships
	if p.relRepo != nil {
		p.createSubdomainRelationships(ctx, tenantID, report, existingMap)
	}

	// mayChange says whether this report may change an existing asset
	// (RFC-040 §5.3): derived edges change their source.
	mayChange := func(id shared.ID) bool {
		if scope == nil || scope.all {
			return true
		}
		for ref := range alterRefs {
			if mid, ok := assetMap[ref]; ok && mid == id {
				return true
			}
		}
		return false
	}

	// Step 7: Create resolves_to relationships for DNS records (domain/subdomain → IP)
	if p.relRepo != nil {
		p.createDNSResolvesToRelationships(ctx, tenantID, report, existingMap, output, &discovered, excl, mayChange)
	}

	// Step 9: Ports: address → port edges, host name → address, and ports a
	// port scan no longer sees are closed (research/22 P0-6).
	p.surfacePorts(ctx, tenantID, report, existingMap, mayChange)

	// Step 8: Typed edges from related_assets (service -> the certificate
	// it served).
	if p.relRepo != nil {
		p.createRelatedAssetRelationships(ctx, tenantID, report, assetMap, alterRefs)
	}

	// What this ingest wrote, for attribution (scan_attribution.go): every
	// asset it created (report assets, root domains, resolved addresses) and
	// every existing one it updated.
	for _, a := range discovered {
		scope.note(a, a.ID(), true)
	}
	for _, a := range updateAssets {
		scope.note(a, a.ID(), false)
	}

	// Announce every asset this ingest created (report assets plus the root
	// domains and resolved IPs derived from them) in ONE callback, so the
	// workflow trigger and the notifier see the batch as a whole.
	if p.assetsDiscoveredCallback != nil && len(discovered) > 0 {
		p.assetsDiscoveredCallback(ctx, tenantID, discovered)
	}
	if p.assetsExposedCallback != nil && len(exposedPersisted) > 0 {
		p.assetsExposedCallback(ctx, tenantID, exposedPersisted)
	}

	return assetMap, nil
}

// UpdateFindingCounts updates finding counts for processed assets.
func (p *AssetProcessor) UpdateFindingCounts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}
	return p.repo.UpdateFindingCounts(ctx, tenantID, assetIDs)
}

// ensureRepositoryExtension creates or updates the repository extension for a repository asset.
// It derives the web_url from the asset name (e.g., github.com/org/repo -> https://github.com/org/repo).
func (p *AssetProcessor) ensureRepositoryExtension(ctx context.Context, domainAsset *asset.Asset, assetName string) error {
	if p.repoExtRepo == nil {
		return nil
	}

	// Check if extension already exists
	existing, err := p.repoExtRepo.GetByAssetID(ctx, domainAsset.ID())
	if err == nil && existing != nil {
		// A repository renamed on its SCM host (matched by its SCM ID) keeps
		// its extension; point full name and web URL at the new name.
		if existing.FullName() != "" && existing.FullName() != domainAsset.Name() && hasAlias(domainAsset, existing.FullName()) {
			existing.SetFullName(domainAsset.Name())
			if webURL := deriveWebURLFromAssetName(domainAsset.Name()); webURL != "" {
				existing.SetWebURL(webURL)
			}
			return p.repoExtRepo.Update(ctx, existing)
		}
		// Extension exists, update web_url if empty
		if existing.WebURL() == "" {
			webURL := deriveWebURLFromAssetName(assetName)
			if webURL != "" {
				existing.SetWebURL(webURL)
				return p.repoExtRepo.Update(ctx, existing)
			}
		}
		return nil
	}

	// Create new repository extension
	repoExt, err := asset.NewRepositoryExtension(domainAsset.ID(), assetName, asset.RepoVisibilityPrivate)
	if err != nil {
		return fmt.Errorf("failed to create repository extension: %w", err)
	}

	// Derive and set web_url
	webURL := deriveWebURLFromAssetName(assetName)
	if webURL != "" {
		repoExt.SetWebURL(webURL)
	}

	// Set the full name as it might contain org/repo info
	repoExt.SetFullName(assetName)

	return p.repoExtRepo.Create(ctx, repoExt)
}

// ensureRootDomainAssets auto-creates root domain assets when subdomains reference
// a root_domain that doesn't exist yet. This ensures subdomain-to-domain relationships
// can always be created, even when only subdomains are ingested (e.g., from subfinder).
func (p *AssetProcessor) ensureRootDomainAssets(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	existingMap map[string]*asset.Asset,
	output *Output,
	discovered *[]*asset.Asset,
	excl *scopeapp.ExclusionMatcher,
) {
	// Collect unique root domains that need to be created
	needed := make(map[string]bool)
	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		if ctisAsset.Type != ctis.AssetTypeSubdomain {
			continue
		}

		rootDomain, ok := ctisAsset.Properties["root_domain"].(string)
		if !ok || rootDomain == "" {
			continue
		}

		if !isValidDomainName(rootDomain) {
			continue
		}
		// The report names the root; it must be a registrable parent of the
		// name it came with, or a sensor could create any domain (and through
		// it a Certificate Transparency watch) it likes (research/22b S2).
		rootDomain = strings.ToLower(strings.TrimSuffix(rootDomain, "."))
		if !isRegistrableParent(rootDomain, getAssetName(ctisAsset)) {
			p.logger.Warn("ingest: root_domain is not a registrable parent of the subdomain; not created",
				"root_domain", logger.SanitizeValue(rootDomain), "subdomain", logger.SanitizeValue(getAssetName(ctisAsset)))
			continue
		}

		// Skip if root domain already exists in current batch
		if _, exists := existingMap[rootDomain]; exists {
			continue
		}

		needed[rootDomain] = true
	}

	if len(needed) == 0 {
		return
	}

	// Batch lookup in database for any that already exist outside this batch
	domainNames := make([]string, 0, len(needed))
	for name := range needed {
		domainNames = append(domainNames, name)
	}

	dbExisting, err := p.repo.GetByNames(ctx, tenantID, domainNames)
	if err != nil {
		p.logger.Warn("failed to lookup root domains in database", "error", err)
		return
	}

	// Add found domains to existingMap
	for name, a := range dbExisting {
		existingMap[name] = a
		delete(needed, name)
	}

	if len(needed) == 0 {
		return
	}

	// Create missing root domain assets
	newDomains := make([]*asset.Asset, 0, len(needed))
	for domainName := range needed {
		domainAsset, err := asset.NewAsset(domainName, asset.AssetTypeDomain, asset.CriticalityMedium)
		if err != nil {
			p.logger.Warn("failed to create root domain asset entity",
				"domain", domainName,
				"error", err,
			)
			continue
		}

		domainAsset.SetTenantID(tenantID)
		domainAsset.UpdateDescription("Root domain auto-created from subdomain discovery")

		now := time.Now()
		domainAsset.SetDiscoveryInfo(asset.DiscoverySourceDNS, "subdomain_enumeration", &now)

		metadata := asset.BuildDomainMetadata(domainName, asset.DiscoverySourceDNS)
		domainAsset.SetProperties(metadata)
		if skipExcluded(excl, domainAsset, "", output) {
			continue
		}
		// Same exposure inference as scanner-reported domains (public by nature).
		if inferred := inferAssetExposure(domainAsset); inferred != asset.ExposureUnknown {
			domainAsset.SetExposure(inferred)
		}

		newDomains = append(newDomains, domainAsset)
		existingMap[domainName] = domainAsset
	}

	if len(newDomains) == 0 {
		return
	}

	created, _, persistedIDs, err := p.repo.UpsertBatch(ctx, newDomains)
	if err != nil {
		p.logger.Warn("failed to batch create root domain assets",
			"count", len(newDomains),
			"error", logger.SanitizeError(err),
		)
		// Remove from existingMap since creation failed
		for _, a := range newDomains {
			delete(existingMap, a.Name())
		}
		return
	}

	output.AssetsCreated += created
	inserted := insertedAssets(newDomains, persistedIDs)
	p.recordDiscoveryHistory(ctx, tenantID, inserted, nil)
	*discovered = append(*discovered, inserted...)
	p.logger.Info("auto-created root domain assets for orphaned subdomains",
		"created", created,
		"domains", domainNames,
	)
}

// isRegistrableParent reports whether root is a strict parent of name and
// is itself registrable: at or below its public suffix plus one label
// (example.com, example.co.uk; never com or co.uk).
func isRegistrableParent(root, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if root == "" || !strings.HasSuffix(name, "."+root) {
		return false
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(root)
	if err != nil {
		return false
	}
	return root == etld1 || strings.HasSuffix(root, "."+etld1)
}

// createSubdomainRelationships creates member_of relationships between subdomain and parent domain assets.
// This links subdomains to their parent domains in the asset relationship graph.
// Uses batch INSERT...ON CONFLICT DO NOTHING for efficiency (1 query instead of 2N).
func (p *AssetProcessor) createSubdomainRelationships(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	existingMap map[string]*asset.Asset,
) {
	// Collect all relationships to create
	rels := make([]*asset.Relationship, 0)

	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		if ctisAsset.Type != ctis.AssetTypeSubdomain {
			continue
		}

		// Get root_domain from properties (set by recon converter)
		rootDomain, ok := ctisAsset.Properties["root_domain"].(string)
		if !ok || rootDomain == "" {
			continue
		}

		// Validate domain format
		if !isValidDomainName(rootDomain) {
			p.logger.Warn("invalid root_domain format, skipping relationship",
				"root_domain", rootDomain,
			)
			continue
		}

		subdomainName := getAssetName(ctisAsset)
		if subdomainName == "" {
			continue
		}

		// Find both assets in the existing map
		subdomainAsset, subOk := existingMap[subdomainName]
		parentAsset, parentOk := existingMap[rootDomain]
		if !subOk || !parentOk {
			continue
		}

		// Create `contains` relationship: parent_domain → subdomain.
		// We use the canonical hierarchy direction (source = parent,
		// target = child) — `member_of` was removed from the registry
		// in favour of a single hierarchy direction. See
		// configs/relationship-types.yaml for the design rationale.
		rel, err := asset.NewRelationship(tenantID, parentAsset.ID(), subdomainAsset.ID(), asset.RelTypeContains)
		if err != nil {
			p.logger.Warn("failed to create subdomain relationship entity",
				"subdomain", subdomainName,
				"domain", rootDomain,
				"error", err,
			)
			continue
		}

		rel.SetDescription(fmt.Sprintf("Domain %s contains subdomain %s", rootDomain, subdomainName))
		_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)

		rels = append(rels, rel)
	}

	if len(rels) == 0 {
		return
	}

	// Batch insert all relationships, skipping duplicates via ON CONFLICT DO NOTHING
	created, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		p.logger.Warn("failed to batch create subdomain relationships",
			"total", len(rels),
			"error", err,
		)
		return
	}

	if created > 0 {
		p.logger.Info("created subdomain relationships",
			"created", created,
			"skipped", len(rels)-created,
		)
	}
}

// createDNSResolvesToRelationships creates resolves_to relationships between domain/subdomain
// assets and their resolved IP addresses. If IP assets don't exist yet, they are auto-created.
// This maps the DNS resolution graph for attack surface analysis: the domain's
// ip_addresses property is the summary, the edges (first seen = created_at,
// last seen = last_verified) are the record. An edge changes its domain, so
// a report that may not change the domain (RFC-040 §5.3) adds none.
func (p *AssetProcessor) createDNSResolvesToRelationships(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	existingMap map[string]*asset.Asset,
	output *Output,
	discovered *[]*asset.Asset,
	excl *scopeapp.ExclusionMatcher,
	mayChange func(shared.ID) bool,
) {
	// Collect domain→IP mappings from report assets
	type dnsMapping struct {
		domainName string
		ip         string
	}
	mappings := make([]dnsMapping, 0)
	ipSet := make(map[string]bool)

	for i := range report.Assets {
		ctisAsset := &report.Assets[i]
		name := getAssetName(ctisAsset)
		if name == "" {
			continue
		}
		// The stored asset decides: a report asset of another type that
		// landed on a domain by name (a nuclei result named by its host)
		// carries that domain's addresses too.
		rt := resolveCTISAssetType(ctisAsset)
		domainName := asset.NormalizeName(name, rt.normType, rt.normSubType)
		stored, ok := existingMap[domainName]
		if !ok || (stored.Type() != asset.AssetTypeDomain && stored.Type() != asset.AssetTypeSubdomain) {
			continue
		}
		if mayChange != nil && !mayChange(stored.ID()) {
			continue
		}

		// ip_addresses and every synonym of it (resolved_ips, ip, ...).
		for _, ip := range asset.IPAddresses(ctisAsset.Properties) {
			mappings = append(mappings, dnsMapping{domainName: domainName, ip: ip})
			ipSet[ip] = true
		}
	}

	if len(mappings) == 0 {
		return
	}

	// Ensure IP assets exist
	ipNames := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ipNames = append(ipNames, ip)
	}

	dbIPs, err := p.repo.GetByNames(ctx, tenantID, ipNames)
	if err != nil {
		p.logger.Warn("failed to lookup IP assets", "error", err)
		return
	}
	for name, a := range dbIPs {
		existingMap[name] = a
	}

	// Create missing IP assets
	newIPs := make([]*asset.Asset, 0)
	for ip := range ipSet {
		if _, exists := existingMap[ip]; exists {
			continue
		}

		ipAsset, err := asset.NewAsset(ip, asset.AssetTypeIPAddress, asset.CriticalityLow)
		if err != nil {
			continue
		}
		ipAsset.SetTenantID(tenantID)
		if skipExcluded(excl, ipAsset, "", output) {
			continue
		}
		ipAsset.UpdateDescription("IP address auto-created from DNS resolution")

		now := time.Now()
		ipAsset.SetDiscoveryInfo(asset.DiscoverySourceDNS, "dns_resolution", &now)
		// Same exposure inference as scanner-reported IPs: a public address a
		// DNS name resolves to is internet-reachable.
		if inferred := inferAssetExposure(ipAsset); inferred != asset.ExposureUnknown {
			ipAsset.SetExposure(inferred)
		}

		newIPs = append(newIPs, ipAsset)
		existingMap[ip] = ipAsset
	}

	if len(newIPs) > 0 {
		created, _, persistedIDs, err := p.repo.UpsertBatch(ctx, newIPs)
		if err != nil {
			p.logger.Warn("failed to create IP assets from DNS resolution", "error", logger.SanitizeError(err))
			for _, a := range newIPs {
				delete(existingMap, a.Name())
			}
			return
		}
		output.AssetsCreated += created
		inserted := insertedAssets(newIPs, persistedIDs)
		p.recordDiscoveryHistory(ctx, tenantID, inserted, nil)
		*discovered = append(*discovered, inserted...)
	}

	// Create resolves_to relationships
	rels := make([]*asset.Relationship, 0, len(mappings))
	for _, m := range mappings {
		domainAsset, dOk := existingMap[m.domainName]
		ipAsset, iOk := existingMap[m.ip]
		if !dOk || !iOk {
			continue
		}

		rel, err := asset.NewRelationship(tenantID, domainAsset.ID(), ipAsset.ID(), asset.RelTypeResolvesTo)
		if err != nil {
			continue
		}
		rel.SetDescription(fmt.Sprintf("%s resolves to %s", m.domainName, m.ip))
		_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)
		rel.Verify() // seen now: refreshes last_verified on an existing edge
		rels = append(rels, rel)
	}

	if len(rels) == 0 {
		return
	}

	created, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		p.logger.Warn("failed to create DNS resolves_to relationships", "error", err)
		return
	}

	if created > 0 {
		p.logger.Info("created DNS resolves_to relationships",
			"created", created,
			"skipped", len(rels)-created,
		)
	}
}

// isValidDomainName validates a basic domain name format.
func isValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		// Labels cannot start or end with hyphen
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}
	return true
}

// deriveWebURLFromAssetName derives the web URL from an asset name.
// Supports formats like:
//   - github.com/org/repo -> https://github.com/org/repo
//   - gitlab.com/org/repo -> https://gitlab.com/org/repo
//   - bitbucket.org/org/repo -> https://bitbucket.org/org/repo
//   - https://github.com/org/repo -> https://github.com/org/repo (already a URL)
func deriveWebURLFromAssetName(name string) string {
	// If already a full URL, return as-is
	if strings.HasPrefix(name, "https://") || strings.HasPrefix(name, "http://") {
		return name
	}

	// Check for known git hosting patterns
	gitHostPattern := regexp.MustCompile(`^(github\.com|gitlab\.com|bitbucket\.org)/([^/]+)/([^/]+)`)
	if matches := gitHostPattern.FindStringSubmatch(name); len(matches) >= 4 {
		host := matches[1]
		org := matches[2]
		repo := matches[3]
		return fmt.Sprintf("https://%s/%s/%s", host, org, repo)
	}

	// Check for self-hosted patterns like gitlab.company.com/org/repo
	selfHostedPattern := regexp.MustCompile(`^(gitlab\.[a-zA-Z0-9.-]+|github\.[a-zA-Z0-9.-]+)/([^/]+)/([^/]+)`)
	if matches := selfHostedPattern.FindStringSubmatch(name); len(matches) >= 4 {
		host := matches[1]
		org := matches[2]
		repo := matches[3]
		return fmt.Sprintf("https://%s/%s/%s", host, org, repo)
	}

	return ""
}

// getAssetName extracts the name from a CTIS asset.
func getAssetName(ctisAsset *ctis.Asset) string {
	if ctisAsset.Name != "" {
		return ctisAsset.Name
	}
	return ctisAsset.Value
}

// createAssetFromMetadata creates a CTIS asset from report metadata using a priority chain.
// This ensures findings are never orphaned due to missing asset context.
//
// Priority chain:
//  1. BranchInfo.RepositoryURL - Most reliable for CI/CD scans
//  2. Unique AssetValue from findings - If all findings share same asset
//  3. Scope.Name from metadata - Explicit scan scope
//  4. Repository inferred from file paths - Pattern matching (github.com/org/repo)
//  5. Tool+ScanID fallback - Uses tool name with scan ID
//  6. Emergency fallback - Uses scan_id alone or generates UUID (ensures findings are NEVER orphaned)
//
// This function should NEVER return nil when there are findings to process.
func (p *AssetProcessor) createAssetFromMetadata(report *ctis.Report) *ctis.Asset {
	// Priority 1: BranchInfo.RepositoryURL (most reliable for CI/CD scans)
	if asset := p.createAssetFromBranchInfo(report); asset != nil {
		return asset
	}

	// Priority 2: Unique AssetValue from ALL findings (not just first)
	if asset := p.createAssetFromFindingValues(report); asset != nil {
		return asset
	}

	// Priority 3: Scope information
	if asset := p.createAssetFromScope(report); asset != nil {
		return asset
	}

	// Priority 4: Infer repository from file path patterns
	if asset := p.createAssetFromPathInference(report); asset != nil {
		return asset
	}

	// Priority 5: Tool+ScanID fallback (uses tool name with scan ID)
	if asset := p.createAssetFromToolFallback(report); asset != nil {
		return asset
	}

	// Priority 6: Emergency fallback - ensures findings are NEVER orphaned
	// Uses scan_id if available, otherwise generates a timestamp-based ID
	return p.createAssetFromEmergencyFallback(report)
}

// createAssetFromBranchInfo creates asset from BranchInfo.RepositoryURL.
// This is the most reliable source for CI/CD scans.
func (p *AssetProcessor) createAssetFromBranchInfo(report *ctis.Report) *ctis.Asset {
	if report.Metadata.Branch == nil || report.Metadata.Branch.RepositoryURL == "" {
		return nil
	}

	repoURL := report.Metadata.Branch.RepositoryURL
	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        ctis.AssetTypeRepository,
		Value:       repoURL,
		Name:        repoURL,
		Criticality: ctis.CriticalityHigh,
		Properties: ctis.Properties{
			"auto_created":   true,
			"source":         "branch_info",
			"commit_sha":     report.Metadata.Branch.CommitSHA,
			"branch":         report.Metadata.Branch.Name,
			"default_branch": report.Metadata.Branch.IsDefaultBranch,
		},
	}
}

// createAssetFromFindingValues creates asset from findings' AssetValue.
// Only creates asset if ALL findings with AssetValue reference the SAME asset.
// This prevents incorrect asset creation when findings span multiple repos.
func (p *AssetProcessor) createAssetFromFindingValues(report *ctis.Report) *ctis.Asset {
	// Collect unique asset values from ALL findings
	type assetInfo struct {
		assetType ctis.AssetType
		count     int
	}
	assetSet := make(map[string]*assetInfo)

	for _, finding := range report.Findings {
		if finding.AssetValue == "" {
			continue
		}
		if info, exists := assetSet[finding.AssetValue]; exists {
			info.count++
		} else {
			assetType := finding.AssetType
			if assetType == "" {
				assetType = ctis.AssetTypeRepository
			}
			assetSet[finding.AssetValue] = &assetInfo{assetType: assetType, count: 1}
		}
	}

	// Only auto-create if exactly 1 unique asset value
	// Multiple different values = require explicit assets (safer)
	if len(assetSet) != 1 {
		if len(assetSet) > 1 && p.logger != nil {
			p.logger.Debug("multiple asset values found in findings, skipping auto-creation",
				"count", len(assetSet),
			)
		}
		return nil
	}

	for value, info := range assetSet {
		// SECURITY: Sanitize user-provided asset value
		sanitizedValue := sanitizeAssetName(value)
		if sanitizedValue == "" {
			if p.logger != nil {
				p.logger.Warn("asset value sanitized to empty, skipping",
					"original_value", value,
				)
			}
			return nil
		}

		if p.logger != nil {
			p.logger.Debug("creating asset from finding values",
				"value", logger.SanitizeText(sanitizedValue),
				"type", info.assetType,
				"finding_count", info.count,
			)
		}
		return &ctis.Asset{
			ID:          "auto-asset-1",
			Type:        info.assetType,
			Value:       sanitizedValue,
			Name:        sanitizedValue,
			Criticality: ctis.CriticalityHigh,
			Properties: ctis.Properties{
				"auto_created":  true,
				"source":        "finding_asset_value",
				"finding_count": info.count,
			},
		}
	}

	return nil
}

// createAssetFromScope creates asset from report metadata Scope.
func (p *AssetProcessor) createAssetFromScope(report *ctis.Report) *ctis.Asset {
	if report.Metadata.Scope == nil || report.Metadata.Scope.Name == "" {
		return nil
	}

	scopeType := ctis.AssetTypeUnclassified
	switch report.Metadata.Scope.Type {
	case "repository":
		scopeType = ctis.AssetTypeRepository
	case "domain":
		scopeType = ctis.AssetTypeDomain
	case "ip_address":
		scopeType = ctis.AssetTypeIPAddress
	case "container":
		scopeType = ctis.AssetTypeContainer
	case "cloud_account":
		scopeType = ctis.AssetTypeCloudAccount
	}

	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        scopeType,
		Value:       report.Metadata.Scope.Name,
		Name:        report.Metadata.Scope.Name,
		Criticality: ctis.CriticalityMedium,
		Properties: ctis.Properties{
			"auto_created": true,
			"source":       "scope",
			"scope_type":   report.Metadata.Scope.Type,
		},
	}
}

// createAssetFromPathInference infers repository from file path patterns.
// Supports patterns like:
//   - github.com/org/repo/path/to/file.go
//   - gitlab.com/org/repo/path/to/file.go
//   - bitbucket.org/org/repo/path/to/file.go
//
// Also detects common project root patterns when paths share a common prefix.
func (p *AssetProcessor) createAssetFromPathInference(report *ctis.Report) *ctis.Asset {
	if len(report.Findings) == 0 {
		return nil
	}

	// Collect all file paths from findings
	var paths []string
	for _, finding := range report.Findings {
		if finding.Location != nil && finding.Location.Path != "" {
			paths = append(paths, finding.Location.Path)
		}
	}

	if len(paths) == 0 {
		return nil
	}

	// Pattern 1: Check for Git hosting URL patterns in paths
	// e.g., github.com/org/repo/... or file:///github.com/org/repo/...
	// SECURITY: Only allow known git hosts to prevent domain spoofing
	gitHostPattern := regexp.MustCompile(`(github\.com|gitlab\.com|bitbucket\.org)/([^/]+)/([^/]+)`)
	for _, path := range paths {
		if matches := gitHostPattern.FindStringSubmatch(path); len(matches) >= 4 {
			host := matches[1]
			org := matches[2]
			repo := matches[3]

			// SECURITY: Validate host is known git provider
			if !isValidGitHost(host) {
				continue
			}

			// SECURITY: Sanitize org and repo names
			org = sanitizeAssetName(org)
			repo = sanitizeAssetName(repo)
			if org == "" || repo == "" {
				continue
			}

			repoURL := fmt.Sprintf("https://%s/%s/%s", host, org, repo)

			if p.logger != nil {
				p.logger.Debug("inferred repository from path pattern",
					"repo_url", repoURL,
					"source_path", path,
				)
			}
			return &ctis.Asset{
				ID:          "auto-asset-1",
				Type:        ctis.AssetTypeRepository,
				Value:       repoURL,
				Name:        repoURL,
				Criticality: ctis.CriticalityHigh,
				Properties: ctis.Properties{
					"auto_created": true,
					"source":       "path_inference",
					"pattern":      "git_host_url",
				},
			}
		}
	}

	// Pattern 2: Find common path prefix (project root)
	// If all paths share a common directory prefix, use it as project identifier
	if len(paths) >= 2 {
		commonPrefix := findCommonPathPrefix(paths)
		if commonPrefix != "" && len(commonPrefix) > 3 {
			// Clean up the prefix
			projectName := filepath.Base(commonPrefix)
			if projectName == "" || projectName == "." || projectName == "/" {
				projectName = commonPrefix
			}
			// Only use if it looks like a meaningful project name
			if len(projectName) >= 2 && !strings.HasPrefix(projectName, ".") {
				// SECURITY: Sanitize project name
				projectName = sanitizeAssetName(projectName)
				if projectName == "" {
					return nil
				}

				// SECURITY: Sanitize common_prefix to avoid path disclosure
				sanitizedPrefix := sanitizePathForProperty(commonPrefix)

				if p.logger != nil {
					p.logger.Debug("inferred project from common path prefix",
						"project_name", logger.SanitizeValue(projectName),
						"common_prefix", sanitizedPrefix,
						"path_count", len(paths),
					)
				}
				return &ctis.Asset{
					ID:          "auto-asset-1",
					Type:        ctis.AssetTypeRepository,
					Value:       projectName,
					Name:        projectName,
					Criticality: ctis.CriticalityMedium,
					Properties: ctis.Properties{
						"auto_created":  true,
						"source":        "path_inference",
						"pattern":       "common_prefix",
						"common_prefix": sanitizedPrefix, // SECURITY: Sanitized path
					},
				}
			}
		}
	}

	return nil
}

// createAssetFromToolFallback creates a pseudo-asset from tool name and scan ID.
// This is the last resort to ensure findings are never orphaned.
func (p *AssetProcessor) createAssetFromToolFallback(report *ctis.Report) *ctis.Asset {
	// Need at least tool name to create meaningful fallback
	if report.Tool == nil || report.Tool.Name == "" {
		return nil
	}

	toolName := report.Tool.Name
	scanID := report.Metadata.ID
	if scanID == "" {
		scanID = UnknownValue
	}

	// Create a meaningful identifier
	assetName := fmt.Sprintf("scan:%s:%s", toolName, scanID)

	if p.logger != nil {
		p.logger.Info("creating fallback asset from tool+scan_id",
			"tool_name", toolName,
			"scan_id", scanID,
			"asset_name", assetName,
		)
	}

	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        ctis.AssetTypeUnclassified,
		Value:       assetName,
		Name:        assetName,
		Criticality: ctis.CriticalityMedium,
		Properties: ctis.Properties{
			"auto_created": true,
			"source":       "tool_fallback",
			"tool_name":    toolName,
			"scan_id":      scanID,
		},
	}
}

// createAssetFromEmergencyFallback creates a pseudo-asset when all other methods fail.
// This is the absolute last resort to ensure findings are NEVER orphaned.
// Uses scan_id if available, otherwise generates a timestamp-based ID.
func (p *AssetProcessor) createAssetFromEmergencyFallback(report *ctis.Report) *ctis.Asset {
	// Try to use scan ID
	scanID := report.Metadata.ID
	if scanID == "" {
		// Generate a timestamp-based ID as last resort
		scanID = fmt.Sprintf("ingest-%d", time.Now().UnixNano())
	}

	// Try to extract source type for more meaningful naming
	sourceType := report.Metadata.SourceType
	if sourceType == "" {
		sourceType = "unknown"
	}

	assetName := fmt.Sprintf("scan:%s:%s", sourceType, scanID)

	if p.logger != nil {
		p.logger.Warn("creating emergency fallback asset - report lacks metadata",
			"scan_id", scanID,
			"source_type", sourceType,
			"asset_name", assetName,
			"findings_count", len(report.Findings),
		)
	}

	return &ctis.Asset{
		ID:          "auto-asset-1",
		Type:        ctis.AssetTypeUnclassified,
		Value:       assetName,
		Name:        assetName,
		Criticality: ctis.CriticalityLow, // Low criticality since we have no context
		Properties: ctis.Properties{
			"auto_created":   true,
			"source":         "emergency_fallback",
			"scan_id":        scanID,
			"source_type":    sourceType,
			"findings_count": len(report.Findings),
		},
	}
}

// findCommonPathPrefix finds the longest common directory prefix among paths.
func findCommonPathPrefix(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) == 1 {
		return filepath.Dir(paths[0])
	}

	// Start with first path's directory
	prefix := filepath.Dir(paths[0])

	for _, path := range paths[1:] {
		pathDir := filepath.Dir(path)
		// Find common prefix between current prefix and this path
		for !strings.HasPrefix(pathDir, prefix) && prefix != "" && prefix != "." && prefix != "/" {
			prefix = filepath.Dir(prefix)
		}
		if prefix == "" || prefix == "." || prefix == "/" {
			return ""
		}
	}

	return prefix
}

// createAssetFromCTIS creates a new domain Asset from a CTIS Asset.
func (p *AssetProcessor) createAssetFromCTIS(
	tenantID shared.ID,
	ctisAsset *ctis.Asset,
	tool *ctis.Tool,
) (*asset.Asset, error) {
	// Resolve aliases and legacy sub-types to the stored (type, sub_type):
	// e.g. "firewall" → (network, firewall). Aliases are never stored.
	rt := resolveCTISAssetType(ctisAsset)
	if rt.stored.NativeSubType != "" {
		p.logger.Warn("unknown asset sub_type from sensor kept as x_native_sub_type",
			"asset_type", string(rt.stored.Type), "sub_type", logger.SanitizeValue(rt.stored.NativeSubType))
	}
	criticality := mapCTISCriticality(ctisAsset.Criticality)

	name := getAssetName(ctisAsset)
	if name == "" {
		return nil, fmt.Errorf("asset name/value is required")
	}

	// NewAsset refuses a name longer than asset.MaxNameLength (after
	// normalization); the caller reports that as an error of this one asset.
	// It used to truncate at 1024 bytes, which still overflowed
	// assets.name varchar(255) and failed the whole report's upsert.
	// Create with the sub-type so the stored name is normalized with the same
	// (type, sub-type) key the lookup above used (RFC-043 section 10).
	newAsset, err := asset.NewAssetWithSubType(name, rt.normType, rt.normSubType, criticality)
	if err != nil {
		return nil, err
	}

	newAsset.SetTenantID(tenantID)

	// Set description (with length limit) - log if truncated
	const maxDescLength = 4096
	if ctisAsset.Description != "" {
		desc := ctisAsset.Description
		if len(desc) > maxDescLength {
			p.logger.Warn("asset description truncated",
				"original_length", len(desc),
				"max_length", maxDescLength,
				"asset_id", ctisAsset.ID,
			)
			desc = desc[:maxDescLength]
		}
		newAsset.UpdateDescription(desc)
	}

	// Set tags (with limit) - log if truncated
	tags := ctisAsset.Tags
	if len(tags) > MaxTagsPerAsset {
		p.logger.Warn("asset tags truncated",
			"original_count", len(tags),
			"max_count", MaxTagsPerAsset,
			"asset_id", ctisAsset.ID,
		)
		tags = tags[:MaxTagsPerAsset]
	}
	for _, tag := range tags {
		newAsset.AddTag(tag)
	}

	// properties.sub_type was resolved with the type above; it is a column,
	// not a property.
	delete(ctisAsset.Properties, "sub_type")

	// Set discovery info
	discoverySource := DiscoverySourceSensor
	discoveryTool := ""
	if tool != nil {
		discoveryTool = tool.Name
	}
	if source, ok := ctisAsset.Properties[asset.PropKeyDiscoverySource].(string); ok {
		discoverySource = normalizeDiscoverySource(source)
	}
	if toolName, ok := ctisAsset.Properties[asset.PropKeyDiscoveryTool].(string); ok {
		discoveryTool = toolName
	}

	// A discovery time in the future would keep the asset out of the
	// lifecycle's grace check for as long as the reporter likes.
	discoveredAt := ctisAsset.DiscoveredAt
	if now := time.Now(); discoveredAt == nil || discoveredAt.After(now) {
		discoveredAt = &now
	}
	newAsset.SetDiscoveryInfo(discoverySource, discoveryTool, discoveredAt)

	// Set owner reference from external source
	ownerRef := p.extractOwnerRef(ctisAsset)
	if ownerRef != "" {
		newAsset.SetOwnerRef(ownerRef)
	}

	// Build and set properties (with validation), then what the input type
	// implied (sub-type, provider, attributes) where nothing is set.
	properties := p.buildPropertiesFromCTIS(ctisAsset)
	dropMisplacedProperties(newAsset.Type(), newAsset.SubType(), properties)
	newAsset.SetProperties(properties)
	newAsset.ApplyResolvedType(rt.stored)

	// Carry the scanner's explicit CTEM signals that were previously dropped at
	// this seam — internet-exposure, compliance scope, data classification, and
	// PII/PHI all feed the prioritization engine's reachability + business-
	// context gates. Before this, only regulatory_owner was read.
	p.applyCTEMSignals(newAsset, ctisAsset, true)

	// Infer internet exposure when the scanner didn't provide one. Exposure is
	// the reachability signal the prioritization engine reads, and it was
	// previously left `unknown` for every ingested asset, so the reachability-
	// gated P0/P1 priority rules never fired.
	if newAsset.Exposure() == asset.ExposureUnknown {
		if inferred := inferAssetExposure(newAsset); inferred != asset.ExposureUnknown {
			newAsset.SetExposure(inferred)
		}
	}

	return newAsset, nil
}

// applyCTEMSignals carries the scanner's explicit CTEM/business-context signals
// from the CTIS asset onto the domain asset. These feed the prioritization
// engine; before this they were silently dropped at the ingest mapping seam
// (only regulatory_owner was consumed). Trusting an explicit
// is_internet_accessible also beats the heuristic exposure inference.
//
// The data classification is applied only to a new asset (classify);
// an existing asset's is decided by attribute reconciliation (RFC-069).
func (p *AssetProcessor) applyCTEMSignals(a *asset.Asset, ctisAsset *ctis.Asset, classify bool) {
	if ctisAsset.IsInternetAccessible {
		a.SetInternetAccessible(true)
		if a.Exposure() == asset.ExposureUnknown {
			a.SetExposure(asset.ExposurePublic)
		}
	}

	c := ctisAsset.Compliance
	if c == nil {
		return
	}
	if len(c.Frameworks) > 0 {
		a.SetComplianceScope(c.Frameworks)
	}
	if classify && c.DataClassification != "" {
		if err := a.SetDataClassification(asset.DataClassification(c.DataClassification)); err != nil {
			p.logger.Warn("invalid data_classification from scanner",
				"value", logger.SanitizeValue(c.DataClassification), "asset", logger.SanitizeValue(a.Name()), "error", err)
		}
	}
	if c.PIIExposed {
		a.SetPIIDataExposed(true)
	}
	if c.PHIExposed {
		a.SetPHIDataExposed(true)
	}
}

// inferAssetExposure derives an internet-exposure level from the asset's type
// and network properties. Assets that are internet-facing by nature (DNS/web)
// or that carry a public (non-RFC1918) IP are `public`; everything else is left
// `unknown` (conservative — internal hosts on private IPs stay non-reachable).
//
// The IPs come from every shape ingest stores them in (ExtractAllIPs): host
// normalisation (normalizeHostIPProperties) moves the legacy `ip` string into
// `ip_addresses` and deletes `ip`, so reading `ip` alone never saw a host's IP.
func inferAssetExposure(a *asset.Asset) asset.Exposure {
	// Internet-facing by nature, declared in the registry (exposure_default):
	// it used to compare against website/api, which ingest never stores, so
	// web applications and APIs were never marked public (RFC-042 §6.3.8).
	if e := asset.DefaultExposure(a.Type(), a.SubType()); e != asset.ExposureUnknown {
		return e
	}
	for _, ip := range ExtractAllIPs(a.Properties(), a.Name()) {
		if isPublicIP(ip) {
			return asset.ExposurePublic
		}
	}
	return asset.ExposureUnknown
}

// isPublicIP reports whether s is a routable public IP (not private/loopback/
// link-local/unspecified).
func isPublicIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
}

// mergeCTISIntoAsset merges CTIS data into an existing asset.
// observedAt is when the report's source saw the asset (reportObservedAt).
func (p *AssetProcessor) mergeCTISIntoAsset(existing *asset.Asset, ctisAsset *ctis.Asset, tool *ctis.Tool, observedAt time.Time, recovered *[]shared.ID) {
	// Mark as seen. Capture the prior status first so we can tell when this
	// scan reactivates a stale/inactive asset (MarkSeen flips it to active).
	wasInactive := existing.Status() == asset.StatusStale || existing.Status() == asset.StatusInactive
	existing.MarkSeenAt(observedAt)
	if recovered != nil && wasInactive && existing.Status() == asset.StatusActive {
		*recovered = append(*recovered, existing.ID())
	}

	// owner_ref and data classification of an existing asset are decided
	// by attribute reconciliation (attributes.go, RFC-069), not here.

	// Merge tags
	for _, tag := range ctisAsset.Tags {
		existing.AddTag(tag)
	}

	// Merge properties using deep merge
	existingProps := existing.Properties()
	newProps := p.buildPropertiesFromCTIS(ctisAsset)
	mergedProps := mergePropertiesDeep(existingProps, newProps)
	// The stored asset's schema decides (the report asset may be of another
	// type that landed here by name): technical blocks an older row still
	// holds are promoted to flat keys, synonyms fold, and a key only another
	// class may hold is not kept here.
	asset.NormalizeAssetProperties(existing.Type(), existing.SubType(), mergedProps)
	dropMisplacedProperties(existing.Type(), existing.SubType(), mergedProps)
	if p.trackSets {
		keepReconciledSets(existingProps, mergedProps)
	}
	existing.SetProperties(mergedProps)

	// Re-apply the scanner's explicit CTEM signals on re-scan (compliance /
	// classification / PII-PHI / internet-exposure) so a later scan that learns
	// them updates the inventory instead of dropping them.
	p.applyCTEMSignals(existing, ctisAsset, false)

	// Backfill exposure on re-scan for assets that predate exposure inference
	// (or that had no signal before) — only when still unknown, never overriding.
	if existing.Exposure() == asset.ExposureUnknown {
		if inferred := inferAssetExposure(existing); inferred != asset.ExposureUnknown {
			existing.SetExposure(inferred)
		}
	}

	// Fill the sub-type (and provider, attributes) the report implies when the
	// existing asset has none; only from the registry's closed list, and
	// only for an asset of the same type.
	existing.ApplyResolvedType(resolveCTISAssetType(ctisAsset).stored)

	// Update discovery tool if not set
	if existing.DiscoveryTool() == "" && tool != nil {
		existing.SetDiscoveryTool(tool.Name)
	}
}

// buildPropertiesFromCTIS builds the properties JSONB from CTIS Asset.
func (p *AssetProcessor) buildPropertiesFromCTIS(ctisAsset *ctis.Asset) map[string]any {
	props := make(map[string]any)

	// Copy CTIS properties (with validation)
	propCount := 0
	for k, v := range ctisAsset.Properties {
		if propCount >= MaxPropertiesPerAsset {
			break
		}

		// Skip platform-owned keys: the discovery fields (handled separately)
		// and the decisions people make (crown jewel, business impact) or the
		// platform records (aliases). A sensor must not set them.
		if asset.IsReservedPropertyKey(k) {
			continue
		}

		// Validate key length
		if len(k) > 100 {
			continue
		}

		props[k] = v
		propCount++
	}

	// Identity hints a scanner observed (CTIS 1.4), bounded, for display and
	// correlation; matching reads them in identifiersFor.
	if h := identityHintProperties(ctisAsset.IdentityHints); h != nil {
		props["identity_hints"] = h
	}

	// Add technical details based on asset type
	if ctisAsset.Technical != nil {
		if ctisAsset.Technical.Domain != nil {
			props["domain"] = buildDomainProperties(ctisAsset.Technical.Domain)
		}
		if ctisAsset.Technical.IPAddress != nil {
			props["ip_address"] = buildIPAddressProperties(ctisAsset.Technical.IPAddress)
		}
		if ctisAsset.Technical.Service != nil {
			props["service"] = buildServiceProperties(ctisAsset.Technical.Service)
		}
		if ctisAsset.Technical.Certificate != nil {
			props["certificate"] = buildCertificateProperties(ctisAsset.Technical.Certificate)
		}
	}

	// One key per concept (RFC-042 §6.3.9): ip, ips, resolved_ips, a plain
	// ip_address string, the technical ip_address block's address, ... all
	// fold into ip_addresses; nameserver into nameservers, and so on.
	asset.NormalizeProperties(props)

	// A host also records the address it is named by.
	if ctisAsset.Type == ctis.AssetTypeHost {
		normalizeHostIPProperties(props, getAssetName(ctisAsset))
	}

	// The asset is keyed by its name, so when a scanner sends a hostname as
	// the name and the address as the value (sdk-go's Vuls adapter does), the
	// address was dropped and a renamed host could never be matched by IP.
	// Keep it in ip_addresses, the array IP correlation searches.
	if ctisAsset.Type == ctis.AssetTypeHost || ctisAsset.Type == ctis.AssetTypeIPAddress {
		if v := strings.TrimSpace(ctisAsset.Value); v != "" && v != getAssetName(ctisAsset) {
			asset.AddIPAddress(props, v)
		}
	}

	// An IP address asset is its own address: ip_addresses lists only others.
	if ctisAsset.Type == ctis.AssetTypeIPAddress {
		dropOwnAddress(props, getAssetName(ctisAsset))
	}

	// Validate properties based on asset type
	if errs := p.propsValidator.ValidateProperties(string(ctisAsset.Type), props); errs != nil {
		p.logger.Warn("properties validation errors",
			"asset_type", ctisAsset.Type,
			"asset_value", ctisAsset.Value,
			"errors", errs.Error(),
		)
	}

	// Properties are flat (RFC-042 §6.3.10): the technical blocks' facts
	// move to the stored type's keys, and the blocks go.
	stored := resolveCTISAssetType(ctisAsset).stored
	asset.NormalizeAssetProperties(stored.Type, stored.SubType, props)
	if stored.Type == asset.AssetTypeCertificate {
		capCertificateProperties(props)
	}

	return props
}

// extractOwnerRef extracts owner reference from CTIS asset.
// Checks multiple sources: compliance.regulatory_owner, technical.repository.owner,
// properties.owner, properties.contact.
func (p *AssetProcessor) extractOwnerRef(ctisAsset *ctis.Asset) string {
	// 1. Compliance regulatory owner (highest priority)
	if ctisAsset.Compliance != nil && ctisAsset.Compliance.RegulatoryOwner != "" {
		return ctisAsset.Compliance.RegulatoryOwner
	}

	// 2. Repository owner (GitHub/GitLab org)
	if ctisAsset.Technical != nil && ctisAsset.Technical.Repository != nil && ctisAsset.Technical.Repository.Owner != "" {
		return ctisAsset.Technical.Repository.Owner
	}

	// 3. Properties (custom fields from scanner)
	if owner, ok := ctisAsset.Properties["owner"].(string); ok && owner != "" {
		return owner
	}
	if contact, ok := ctisAsset.Properties["contact"].(string); ok && contact != "" {
		return contact
	}
	if responsible, ok := ctisAsset.Properties["responsible"].(string); ok && responsible != "" {
		return responsible
	}

	return ""
}

// normalizeHostIPProperties completes a host's properties once synonyms
// are folded (asset.NormalizeProperties): a host named by an address records
// that address in ip_addresses. (The hostname of its technical ip_address
// block reaches `hostname` through asset.PromoteTechnicalBlocks.)
func normalizeHostIPProperties(props map[string]any, assetName string) {
	if looksLikeIPv4(assetName) {
		asset.AddIPAddress(props, assetName)
	}
}

// dropMisplacedProperties removes the keys only assets of other classes may
// hold (routeMisplacedProperties moved the report's own to their asset).
func dropMisplacedProperties(t asset.AssetType, subType string, props map[string]any) {
	for _, k := range asset.MisplacedPropertyKeys(t, subType, props) {
		delete(props, k)
	}
}

// dropOwnAddress removes an IP address asset's own address from its
// ip_addresses (the key goes when nothing else is left).
func dropOwnAddress(props map[string]any, assetName string) {
	own := net.ParseIP(strings.TrimSpace(assetName))
	if own == nil {
		return
	}
	ips := asset.IPAddresses(props)
	if len(ips) == 0 {
		return
	}
	rest := make([]any, 0, len(ips))
	for _, ip := range ips {
		if ip != own.String() {
			rest = append(rest, ip)
		}
	}
	if len(rest) == 0 {
		delete(props, asset.PropKeyIPAddresses)
		return
	}
	props[asset.PropKeyIPAddresses] = rest
}

// looksLikeIPv4 returns true if s matches basic IPv4 pattern.
func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// sensorProvenance keeps a sensor's report from claiming a provenance that
// is not a scan. The lifecycle worker leaves assets of the manual, import
// and integration categories alone by default (assetProvenanceSQL), so a
// sensor that labels a planted asset "manual" would keep it from ever going
// stale and show it as made by a person. Such a claim is recorded as
// "sensor"; scanner categories (dns, cert_transparency, …) are kept.
func sensorProvenance(a *asset.Asset) {
	switch strings.ToLower(strings.TrimSpace(a.DiscoverySource())) {
	case "", asset.DiscoverySourceManual, "import", "nessus", "kubernetes",
		"integration", "aws", "gcp", "azure", "git-host":
		a.SetDiscoveryInfo(DiscoverySourceSensor, a.DiscoveryTool(), a.DiscoveredAt())
	}
}
