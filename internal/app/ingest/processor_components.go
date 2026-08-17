package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/ctis"
)

// ComponentProcessor handles batch processing of dependencies/components during ingestion.
type ComponentProcessor struct {
	repo   component.Repository
	logger *slog.Logger
}

// NewComponentProcessor creates a new component processor.
func NewComponentProcessor(repo component.Repository, logger *slog.Logger) *ComponentProcessor {
	return &ComponentProcessor{
		repo:   repo,
		logger: logger,
	}
}

// ComponentOutput tracks component processing results.
type ComponentOutput struct {
	ComponentsCreated  int
	ComponentsUpdated  int
	DependenciesLinked int
	LicensesLinked     int
	Errors             []string
	Warnings           []string
}

// ProcessBatch processes all dependencies from a CTIS report.
// It creates/updates global components and links them to assets.
// Three-pass approach to handle foreign key constraints:
// 1. Pass 1: Create all global components and collect their IDs
// 2. Pass 2: Insert asset_components WITHOUT parent_component_id
// 3. Pass 3: Update asset_components WITH parent_component_id
func (p *ComponentProcessor) ProcessBatch(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	assetMap map[string]shared.ID,
	output *Output,
) error {
	if len(report.Dependencies) == 0 {
		return nil
	}

	p.logger.Debug("starting component processing",
		"dependencies_count", len(report.Dependencies),
		"assets_count", len(assetMap),
	)

	compOutput := &ComponentOutput{}

	if len(assetMap) == 0 {
		p.logger.Warn("no asset found for dependency linking")
		return nil
	}

	// Resolve the OWNING asset for each dependency (index-aligned with
	// report.Dependencies). Previously every dependency was linked to a RANDOM
	// first asset from the map, collapsing a multi-asset SBOM onto one asset;
	// this attributes each dependency to its correct asset.
	depAssetIDs := p.resolveDepAssetIDs(report, assetMap)

	// Pass 1: Create all global components and build lookup maps
	// componentIDMap: PURL/name@version -> component ID
	componentIDMap := make(map[string]shared.ID)

	for _, dep := range report.Dependencies {
		compID, err := p.createOrUpdateComponent(ctx, &dep, compOutput)
		if err != nil {
			p.logger.Warn("failed to create/update component",
				"name", dep.Name,
				"version", dep.Version,
				"error", err,
			)
			compOutput.Errors = append(compOutput.Errors, err.Error())
			continue
		}

		// Build lookup keys (multiple formats for matching DependsOn)
		keys := p.buildDependencyKeys(&dep)
		for _, key := range keys {
			componentIDMap[key] = compID
		}
	}

	// Pass 2: Insert asset_components WITHOUT parent_component_id
	// Build assetDepIDMap for parent lookup in Pass 3. Keys are namespaced by
	// owning asset so the same PURL on two assets can't collide.
	assetDepIDMap := make(map[string]shared.ID)
	assetDepDepthMap := make(map[string]int)

	for i, dep := range report.Dependencies {
		assetID := depAssetIDs[i]
		if assetID.IsZero() {
			continue // could not attribute (already logged during resolution)
		}

		keys := p.buildDependencyKeys(&dep)
		primaryKey := keys[0] // First key is the primary one

		compID, ok := componentIDMap[primaryKey]
		if !ok {
			continue // Component wasn't created successfully
		}

		// Insert WITHOUT parent (parent_component_id will be updated in Pass 3)
		assetDepID, depth, err := p.linkDependencyToAssetWithoutParent(ctx, tenantID, assetID, compID, &dep, compOutput)
		if err != nil {
			p.logger.Warn("failed to link dependency",
				"name", dep.Name,
				"version", dep.Version,
				"error", err,
			)
			compOutput.Errors = append(compOutput.Errors, err.Error())
			continue
		}

		// Store in maps for parent lookup in Pass 3 (namespaced by asset).
		if !assetDepID.IsZero() {
			for _, key := range keys {
				nsKey := assetScopedKey(assetID, key)
				assetDepIDMap[nsKey] = assetDepID
				assetDepDepthMap[nsKey] = depth
			}
		}
	}

	// Pass 3: Update asset_components WITH parent_component_id
	// Now all asset_components exist, we can safely set parent references. Parent
	// resolution is scoped to the SAME owning asset as the child.
	for i, dep := range report.Dependencies {
		// Only process transitive dependencies with DependsOn
		if dep.Relationship != "indirect" && dep.Relationship != "transitive" {
			continue
		}
		if len(dep.DependsOn) == 0 {
			continue
		}

		assetID := depAssetIDs[i]
		if assetID.IsZero() {
			continue
		}

		keys := p.buildDependencyKeys(&dep)
		primaryKey := keys[0]

		assetDepID, ok := assetDepIDMap[assetScopedKey(assetID, primaryKey)]
		if !ok || assetDepID.IsZero() {
			continue // Asset dependency wasn't created
		}

		// Find parent's asset_component ID — within this dependency's own asset.
		parentID, parentDepth, found := p.findParentInMaps(assetID, dep.DependsOn, assetDepIDMap, assetDepDepthMap)
		if !found {
			// Try database lookup as fallback (also asset-scoped)
			parentID, parentDepth, found = p.findParentInDB(ctx, assetID, dep.DependsOn)
		}

		if found && parentID != nil {
			// Calculate depth and update
			depth := parentDepth + 1
			if err := p.repo.UpdateAssetDependencyParent(ctx, assetDepID, *parentID, depth); err != nil {
				p.logger.Warn("failed to update parent reference",
					"dependency", dep.Name,
					"parent_id", parentID.String(),
					"error", err,
				)
			} else {
				// Update local map with correct depth
				for _, key := range keys {
					assetDepDepthMap[assetScopedKey(assetID, key)] = depth
				}
			}
		}
	}

	p.logger.Info("component processing complete",
		"components_created", compOutput.ComponentsCreated,
		"components_updated", compOutput.ComponentsUpdated,
		"dependencies_linked", compOutput.DependenciesLinked,
		"licenses_linked", compOutput.LicensesLinked,
		"errors", len(compOutput.Errors),
		"warnings", len(compOutput.Warnings),
	)

	// Update output stats
	output.ComponentsCreated = compOutput.ComponentsCreated
	output.ComponentsUpdated = compOutput.ComponentsUpdated
	output.DependenciesLinked = compOutput.DependenciesLinked
	output.LicensesLinked = compOutput.LicensesLinked
	output.Warnings = append(output.Warnings, compOutput.Warnings...)
	// Merge component errors too — the ingest audit log derives its
	// success/partial/failed result from len(output.Errors). Without this a SBOM
	// import where every component failed was recorded as a full success.
	output.Errors = append(output.Errors, compOutput.Errors...)

	return nil
}

// buildDependencyKeys creates multiple lookup keys for a dependency.
// This allows matching DependsOn values in various formats that scanners might provide.
// Returns keys in order of preference: PURL, name@version, name, ID
func (p *ComponentProcessor) buildDependencyKeys(dep *ctis.Dependency) []string {
	keys := make([]string, 0, 4)

	// Primary key: PURL (most specific)
	if dep.PURL != "" {
		keys = append(keys, dep.PURL)
	}

	// Secondary key: name@version
	nameVersion := fmt.Sprintf("%s@%s", dep.Name, dep.Version)
	keys = append(keys, nameVersion)

	// Tertiary key: just name (some scanners only provide name in DependsOn)
	if dep.Name != "" {
		keys = append(keys, dep.Name)
	}

	// Quaternary key: ID if provided
	if dep.ID != "" && dep.ID != dep.Name {
		keys = append(keys, dep.ID)
	}

	return keys
}

// findParentInMaps attempts to find a parent dependency using multiple key
// formats, scoped to the child's owning asset. Returns the parent's
// asset_dependency ID and depth if found.
func (p *ComponentProcessor) findParentInMaps(
	assetID shared.ID,
	dependsOn []string,
	assetDepIDMap map[string]shared.ID,
	assetDepDepthMap map[string]int,
) (*shared.ID, int, bool) {
	for _, parentRef := range dependsOn {
		// Try exact match first
		if id, ok := assetDepIDMap[assetScopedKey(assetID, parentRef)]; ok {
			depth := assetDepDepthMap[assetScopedKey(assetID, parentRef)]
			return &id, depth, true
		}

		// Try with pkg: prefix (some tools provide just the path part)
		if !strings.HasPrefix(parentRef, "pkg:") {
			purlKey := "pkg:" + parentRef
			if id, ok := assetDepIDMap[assetScopedKey(assetID, purlKey)]; ok {
				depth := assetDepDepthMap[assetScopedKey(assetID, purlKey)]
				return &id, depth, true
			}
		}
	}
	return nil, 0, false
}

// assetScopedKey namespaces a dependency lookup key by its owning asset so the
// same PURL / name appearing on two assets in one multi-asset report cannot
// collide in the Pass 2/3 maps.
func assetScopedKey(assetID shared.ID, key string) string {
	return assetID.String() + "\x1f" + key
}

// resolveDepAssetIDs returns, index-aligned with report.Dependencies, the
// persisted asset ID each dependency should link to. Resolution order:
//  1. Single-asset report → that asset (the common SBOM case; deterministic,
//     replacing the old random map-iteration pick).
//  2. Multi-asset report → the report asset whose value or name appears in the
//     dependency's file path(s) (monorepo / multi-target SBOMs emit per-target
//     paths). The most specific (longest) match wins.
//  3. Unresolved → a deterministic fallback asset (preserving the previous
//     "link it somewhere" behavior rather than dropping the component), logged
//     so the ambiguity is visible.
func (p *ComponentProcessor) resolveDepAssetIDs(report *ctis.Report, assetMap map[string]shared.ID) []shared.ID {
	out := make([]shared.ID, len(report.Dependencies))

	// Single-asset fast path.
	if len(assetMap) == 1 {
		var only shared.ID
		for _, id := range assetMap {
			only = id
		}
		for i := range out {
			out[i] = only
		}
		return out
	}

	// Build path-match candidates (value/name → persisted asset ID) and a
	// deterministic fallback (smallest ctis asset ID that maps to a persisted
	// asset), both derived from report.Assets.
	matchers, fallback := p.buildAssetMatchers(report, assetMap)

	for i := range report.Dependencies {
		dep := &report.Dependencies[i]
		if id, ok := matchDepToAsset(dep, matchers); ok {
			out[i] = id
			continue
		}
		out[i] = fallback
		if fallback.IsZero() {
			p.logger.Warn("SBOM dependency could not be attributed to any asset; skipping",
				"name", sanitizeIngestLogField(dep.Name), "version", sanitizeIngestLogField(dep.Version))
		} else {
			p.logger.Debug("SBOM dependency not attributable to a specific asset; using fallback",
				"name", sanitizeIngestLogField(dep.Name), "version", sanitizeIngestLogField(dep.Version), "asset_id", fallback.String())
		}
	}
	return out
}

// assetMatcher pairs a lowercased match token (asset value or name) with its
// persisted asset ID.
type assetMatcher struct {
	token string
	id    shared.ID
}

// buildAssetMatchers builds the path-match tokens for each report asset that is
// present in assetMap, plus a deterministic fallback asset ID (the one with the
// lexicographically smallest ctis asset ID). Longer tokens are ordered first so
// the most specific match wins.
func (p *ComponentProcessor) buildAssetMatchers(report *ctis.Report, assetMap map[string]shared.ID) ([]assetMatcher, shared.ID) {
	matchers := make([]assetMatcher, 0, len(report.Assets)*2)
	fallback := shared.ID{}
	fallbackKey := ""

	for _, a := range report.Assets {
		id, ok := assetMap[a.ID]
		if !ok {
			continue
		}
		if fallbackKey == "" || a.ID < fallbackKey {
			fallbackKey = a.ID
			fallback = id
		}
		for _, tok := range []string{a.Value, a.Name} {
			tok = strings.ToLower(strings.TrimSpace(tok))
			if tok != "" {
				matchers = append(matchers, assetMatcher{token: tok, id: id})
			}
		}
	}

	// If report.Assets is empty/uncorrelated, fall back to a deterministic pick
	// from assetMap itself so the fallback is never zero when assets exist.
	if fallback.IsZero() {
		bestKey := ""
		for k, id := range assetMap {
			if bestKey == "" || k < bestKey {
				bestKey = k
				fallback = id
			}
		}
	}

	sort.SliceStable(matchers, func(i, j int) bool {
		return len(matchers[i].token) > len(matchers[j].token)
	})
	return matchers, fallback
}

// matchDepToAsset returns the asset whose value/name token appears in any of the
// dependency's file paths. The matchers are pre-sorted longest-first, so the
// first hit is the most specific.
func matchDepToAsset(dep *ctis.Dependency, matchers []assetMatcher) (shared.ID, bool) {
	if len(matchers) == 0 {
		return shared.ID{}, false
	}
	paths := make([]string, 0, len(dep.Locations)+1)
	if dep.Path != "" {
		paths = append(paths, strings.ToLower(dep.Path))
	}
	for _, loc := range dep.Locations {
		if loc.Path != "" {
			paths = append(paths, strings.ToLower(loc.Path))
		}
	}
	for _, m := range matchers {
		for _, path := range paths {
			if strings.Contains(path, m.token) {
				return m.id, true
			}
		}
	}
	return shared.ID{}, false
}

// findParentInDB attempts to find a parent dependency in the database.
// This is a fallback for when the parent was created in a previous scan but not included in current batch.
// Returns the parent's asset_dependency ID and depth if found.
func (p *ComponentProcessor) findParentInDB(
	ctx context.Context,
	assetID shared.ID,
	dependsOn []string,
) (*shared.ID, int, bool) {
	for _, parentRef := range dependsOn {
		// Try to find by PURL (most reliable)
		purl := parentRef
		if !strings.HasPrefix(purl, "pkg:") {
			purl = "pkg:" + parentRef
		}

		existingDep, err := p.repo.GetExistingDependencyByPURL(ctx, assetID, purl)
		if err != nil {
			p.logger.Debug("failed to lookup parent in DB",
				"purl", purl,
				"error", err,
			)
			continue
		}

		if existingDep != nil {
			id := existingDep.ID()
			p.logger.Debug("found parent in DB from previous scan",
				"parent_purl", purl,
				"parent_id", id.String(),
				"parent_depth", existingDep.Depth(),
			)
			return &id, existingDep.Depth(), true
		}
	}
	return nil, 0, false
}

// createOrUpdateComponent creates or updates a global component.
// Returns the component ID.
func (p *ComponentProcessor) createOrUpdateComponent(
	ctx context.Context,
	dep *ctis.Dependency,
	output *ComponentOutput,
) (shared.ID, error) {
	// Step 1: Parse ecosystem
	ecosystem, _ := component.ParseEcosystem(dep.Ecosystem)

	// Step 2: Create or update global component
	comp, err := component.NewComponent(dep.Name, dep.Version, ecosystem)
	if err != nil {
		return shared.ID{}, err
	}

	// Prefer agent's PURL over generated PURL
	// Agent's PURL may be more accurate (e.g., includes namespace, qualifiers)
	if dep.PURL != "" {
		comp.SetPURL(dep.PURL)
	}
	if len(dep.Licenses) > 0 {
		comp.UpdateLicense(strings.Join(dep.Licenses, ", "))
	}

	// Upsert component (creates if not exists, returns ID)
	compID, err := p.repo.Upsert(ctx, comp)
	if err != nil {
		return shared.ID{}, err
	}

	// Link licenses to component
	if len(dep.Licenses) > 0 {
		linked, err := p.repo.LinkLicenses(ctx, compID, dep.Licenses)
		if err != nil {
			p.logger.Warn("failed to link licenses",
				"component_id", compID.String(),
				"licenses", dep.Licenses,
				"error", err,
			)
			output.Warnings = append(output.Warnings, fmt.Sprintf("license linking failed for %s: %v", dep.Name, err))
			// Don't fail the whole process for license linking errors
		} else {
			output.LicensesLinked += linked
		}
	}

	// Track if created or updated
	if comp.ID() == compID {
		output.ComponentsCreated++
	} else {
		output.ComponentsUpdated++
	}

	return compID, nil
}

// linkDependencyToAssetWithoutParent links a component to an asset WITHOUT parent tracking.
// This is used in Pass 2 to ensure all asset_components exist before setting parent references.
// Returns the asset_dependency ID and initial depth for use in Pass 3.
func (p *ComponentProcessor) linkDependencyToAssetWithoutParent(
	ctx context.Context,
	tenantID shared.ID,
	assetID shared.ID,
	compID shared.ID,
	dep *ctis.Dependency,
	output *ComponentOutput,
) (shared.ID, int, error) {
	// Parse dependency type
	depType, _ := component.ParseDependencyType(dep.Relationship)

	// Create asset dependency link WITHOUT parent
	assetDep, err := component.NewAssetDependency(tenantID, assetID, compID, dep.Path, depType)
	if err != nil {
		return shared.ID{}, 0, err
	}

	// Set initial depth based on dependency type
	// - depth = 1: direct dependency
	// - depth = 2: transitive dependency (will be updated in Pass 3 if parent found)
	depth := 1
	if depType == component.DependencyTypeTransitive {
		depth = 2
		assetDep.SetDepth(depth)
	}

	// Link asset to component (without parent reference)
	if err := p.repo.LinkAsset(ctx, assetDep); err != nil {
		// Ignore duplicate link errors (already linked)
		if !strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "already exists") {
			return shared.ID{}, 0, err
		}
		// For duplicates, try to get the existing ID
		existingDep, lookupErr := p.repo.GetExistingDependencyByComponentID(ctx, assetID, compID, dep.Path)
		if lookupErr == nil && existingDep != nil {
			return existingDep.ID(), existingDep.Depth(), nil
		}
		// Return zero ID for duplicate - it's already linked
		return shared.ID{}, depth, nil
	}

	output.DependenciesLinked++
	return assetDep.ID(), depth, nil
}
