package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/sdk/pkg/eis"
)

// ComponentProcessor handles batch processing of dependencies/components during ingestion.
type ComponentProcessor struct {
	repo    component.Repository
	logger  *slog.Logger
	verbose bool
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

// ProcessBatch processes all dependencies from an EIS report.
// It creates/updates global components and links them to assets.
// Three-pass approach to handle foreign key constraints:
// 1. Pass 1: Create all global components and collect their IDs
// 2. Pass 2: Insert asset_components WITHOUT parent_component_id
// 3. Pass 3: Update asset_components WITH parent_component_id
func (p *ComponentProcessor) ProcessBatch(
	ctx context.Context,
	tenantID shared.ID,
	report *eis.Report,
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

	// Get the first asset ID (typically there's one asset per scan)
	var assetID shared.ID
	for _, id := range assetMap {
		assetID = id
		break
	}

	if assetID.IsZero() {
		p.logger.Warn("no asset found for dependency linking")
		return nil
	}

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
	// Build assetDepIDMap for parent lookup in Pass 3
	assetDepIDMap := make(map[string]shared.ID)
	assetDepDepthMap := make(map[string]int)

	for _, dep := range report.Dependencies {
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

		// Store in maps for parent lookup in Pass 3
		if !assetDepID.IsZero() {
			for _, key := range keys {
				assetDepIDMap[key] = assetDepID
				assetDepDepthMap[key] = depth
			}
		}
	}

	// Pass 3: Update asset_components WITH parent_component_id
	// Now all asset_components exist, we can safely set parent references
	for _, dep := range report.Dependencies {
		// Only process transitive dependencies with DependsOn
		if dep.Relationship != "indirect" && dep.Relationship != "transitive" {
			continue
		}
		if len(dep.DependsOn) == 0 {
			continue
		}

		keys := p.buildDependencyKeys(&dep)
		primaryKey := keys[0]

		assetDepID, ok := assetDepIDMap[primaryKey]
		if !ok || assetDepID.IsZero() {
			continue // Asset dependency wasn't created
		}

		// Find parent's asset_component ID
		parentID, parentDepth, found := p.findParentInMaps(dep.DependsOn, assetDepIDMap, assetDepDepthMap)
		if !found {
			// Try database lookup as fallback
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
					assetDepDepthMap[key] = depth
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

	return nil
}

// buildDependencyKeys creates multiple lookup keys for a dependency.
// This allows matching DependsOn values in various formats that scanners might provide.
// Returns keys in order of preference: PURL, name@version, name, ID
func (p *ComponentProcessor) buildDependencyKeys(dep *eis.Dependency) []string {
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

// findParentInMaps attempts to find a parent dependency using multiple key formats.
// Returns the parent's asset_dependency ID and depth if found.
func (p *ComponentProcessor) findParentInMaps(
	dependsOn []string,
	assetDepIDMap map[string]shared.ID,
	assetDepDepthMap map[string]int,
) (*shared.ID, int, bool) {
	for _, parentRef := range dependsOn {
		// Try exact match first
		if id, ok := assetDepIDMap[parentRef]; ok {
			depth := assetDepDepthMap[parentRef]
			return &id, depth, true
		}

		// Try with pkg: prefix (some tools provide just the path part)
		if !strings.HasPrefix(parentRef, "pkg:") {
			purlKey := "pkg:" + parentRef
			if id, ok := assetDepIDMap[purlKey]; ok {
				depth := assetDepDepthMap[purlKey]
				return &id, depth, true
			}
		}
	}
	return nil, 0, false
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
	dep *eis.Dependency,
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
	dep *eis.Dependency,
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
