package ingest

// SBOM dependencies of a CTIS report into the software catalog. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
)

// ComponentProcessor writes the dependencies of a report as package
// snapshots, one per owning asset.
type ComponentProcessor struct {
	writer software.PackageWriter
	logger *slog.Logger
}

// NewComponentProcessor creates a new component processor.
func NewComponentProcessor(writer software.PackageWriter, logger *slog.Logger) *ComponentProcessor {
	return &ComponentProcessor{writer: writer, logger: logger}
}

// PackageChannel is the package channel of a report: a sensor, an
// integration, a person (finding import) or a CI upload.
func PackageChannel(fromSensor bool, sourceType string) string {
	switch {
	case fromSensor:
		return software.ChannelSensor
	case strings.EqualFold(sourceType, "integration"):
		return software.ChannelIntegration
	case strings.EqualFold(sourceType, "manual"):
		return software.ChannelFindingImport
	default:
		return software.ChannelCI
	}
}

// DependencyNodes converts CTIS dependencies to package nodes, index-aligned
// with deps; ok[i] is false for an entry without a usable identity or a root
// entry (the project itself), whose depends_on marks the direct packages.
func DependencyNodes(deps []ctis.Dependency) (nodes []software.PackageNode, ok []bool) {
	nodes = make([]software.PackageNode, len(deps))
	ok = make([]bool, len(deps))
	direct := map[string]bool{}
	for i := range deps {
		if strings.EqualFold(deps[i].Relationship, "root") {
			for _, ref := range deps[i].DependsOn {
				direct[ref] = true
			}
		}
	}
	for i := range deps {
		d := &deps[i]
		if strings.EqualFold(d.Relationship, "root") {
			continue
		}
		n, valid := dependencyNode(d)
		if !valid {
			continue
		}
		if n.Relationship == software.RelationshipUnknown && (direct[d.ID] || direct[d.PURL] || direct[d.Name]) {
			n.Relationship = software.RelationshipDirect
		}
		nodes[i], ok[i] = n, true
	}
	return nodes, ok
}

func dependencyNode(d *ctis.Dependency) (software.PackageNode, bool) {
	var n software.PackageNode
	p, err := software.ParsePURL(d.PURL)
	if err != nil {
		p, err = software.SyntheticPURL(d.Ecosystem, d.Name, d.Version)
		if err != nil {
			return n, false
		}
		n.Synthetic = true
	}
	if p.Version == "" {
		p.Version = clipVersion(d.Version)
	}
	ref := d.ID
	if ref == "" {
		ref = d.PURL
	}
	if ref == "" {
		ref = d.Name + "@" + d.Version
	}
	location := d.Path
	if location == "" && len(d.Locations) > 0 {
		location = d.Locations[0].Path
	}
	n.Ref = ref
	n.PURL = p
	n.DisplayName = d.Name
	n.Location = software.CleanLocation(location)
	n.Relationship = software.NormalizeRelationship(d.Relationship)
	n.Scope = dependencyScope(d)
	n.Licenses = software.NormalizeLicenses(d.Licenses)
	n.DependsOn = d.DependsOn
	return n, true
}

// dependencyScope reads the scope a producer put in the dependency
// properties (CycloneDX scope, trivy "dev").
func dependencyScope(d *ctis.Dependency) string {
	for _, k := range []string{"scope", "dependency_scope"} {
		if v, ok := d.Properties[k].(string); ok {
			if s := software.NormalizeScope(v); s != "" {
				return s
			}
		}
	}
	if dev, ok := d.Properties["dev"].(bool); ok && dev {
		return software.ScopeDevelopment
	}
	return ""
}

func clipVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > software.MaxPackageVer {
		v = v[:software.MaxPackageVer]
	}
	return v
}

// ProcessBatch writes the report's dependencies, one snapshot per owning
// asset. A report is a full inventory of the locations it names.
func (p *ComponentProcessor) ProcessBatch(
	ctx context.Context,
	tenantID shared.ID,
	report *ctis.Report,
	assetMap map[string]shared.ID,
	channel string,
	output *Output,
) error {
	if len(report.Dependencies) == 0 || p.writer == nil {
		return nil
	}
	if len(assetMap) == 0 {
		p.logger.Warn("no asset found for dependency linking")
		return nil
	}
	depAssetIDs := p.resolveDepAssetIDs(report, assetMap)
	nodes, ok := DependencyNodes(report.Dependencies)
	byAsset := map[shared.ID][]software.PackageNode{}
	order := []shared.ID{}
	for i := range nodes {
		if !ok[i] || depAssetIDs[i].IsZero() {
			continue
		}
		if _, seen := byAsset[depAssetIDs[i]]; !seen {
			order = append(order, depAssetIDs[i])
		}
		byAsset[depAssetIDs[i]] = append(byAsset[depAssetIDs[i]], nodes[i])
	}
	for _, assetID := range order {
		res, err := p.writer.WritePackages(ctx, tenantID, software.PackageSnapshot{
			AssetID: assetID, Channel: channel, Packages: byAsset[assetID], Replace: true,
		})
		if err != nil {
			p.logger.Warn("failed to write packages", "asset_id", assetID.String(), "error", sanitizeIngestLogField(err.Error()))
			output.Errors = append(output.Errors, "packages: "+err.Error())
			continue
		}
		output.ComponentsCreated += res.Versions
		output.DependenciesLinked += res.Links
	}
	return nil
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
