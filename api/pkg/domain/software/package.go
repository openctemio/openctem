package software

// Package observations: what a producer (sensor or CI SCA tool, SBOM upload,
// finding import) reports about the packages one asset is built from.
// Design: api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Package link relationship values.
const (
	RelationshipDirect     = "direct"
	RelationshipTransitive = "transitive"
	RelationshipUnknown    = "unknown"
)

// Package dependency scopes.
const (
	ScopeRuntime     = "runtime"
	ScopeDevelopment = "development"
	ScopeTest        = "test"
	ScopeOptional    = "optional"
	ScopeBuild       = "build"
	ScopeProvided    = "provided"
)

// Channels a package observation arrives through.
const (
	ChannelSensor        = "sensor"
	ChannelCI            = "ci"
	ChannelSBOMUpload    = "sbom_upload"
	ChannelFindingImport = "finding_import"
	ChannelIntegration   = "integration"
)

// Limits on one snapshot (a hostile SBOM must not exhaust the database).
const (
	MaxSnapshotPackages = 100_000
	MaxSnapshotEdges    = 500_000
	MaxLinkLicenses     = 16
	MaxLicenseLen       = 128
	MaxPackageLocation  = 512
	MaxDepth            = 32
)

// PackageNode is one package entry of a snapshot.
type PackageNode struct {
	// Ref is the producer's key for the entry (bom-ref, SPDX id, purl or
	// name@version); DependsOn names other entries by Ref.
	Ref          string
	PURL         PURL
	DisplayName  string
	Location     string
	Relationship string
	Scope        string
	Licenses     []string
	DependsOn    []string
	// Synthetic: the producer gave no package URL; PURL was built from the
	// ecosystem and name, so the identity is less certain.
	Synthetic bool
}

// PackageSnapshot is what one report says about one asset's packages.
type PackageSnapshot struct {
	AssetID  shared.ID
	Channel  string
	Packages []PackageNode
	// Replace marks a full inventory of the locations it reports (an SBOM):
	// links at those locations that it does not name are removed. A partial
	// report (packages named by findings) only adds and refreshes.
	Replace bool
}

// PackageWriteResult counts what a write changed.
type PackageWriteResult struct {
	Products   int `json:"products_created"`
	Versions   int `json:"versions_created"`
	Links      int `json:"links_written"`
	Edges      int `json:"edges_written"`
	Removed    int `json:"links_removed"`
	Superseded int `json:"links_superseded"`
}

// PackageWriter stores package observations in the catalog.
type PackageWriter interface {
	// WritePackages resolves products and versions for the snapshot (the
	// tenant's own rows first, then global rows, else new tenant-private
	// rows), upserts the asset's links and replaces the edges of the
	// reported locations.
	WritePackages(ctx context.Context, tenantID shared.ID, snap PackageSnapshot) (PackageWriteResult, error)
	// EnsurePackageVersion returns the version id the tenant sees for a
	// package URL, creating tenant-private rows when none exists.
	EnsurePackageVersion(ctx context.Context, tenantID shared.ID, p PURL) (shared.ID, error)
}

// NormalizeRelationship maps producer vocabularies onto direct, transitive or
// unknown.
func NormalizeRelationship(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "direct", "explicit", "top-level", "toplevel":
		return RelationshipDirect
	case "transitive", "indirect", "transit", "implicit":
		return RelationshipTransitive
	default:
		return RelationshipUnknown
	}
}

// NormalizeScope maps producer vocabularies onto the stored scopes ("" when
// unknown). CycloneDX "required" is runtime, "excluded" is development.
func NormalizeScope(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "runtime", "required", "compile", "main", "prod", "production":
		return ScopeRuntime
	case "dev", "development", "excluded", "devdependencies":
		return ScopeDevelopment
	case "test":
		return ScopeTest
	case "optional", "peer":
		return ScopeOptional
	case "build":
		return ScopeBuild
	case "provided", "system":
		return ScopeProvided
	default:
		return ""
	}
}

// licenseRe admits SPDX ids, expressions ("MIT OR Apache-2.0") and plain
// license names; anything else (markup, control characters) is dropped.
var licenseRe = regexp.MustCompile(`^[A-Za-z0-9 .+\-()/:_]+$`)

// NormalizeLicenses trims, de-duplicates and caps a license list; entries
// that are not license ids, expressions or names are dropped.
func NormalizeLicenses(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, l := range in {
		for _, part := range strings.Split(l, ",") {
			part = clip(strings.TrimSpace(part), MaxLicenseLen)
			if part == "" || strings.EqualFold(part, "NOASSERTION") || strings.EqualFold(part, "NONE") || seen[part] || !licenseRe.MatchString(part) {
				continue
			}
			seen[part] = true
			out = append(out, part)
			if len(out) == MaxLinkLicenses {
				sort.Strings(out)
				return out
			}
		}
	}
	sort.Strings(out)
	return out
}

// CleanLocation trims a manifest path to the stored limit.
func CleanLocation(s string) string {
	return clip(strings.TrimSpace(s), MaxPackageLocation)
}

// PlannedEdge is a dependency edge between two snapshot entries, by index.
type PlannedEdge struct{ Parent, Child int }

// PlanGraph resolves DependsOn references to entry indexes, drops self and
// dangling references, and computes each entry's depth breadth-first from the
// roots (direct entries, or entries no other entry depends on when the
// producer marked none). It also fills an unknown relationship from the
// graph: depth 0 is direct, deeper is transitive. Cycles are tolerated.
// It returns the edges and the depth per entry (-1 when unreachable).
func PlanGraph(nodes []PackageNode) ([]PlannedEdge, []int) {
	edges, children, hasParent := resolveEdges(nodes)
	depth := graphDepths(nodes, children, hasParent)
	for i := range nodes {
		if nodes[i].Relationship != RelationshipUnknown && nodes[i].Relationship != "" {
			continue
		}
		switch {
		case depth[i] == 0 && len(edges) > 0:
			nodes[i].Relationship = RelationshipDirect
		case depth[i] > 0:
			nodes[i].Relationship = RelationshipTransitive
		default:
			nodes[i].Relationship = RelationshipUnknown
		}
	}
	return edges, depth
}

// nodeIndex maps every key an entry is referred to by (its Ref, its package
// URL with and without version) to the first entry with that key.
func nodeIndex(nodes []PackageNode) map[string]int {
	index := make(map[string]int, len(nodes)*3)
	add := func(k string, i int) {
		if _, dup := index[k]; !dup && k != "" {
			index[k] = i
		}
	}
	for i, n := range nodes {
		add(n.Ref, i)
	}
	for i, n := range nodes {
		add(n.PURL.String(), i)
		add(n.PURL.Base(), i)
	}
	return index
}

// resolveEdges turns DependsOn references into edges between entries,
// dropping self, duplicate and dangling references.
func resolveEdges(nodes []PackageNode) ([]PlannedEdge, [][]int, []bool) {
	index := nodeIndex(nodes)
	lookup := func(ref string) (int, bool) {
		if j, ok := index[ref]; ok {
			return j, true
		}
		if !strings.HasPrefix(ref, "pkg:") {
			j, ok := index["pkg:"+ref]
			return j, ok
		}
		return 0, false
	}
	edges := make([]PlannedEdge, 0, len(nodes))
	seen := make(map[PlannedEdge]bool, len(nodes))
	children := make([][]int, len(nodes))
	hasParent := make([]bool, len(nodes))
	for i, n := range nodes {
		for _, ref := range n.DependsOn {
			j, ok := lookup(ref)
			e := PlannedEdge{Parent: i, Child: j}
			if !ok || j == i || seen[e] || len(edges) >= MaxSnapshotEdges {
				continue
			}
			seen[e] = true
			edges = append(edges, e)
			children[i] = append(children[i], j)
			hasParent[j] = true
		}
	}
	return edges, children, hasParent
}

// graphDepths walks breadth-first from the roots: the direct entries, or,
// when the producer marked none, the entries no other entry depends on.
func graphDepths(nodes []PackageNode, children [][]int, hasParent []bool) []int {
	anyDirect := false
	for _, n := range nodes {
		if n.Relationship == RelationshipDirect {
			anyDirect = true
			break
		}
	}
	depth := make([]int, len(nodes))
	queue := make([]int, 0, len(nodes))
	for i, n := range nodes {
		depth[i] = -1
		if (anyDirect && n.Relationship == RelationshipDirect) || (!anyDirect && !hasParent[i]) {
			depth[i] = 0
			queue = append(queue, i)
		}
	}
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		if depth[i] >= MaxDepth {
			continue
		}
		for _, j := range children[i] {
			if depth[j] == -1 {
				depth[j] = depth[i] + 1
				queue = append(queue, j)
			}
		}
	}
	return depth
}
