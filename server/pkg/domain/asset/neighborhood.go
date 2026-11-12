package asset

// Asset neighborhood (docs/architecture/asset-relationships.md,
// "Neighborhood"): the assets around one asset up to a few hops away, in
// both directions, with large sibling groups collapsed into counted clusters.

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Bounds of a neighborhood read. A request outside them is clamped, never
// refused, so the console can ask for "the default" without knowing them.
const (
	NeighborhoodMaxDepth     = 3
	NeighborhoodDefaultDepth = 2
	// NeighborhoodDefaultNodes and NeighborhoodMaxNodes bound how many
	// assets one answer draws; the rest are counted in clusters.
	NeighborhoodDefaultNodes = 150
	NeighborhoodMaxNodes     = 300
	// NeighborhoodClusterAt is the largest group of siblings (one anchor,
	// one relationship type, one direction) drawn one by one; a bigger group
	// is returned as one cluster with its count.
	NeighborhoodClusterAt = 8
	// NeighborhoodMaxFilters bounds the types and relations lists.
	NeighborhoodMaxFilters = 32
)

// Neighborhood directions, seen from the anchor asset.
const (
	NeighborhoodBoth = "both"
	NeighborhoodOut  = "out"
	NeighborhoodIn   = "in"
)

// NeighborhoodHopQuery is one hop of a neighborhood walk: the edges of
// every frontier asset. Known assets (already in the answer) are returned as
// edges and never counted into a cluster. With a non-nil Scope the other end
// of an edge must be in it; edges to assets outside it are only counted per
// anchor (HiddenByAnchor), whatever the filters, so a filter cannot probe
// what an out-of-scope asset is.
type NeighborhoodHopQuery struct {
	Frontier  []shared.ID
	Known     []shared.ID
	Direction string
	Types     []AssetType
	Relations []RelationshipType
	Scope     *shared.DataScope
	ClusterAt int
}

// NeighborhoodNode is an asset of a neighborhood the caller may see.
type NeighborhoodNode struct {
	ID          shared.ID
	Name        string
	Type        AssetType
	SubType     string
	Status      string
	Criticality string
	Exposure    string
}

// NeighborhoodEdge is one relationship seen from the anchor. Direction is
// RelationshipDirectionOutgoing when the anchor is the source.
type NeighborhoodEdge struct {
	Anchor    shared.ID
	Other     NeighborhoodNode
	Type      RelationshipType
	Direction string
	// Known is set when Other was already in the answer before this hop.
	Known bool
}

// NeighborhoodCluster is a group of siblings returned as a count: every
// in-scope asset at the other end of the anchor's edges of one type in one
// direction, by asset type.
type NeighborhoodCluster struct {
	Anchor    shared.ID
	Type      RelationshipType
	Direction string
	ByType    map[AssetType]int
}

// Count is the number of assets in the cluster.
func (c NeighborhoodCluster) Count() int {
	n := 0
	for _, v := range c.ByType {
		n += v
	}
	return n
}

// NeighborhoodHop is the answer for one hop. Edges come most critical first
// within each group.
type NeighborhoodHop struct {
	Edges          []NeighborhoodEdge
	Clusters       []NeighborhoodCluster
	HiddenByAnchor map[shared.ID]int
}

// NeighborhoodReader reads one hop of a neighborhood. Every table is bound
// to the tenant, soft-deleted assets are skipped, and the scope is applied
// in the database (a hidden asset's name never leaves it).
type NeighborhoodReader interface {
	NeighborhoodHop(ctx context.Context, tenantID shared.ID, q NeighborhoodHopQuery) (*NeighborhoodHop, error)
}

// GraphReader is the graph read engine of an asset: its discovery lineage
// and its neighborhood.
type GraphReader interface {
	LineageReader
	NeighborhoodReader
}

// NeighborhoodQuery is a caller's neighborhood request (already parsed).
type NeighborhoodQuery struct {
	Depth     int
	Direction string
	Types     []AssetType
	Relations []RelationshipType
	MaxNodes  int
}

// Normalize clamps the query to the bounds above and fills the defaults.
func (q NeighborhoodQuery) Normalize() NeighborhoodQuery {
	if q.Depth <= 0 {
		q.Depth = NeighborhoodDefaultDepth
	}
	q.Depth = min(q.Depth, NeighborhoodMaxDepth)
	if q.Direction == "" {
		q.Direction = NeighborhoodBoth
	}
	if q.MaxNodes <= 0 {
		q.MaxNodes = NeighborhoodDefaultNodes
	}
	q.MaxNodes = min(q.MaxNodes, NeighborhoodMaxNodes)
	return q
}

// NeighborhoodGraphNode is a node of the answer: the asset and how far it
// is from the asset asked about.
type NeighborhoodGraphNode struct {
	NeighborhoodNode
	// Distance is the number of hops from the asset (0 for the asset).
	Distance int
	// Expanded is set when this node's own edges were read (its neighbors,
	// clusters and hidden count are in the answer).
	Expanded bool
	// HiddenNeighbors counts the related assets outside the caller's data
	// scope (only for expanded nodes).
	HiddenNeighbors int
}

// NeighborhoodGraphEdge is one relationship of the answer, source to target
// as stored.
type NeighborhoodGraphEdge struct {
	Source shared.ID
	Target shared.ID
	Type   RelationshipType
}

// Neighborhood is the answer: nodes (the asset first), edges between them,
// clusters hanging off nodes, and the asset's discovery lineage.
type Neighborhood struct {
	Query    NeighborhoodQuery
	Nodes    []NeighborhoodGraphNode
	Edges    []NeighborhoodGraphEdge
	Clusters []NeighborhoodCluster
	Lineage  Lineage
	// Truncated is set when the node cap stopped the walk; what did not fit
	// is counted in clusters.
	Truncated bool
	// HiddenCount is the sum of HiddenNeighbors.
	HiddenCount int
}
