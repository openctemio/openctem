package asset

// Asset neighborhood (docs/architecture/asset-relationships.md,
// "Neighborhood").

import (
	"context"
	"fmt"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetGraphReader wires the graph read engine (neighborhood and lineage).
// Unset, a neighborhood holds only the asset itself.
func (s *AssetRelationshipService) SetGraphReader(r assetdom.GraphReader) { s.graph = r }

// NeighborhoodInput is a caller's neighborhood request, as received.
type NeighborhoodInput struct {
	Depth     int
	Direction string
	Types     []string
	Relations []string
	MaxNodes  int
}

// parseNeighborhoodInput validates the filters and clamps the bounds.
func parseNeighborhoodInput(in NeighborhoodInput) (assetdom.NeighborhoodQuery, error) {
	q := assetdom.NeighborhoodQuery{Depth: in.Depth, Direction: in.Direction, MaxNodes: in.MaxNodes}
	switch in.Direction {
	case "", assetdom.NeighborhoodBoth, assetdom.NeighborhoodOut, assetdom.NeighborhoodIn:
	default:
		return q, fmt.Errorf("%w: direction must be both, out or in", shared.ErrValidation)
	}
	if len(in.Types) > assetdom.NeighborhoodMaxFilters || len(in.Relations) > assetdom.NeighborhoodMaxFilters {
		return q, fmt.Errorf("%w: at most %d types and %d relations", shared.ErrValidation,
			assetdom.NeighborhoodMaxFilters, assetdom.NeighborhoodMaxFilters)
	}
	for _, t := range in.Types {
		at, err := assetdom.ParseAssetType(t)
		if err != nil {
			return q, fmt.Errorf("%w: unknown asset type", shared.ErrValidation)
		}
		q.Types = append(q.Types, at)
	}
	for _, r := range in.Relations {
		rt, err := assetdom.ParseRelationshipType(r)
		if err != nil {
			return q, err
		}
		q.Relations = append(q.Relations, rt)
	}
	return q.Normalize(), nil
}

// Neighborhood returns the assets around an asset up to q.Depth hops away
// (both directions unless asked otherwise), with its discovery lineage.
//
//   - The asset must be one the caller may see (another tenant's, or one
//     outside the caller's data scope, is not found).
//   - Every other asset is checked against the caller's data scope in the
//     database. An asset outside it is never returned and never walked
//     through: it is only counted on the node it hangs off
//     (HiddenNeighbors), like the related-assets groups do. Lineage hops
//     outside the scope stay hidden nodes with no identity.
//   - A group of more than NeighborhoodClusterAt siblings (one anchor, one
//     relationship type, one direction) comes back as one cluster with its
//     count by asset type, and its members are not walked.
//   - At most q.MaxNodes assets: what does not fit is counted in clusters and
//     the answer is marked truncated.
//   - Each asset is visited once (cycles end the walk).
func (s *AssetRelationshipService) Neighborhood(
	ctx context.Context, tenantID, assetID string, in NeighborhoodInput,
) (*assetdom.Neighborhood, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	q, err := parseNeighborhoodInput(in)
	if err != nil {
		return nil, err
	}
	a, err := s.assetRepo.GetByID(ctx, tid, aid)
	if err != nil {
		return nil, err
	}
	if err := s.dataScope.AssertAsset(ctx, tid, aid); err != nil {
		return nil, err
	}
	scope, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}

	w := newNeighborhoodWalk(q, assetdom.NeighborhoodNode{
		ID: a.ID(), Name: a.Name(), Type: a.Type(), SubType: a.SubType(),
		Status: a.Status().String(), Criticality: a.Criticality().String(), Exposure: a.Exposure().String(),
	})
	if s.graph == nil {
		return w.result(assetdom.BuildLineage(nil, assetdom.LineageMaxDepth)), nil
	}

	rows, err := s.graph.Lineage(ctx, tid, aid, scope, assetdom.LineageMaxDepth)
	if err != nil {
		return nil, fmt.Errorf("read asset lineage: %w", err)
	}
	lineage := assetdom.BuildLineage(rows, assetdom.LineageMaxDepth)
	w.addLineage(lineage)

	for d := 0; d < q.Depth && len(w.frontier) > 0 && !w.truncated; d++ {
		hop, err := s.graph.NeighborhoodHop(ctx, tid, assetdom.NeighborhoodHopQuery{
			Frontier: w.frontier, Known: w.knownIDs(), Direction: q.Direction,
			Types: q.Types, Relations: q.Relations, Scope: scope, ClusterAt: assetdom.NeighborhoodClusterAt,
		})
		if err != nil {
			return nil, fmt.Errorf("read asset neighborhood: %w", err)
		}
		w.apply(hop, d+1)
	}
	return w.result(lineage), nil
}

// neighborhoodWalk accumulates the answer hop by hop.
type neighborhoodWalk struct {
	q        assetdom.NeighborhoodQuery
	order    []shared.ID
	nodes    map[shared.ID]*assetdom.NeighborhoodGraphNode
	reached  map[shared.ID]bool
	frontier []shared.ID
	edges    []assetdom.NeighborhoodGraphEdge
	edgeSeen map[string]bool
	clusters []assetdom.NeighborhoodCluster
	clusterI map[string]int
	// walked counts the nodes the walk reached (the node cap).
	walked int
	// truncated: the node cap stopped the walk.
	truncated bool
}

func newNeighborhoodWalk(q assetdom.NeighborhoodQuery, self assetdom.NeighborhoodNode) *neighborhoodWalk {
	w := &neighborhoodWalk{
		q:        q,
		nodes:    map[shared.ID]*assetdom.NeighborhoodGraphNode{},
		reached:  map[shared.ID]bool{self.ID: true},
		frontier: []shared.ID{self.ID},
		edgeSeen: map[string]bool{},
		clusterI: map[string]int{},
	}
	w.addNode(assetdom.NeighborhoodGraphNode{NeighborhoodNode: self, Distance: 0})
	return w
}

func (w *neighborhoodWalk) addNode(n assetdom.NeighborhoodGraphNode) {
	if _, ok := w.nodes[n.ID]; ok {
		return
	}
	cp := n
	w.nodes[n.ID] = &cp
	if n.Distance >= 0 {
		w.walked++
	}
	w.order = append(w.order, n.ID)
}

// addLineage adds the visible ancestors as nodes (Distance -1 until the walk
// reaches them), so the walk never clusters them away and draws the edges to
// them. They do not count toward the node cap: the lineage is always drawn.
func (w *neighborhoodWalk) addLineage(l assetdom.Lineage) {
	for _, n := range l.Nodes {
		if n.Depth == 0 || n.Hidden {
			continue
		}
		w.addNode(assetdom.NeighborhoodGraphNode{
			NeighborhoodNode: assetdom.NeighborhoodNode{ID: n.ID, Name: n.Name, Type: n.Type},
			Distance:         -1,
		})
	}
}

func (w *neighborhoodWalk) knownIDs() []shared.ID {
	return append([]shared.ID(nil), w.order...)
}

func (w *neighborhoodWalk) addEdge(e assetdom.NeighborhoodEdge) {
	src, tgt := e.Anchor, e.Other.ID
	if e.Direction == assetdom.RelationshipDirectionIncoming {
		src, tgt = tgt, src
	}
	key := src.String() + "|" + tgt.String() + "|" + string(e.Type)
	if w.edgeSeen[key] {
		return
	}
	w.edgeSeen[key] = true
	w.edges = append(w.edges, assetdom.NeighborhoodGraphEdge{Source: src, Target: tgt, Type: e.Type})
}

func (w *neighborhoodWalk) addToCluster(anchor shared.ID, typ assetdom.RelationshipType, dir string, byType map[assetdom.AssetType]int) {
	key := anchor.String() + "|" + string(typ) + "|" + dir
	i, ok := w.clusterI[key]
	if !ok {
		i = len(w.clusters)
		w.clusterI[key] = i
		w.clusters = append(w.clusters, assetdom.NeighborhoodCluster{
			Anchor: anchor, Type: typ, Direction: dir, ByType: map[assetdom.AssetType]int{},
		})
	}
	for t, n := range byType {
		w.clusters[i].ByType[t] += n
	}
}

// apply merges one hop read at distance d.
func (w *neighborhoodWalk) apply(hop *assetdom.NeighborhoodHop, d int) {
	for _, id := range w.frontier {
		n := w.nodes[id]
		n.Expanded = true
		n.HiddenNeighbors = hop.HiddenByAnchor[id]
	}
	var next []shared.ID
	for _, e := range hop.Edges {
		id := e.Other.ID
		if _, ok := w.nodes[id]; !ok {
			if w.walked >= w.q.MaxNodes {
				// Over the cap: counted, not drawn, and the walk ends here.
				w.truncated = true
				w.addToCluster(e.Anchor, e.Type, e.Direction, map[assetdom.AssetType]int{e.Other.Type: 1})
				continue
			}
			w.addNode(assetdom.NeighborhoodGraphNode{NeighborhoodNode: e.Other, Distance: d})
		} else if n := w.nodes[id]; n.Distance < 0 {
			// A lineage ancestor the walk reached: it now has a distance and
			// the attributes the lineage does not carry.
			n.NeighborhoodNode = e.Other
			n.Distance = d
			w.walked++
		}
		w.addEdge(e)
		if !w.reached[id] {
			w.reached[id] = true
			next = append(next, id)
		}
	}
	for _, c := range hop.Clusters {
		w.addToCluster(c.Anchor, c.Type, c.Direction, c.ByType)
	}
	w.frontier = next
}

func (w *neighborhoodWalk) result(lineage assetdom.Lineage) *assetdom.Neighborhood {
	out := &assetdom.Neighborhood{
		Query: w.q, Edges: w.edges, Clusters: w.clusters, Lineage: lineage, Truncated: w.truncated,
		Nodes: make([]assetdom.NeighborhoodGraphNode, 0, len(w.order)),
	}
	if out.Edges == nil {
		out.Edges = []assetdom.NeighborhoodGraphEdge{}
	}
	if out.Clusters == nil {
		out.Clusters = []assetdom.NeighborhoodCluster{}
	}
	for _, id := range w.order {
		n := *w.nodes[id]
		out.HiddenCount += n.HiddenNeighbors
		out.Nodes = append(out.Nodes, n)
	}
	return out
}
