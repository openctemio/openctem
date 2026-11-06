package attack

// Attack paths to one asset: every short route from an internet-facing entry
// point to the asset, the finding that enables each step, the product of the
// step weights as the path likelihood, and the choke points (the assets whose
// findings, once fixed, cut the most of those routes).
// Design: api/docs/architecture/attack-paths.md.

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// PathFindingReader returns, per asset, the open finding count, the KEV count
// and the lead finding of each asset in assetIDs. Tenant-scoped. Implemented
// by the finding repository.
type PathFindingReader interface {
	AttackPathFindings(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]vulnerability.AssetPathFindings, error)
}

// SetPathFindingReader wires the finding reader of the path detail.
func (s *SurfaceService) SetPathFindingReader(r PathFindingReader) {
	s.pathFindings = r
}

const (
	// pathMaxEdges bounds the length of an enumerated route (edges).
	pathMaxEdges = 8
	// pathSlack admits routes up to this many edges longer than the shortest.
	pathSlack = 2
	// pathShowCap is the number of routes a response returns (shortest and
	// most likely first).
	pathShowCap = 12
	// pathCollectCap and pathStepBudget bound the enumeration on dense graphs;
	// hitting either sets Capped.
	pathCollectCap = 200
	pathStepBudget = 50000
)

// Roles of a node on a route.
const (
	PathRoleEntry  = "entry"
	PathRoleHop    = "hop"
	PathRoleTarget = "target"
)

// Bases of a step weight.
const (
	PathBasisEPSS     = "epss"
	PathBasisKEV      = "kev"
	PathBasisSeverity = "severity"
	// PathBasisAssumed is a step with no open finding: the relationship alone
	// is taken to allow it, at weight 1.
	PathBasisAssumed = "assumed"
)

// ErrPathTargetNotFound is returned when the asset is not in the tenant's
// graph, or not in the caller's data scope (both answer 404).
var ErrPathTargetNotFound = fmt.Errorf("%w: asset not found", shared.ErrNotFound)

// PathFinding is the lead finding of a step.
type PathFinding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	CVEID    string   `json:"cve_id,omitempty"`
	Severity string   `json:"severity"`
	EPSS     *float64 `json:"epss,omitempty"`
	KEV      bool     `json:"kev"`
}

// PathNode is one asset on the routes. Key identifies it inside this response
// only. A node outside the caller's data scope has Hidden set and carries
// nothing else but its key and role.
type PathNode struct {
	Key          string       `json:"key"`
	Hidden       bool         `json:"hidden,omitempty"`
	Role         string       `json:"role"`
	AssetID      string       `json:"asset_id,omitempty"`
	Name         string       `json:"name,omitempty"`
	AssetType    string       `json:"asset_type,omitempty"`
	Exposure     string       `json:"exposure,omitempty"`
	Criticality  string       `json:"criticality,omitempty"`
	IsCrownJewel bool         `json:"is_crown_jewel,omitempty"`
	OpenFindings int          `json:"open_findings"`
	KEVFindings  int          `json:"kev_findings"`
	Weight       *float64     `json:"weight,omitempty"`
	Basis        string       `json:"basis,omitempty"`
	Finding      *PathFinding `json:"finding,omitempty"`
}

// PathEdge is one relationship used by at least one route. From is "" for the
// step from the internet onto an entry point. Paths lists the indexes of the
// routes that use the edge.
type PathEdge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship,omitempty"`
	Paths        []int  `json:"paths"`
}

// AttackPath is one route, entry point first, target last (node keys).
// Likelihood is the product of the node weights; nil when a step is hidden.
type AttackPath struct {
	Nodes      []string `json:"nodes"`
	Length     int      `json:"length"`
	Likelihood *float64 `json:"likelihood,omitempty"`
	KEVSteps   int      `json:"kev_steps"`
}

// ChokePoint is a node whose findings, once fixed, cut Breaks of the routes.
type ChokePoint struct {
	Node   string `json:"node"`
	Breaks int    `json:"breaks"`
}

// PathDetail is the response of the attack paths to one asset.
type PathDetail struct {
	Target      string       `json:"target"`
	Nodes       []PathNode   `json:"nodes"`
	Edges       []PathEdge   `json:"edges"`
	Paths       []AttackPath `json:"paths"`
	ChokePoints []ChokePoint `json:"choke_points"`
	// TotalPaths is the number of routes found; Paths holds at most
	// pathShowCap of them. Capped is set when the enumeration stopped early.
	TotalPaths int       `json:"total_paths"`
	Capped     bool      `json:"capped"`
	ComputedAt time.Time `json:"computed_at"`
}

// PathDetailForCaller returns the attack paths to targetID, narrowed to the
// caller's data scope: the target must be in scope (else ErrPathTargetNotFound);
// steps outside the scope are hidden and the likelihood of a route through one
// is withheld. The routes themselves are those of the whole tenant graph.
func (s *SurfaceService) PathDetailForCaller(ctx context.Context, tenantID shared.ID, targetID string) (*PathDetail, error) {
	scope, err := s.dataScope.ResolveStrict(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	tid, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, ErrPathTargetNotFound
	}
	if scope != nil {
		keep, ferr := s.dataScope.Filter(ctx, scope, []shared.ID{tid})
		if ferr != nil {
			return nil, ferr
		}
		if !keep(tid) {
			return nil, ErrPathTargetNotFound
		}
	}

	nodes, err := s.assetRepo.ListAllNodes(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load nodes: %w", err)
	}
	edges, err := s.relRepo.ListAllEdges(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load edges: %w", err)
	}
	routes, total, capped, ok := enumeratePaths(nodes, edges, tid.String())
	if !ok {
		return nil, ErrPathTargetNotFound
	}

	// Every asset on a route, the target included even with no route.
	ids := []string{tid.String()}
	seen := map[string]bool{tid.String(): true}
	for _, r := range routes {
		for _, id := range r.nodes {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	keep := func(shared.ID) bool { return true }
	if scope != nil {
		sids := make([]shared.ID, 0, len(ids))
		for _, id := range ids {
			if sid, perr := shared.IDFromString(id); perr == nil {
				sids = append(sids, sid)
			}
		}
		if keep, err = s.dataScope.Filter(ctx, scope, sids); err != nil {
			return nil, err
		}
	}
	visible := make(map[string]bool, len(ids))
	visibleIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		if sid, perr := shared.IDFromString(id); perr == nil && keep(sid) {
			visible[id] = true
			visibleIDs = append(visibleIDs, id)
		}
	}
	// Findings are read for visible assets only: a hidden step's findings
	// never leave the database.
	var findings map[string]vulnerability.AssetPathFindings
	if s.pathFindings != nil && len(visibleIDs) > 0 {
		if findings, err = s.pathFindings.AttackPathFindings(ctx, tenantID, visibleIDs); err != nil {
			return nil, fmt.Errorf("load path findings: %w", err)
		}
	}
	nodeByID := make(map[string]*asset.AssetNode, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].ID] = &nodes[i]
	}
	d := assemblePathDetail(tid.String(), routes, nodeByID, edges, visible, findings)
	d.TotalPaths, d.Capped = total, capped
	d.ComputedAt = time.Now().UTC()
	return d, nil
}

// route is one enumerated route (asset ids, entry first).
type route struct {
	nodes []string
}

// enumeratePaths returns the shortest routes from public entry points to
// target over attack-path relationships: simple routes whose length is at most
// the shortest plus pathSlack (and pathMaxEdges), that pass through no other
// public asset (a route through a second entry point is the shorter route
// from that entry). Sorted by length, then by ids. ok is false when target is
// not a live asset.
func enumeratePaths(nodes []asset.AssetNode, edges []asset.RelationshipEdge, target string) (routes []route, total int, capped, ok bool) {
	nodeByID := make(map[string]*asset.AssetNode, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].ID] = &nodes[i]
	}
	if nodeByID[target] == nil {
		return nil, 0, false, false
	}
	public := func(id string) bool { return nodeByID[id].Exposure == string(asset.ExposurePublic) }
	adj, radj := attackAdjacency(nodeByID, edges)
	dist := distancesTo(target, radj)
	entries, shortest := entriesByDistance(dist, public)
	if shortest < 0 {
		return nil, 0, false, true
	}
	limit := shortest + pathSlack
	if limit > pathMaxEdges {
		limit = pathMaxEdges
	}

	steps := 0
	onPath := map[string]bool{}
	var path []string
	var walk func(cur string) bool
	walk = func(cur string) bool {
		steps++
		if steps > pathStepBudget || len(routes) >= pathCollectCap {
			capped = true
			return false
		}
		if cur == target {
			routes = append(routes, route{nodes: append([]string(nil), path...)})
			return true
		}
		for _, nb := range adj[cur] {
			d, reach := dist[nb]
			if !reach || onPath[nb] || len(path)+d > limit {
				continue
			}
			if nb != target && public(nb) {
				continue
			}
			onPath[nb] = true
			path = append(path, nb)
			cont := walk(nb)
			path = path[:len(path)-1]
			delete(onPath, nb)
			if !cont {
				return false
			}
		}
		return true
	}
	for _, ep := range entries {
		if dist[ep] > limit {
			continue
		}
		onPath[ep] = true
		path = append(path[:0], ep)
		cont := walk(ep)
		delete(onPath, ep)
		if !cont {
			break
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return len(routes[i].nodes) < len(routes[j].nodes) })
	return routes, len(routes), capped, true
}

// attackAdjacency returns the forward and reverse adjacency over attack-path
// relationships between live assets, without duplicates or self loops; the
// forward lists are sorted so the enumeration is deterministic.
func attackAdjacency(nodeByID map[string]*asset.AssetNode, edges []asset.RelationshipEdge) (adj, radj map[string][]string) {
	adj = make(map[string][]string, len(nodeByID))
	radj = make(map[string][]string, len(nodeByID))
	dup := make(map[[2]string]bool, len(edges))
	for _, e := range edges {
		if !attackPathRelationshipTypes[e.Type] || nodeByID[e.SourceAssetID] == nil || nodeByID[e.TargetAssetID] == nil {
			continue
		}
		k := [2]string{e.SourceAssetID, e.TargetAssetID}
		if dup[k] || k[0] == k[1] {
			continue
		}
		dup[k] = true
		adj[k[0]] = append(adj[k[0]], k[1])
		radj[k[1]] = append(radj[k[1]], k[0])
	}
	for _, l := range adj {
		sort.Strings(l)
	}
	return adj, radj
}

// distancesTo returns the distance of every node to target (reverse BFS).
func distancesTo(target string, radj map[string][]string) map[string]int {
	dist := map[string]int{target: 0}
	queue := []string{target}
	for h := 0; h < len(queue); h++ {
		cur := queue[h]
		for _, p := range radj[cur] {
			if _, done := dist[p]; !done {
				dist[p] = dist[cur] + 1
				queue = append(queue, p)
			}
		}
	}
	return dist
}

// entriesByDistance returns the public nodes that reach the target, nearest
// first, and the shortest distance (-1 when none reaches it).
func entriesByDistance(dist map[string]int, public func(string) bool) ([]string, int) {
	shortest := -1
	var entries []string
	for id, d := range dist {
		if public(id) {
			entries = append(entries, id)
			if shortest < 0 || d < shortest {
				shortest = d
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if dist[entries[i]] != dist[entries[j]] {
			return dist[entries[i]] < dist[entries[j]]
		}
		return entries[i] < entries[j]
	})
	return entries, shortest
}

// stepWeight returns the likelihood of the step onto an asset whose open
// findings are f, and the basis that set it.
func stepWeight(f vulnerability.AssetPathFindings) (float64, string) {
	l := f.Lead
	if l == nil {
		return 1, PathBasisAssumed
	}
	w, basis := vulnerability.PathSeverityWeight(l.Severity), PathBasisSeverity
	if l.KEV && vulnerability.PathWeightKEV > w {
		w, basis = vulnerability.PathWeightKEV, PathBasisKEV
	}
	if l.EPSS != nil && *l.EPSS > w {
		w, basis = *l.EPSS, PathBasisEPSS
	}
	return w, basis
}

// assemblePathDetail turns routes into the response: nodes keyed in order of
// first appearance, edges with the routes that use them, routes ranked by
// length then likelihood (top pathShowCap), and choke points over the shown
// routes. visible holds the asset ids the caller may see.
func assemblePathDetail(
	target string,
	routes []route,
	nodeByID map[string]*asset.AssetNode,
	edges []asset.RelationshipEdge,
	visible map[string]bool,
	findings map[string]vulnerability.AssetPathFindings,
) *PathDetail {
	weight := func(id string) (float64, string) { return stepWeight(findings[id]) }

	// Rank: shorter, then more likely. A hidden step's findings are never
	// read, so it counts as 1 here and the route's likelihood is withheld.
	type scored struct {
		r route
		p float64
	}
	sc := make([]scored, len(routes))
	for i, r := range routes {
		p := 1.0
		for _, id := range r.nodes {
			if visible[id] {
				w, _ := weight(id)
				p *= w
			}
		}
		sc[i] = scored{r, p}
	}
	sort.SliceStable(sc, func(i, j int) bool {
		if len(sc[i].r.nodes) != len(sc[j].r.nodes) {
			return len(sc[i].r.nodes) < len(sc[j].r.nodes)
		}
		return sc[i].p > sc[j].p
	})
	if len(sc) > pathShowCap {
		sc = sc[:pathShowCap]
	}

	keys := map[string]string{}
	d := &PathDetail{Nodes: []PathNode{}, Edges: []PathEdge{}, Paths: []AttackPath{}, ChokePoints: []ChokePoint{}}
	key := func(id string, role string) string {
		if k, ok := keys[id]; ok {
			return k
		}
		k := fmt.Sprintf("n%d", len(keys))
		keys[id] = k
		d.Nodes = append(d.Nodes, pathNode(k, role, visible[id], nodeByID[id], findings[id]))
		return k
	}
	d.Target = key(target, PathRoleTarget)

	relType := map[[2]string]string{}
	for _, e := range edges {
		k := [2]string{e.SourceAssetID, e.TargetAssetID}
		if _, ok := relType[k]; !ok && attackPathRelationshipTypes[e.Type] {
			relType[k] = string(e.Type)
		}
	}
	edgeIdx := map[[2]string]int{}
	addEdge := func(from, to string, fromKey, toKey string, path int) {
		k := [2]string{from, to}
		if i, ok := edgeIdx[k]; ok {
			d.Edges[i].Paths = append(d.Edges[i].Paths, path)
			return
		}
		e := PathEdge{From: fromKey, To: toKey, Paths: []int{path}}
		// The relationship type is shown only when both ends are visible.
		if from != "" && visible[from] && visible[to] {
			e.Relationship = relType[k]
		}
		edgeIdx[k] = len(d.Edges)
		d.Edges = append(d.Edges, e)
	}

	breaks := map[string]int{}
	for pi, s := range sc {
		ap := AttackPath{Nodes: make([]string, len(s.r.nodes)), Length: len(s.r.nodes) - 1}
		hidden := false
		prev, prevKey := "", ""
		for i, id := range s.r.nodes {
			role := PathRoleHop
			switch {
			case id == target:
				role = PathRoleTarget
			case i == 0:
				role = PathRoleEntry
			}
			k := key(id, role)
			ap.Nodes[i] = k
			addEdge(prev, id, prevKey, k, pi)
			prev, prevKey = id, k
			if !visible[id] {
				hidden = true
				continue
			}
			if f := findings[id]; f.Lead != nil {
				if f.Lead.KEV {
					ap.KEVSteps++
				}
				if id != target {
					breaks[id]++
				}
			}
		}
		if !hidden {
			p := s.p
			ap.Likelihood = &p
		}
		d.Paths = append(d.Paths, ap)
	}

	d.ChokePoints = rankChokePoints(breaks, keys, func(id string) float64 {
		w, _ := weight(id)
		return w
	})
	return d
}

// pathNode is the response node of one asset: everything for a visible asset,
// only the key and role for a hidden one.
func pathNode(key, role string, visible bool, a *asset.AssetNode, f vulnerability.AssetPathFindings) PathNode {
	n := PathNode{Key: key, Role: role}
	if !visible {
		n.Hidden = true
		return n
	}
	w, basis := stepWeight(f)
	n.AssetID, n.Name, n.AssetType = a.ID, a.Name, a.AssetType
	n.Exposure, n.Criticality, n.IsCrownJewel = a.Exposure, a.Criticality, a.IsCrownJewel
	n.OpenFindings, n.KEVFindings = f.OpenCount, f.KEVCount
	n.Weight, n.Basis = &w, basis
	if l := f.Lead; l != nil {
		n.Finding = &PathFinding{ID: l.ID, Title: l.Title, CVEID: l.CVEID, Severity: l.Severity, EPSS: l.EPSS, KEV: l.KEV}
	}
	return n
}

// rankChokePoints orders the assets by the routes they cut, then by step
// weight, then by key. breaks holds only visible assets with a lead finding.
func rankChokePoints(breaks map[string]int, keys map[string]string, weight func(string) float64) []ChokePoint {
	out := make([]ChokePoint, 0, len(breaks))
	wByKey := make(map[string]float64, len(breaks))
	for id, n := range breaks {
		out = append(out, ChokePoint{Node: keys[id], Breaks: n})
		wByKey[keys[id]] = weight(id)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Breaks != b.Breaks {
			return a.Breaks > b.Breaks
		}
		if wByKey[a.Node] != wByKey[b.Node] {
			return wByKey[a.Node] > wByKey[b.Node]
		}
		return a.Node < b.Node
	})
	return out
}
