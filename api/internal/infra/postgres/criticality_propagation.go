package postgres

import "github.com/openctemio/api/pkg/domain/asset"

// This file holds the pure, DB-free graph walks behind two criticality
// propagation features (both floor / only-raise, both cycle- and depth-guarded):
//
//   - resolveBUCriticality: business-unit criticality inherited up the parent_id
//     hierarchy (Feature 2).
//   - walkControlPlane: control-plane criticality propagated across bounded
//     multi-hop is_control_plane edges (Feature 1).
//
// They are separated from the repository so the traversal invariants (multi-hop,
// cycle termination, depth cap) are unit-testable without a database.

// resolveBUCriticality returns the effective criticality of business unit `id` —
// the MAX of its own criticality and every ancestor's along the parent_id chain —
// together with the name of the BU that supplied that MAX. Only ever raises: when
// no ancestor is more critical, the BU's own criticality and name are returned
// (identical to a flat hierarchy, so pre-hierarchy data is unchanged). Bounded by
// maxDepth ancestors and guarded by a visited set, so a malformed/cyclic parent
// chain terminates. Returns ("", "") when `id` is unknown.
func resolveBUCriticality(id string, nodes map[string]buNode, maxDepth int) (asset.Criticality, string) {
	node, ok := nodes[id]
	if !ok {
		return "", ""
	}
	bestCrit, bestName := node.crit, node.name
	visited := map[string]bool{id: true}
	cur := node.parentID
	for depth := 0; depth < maxDepth && cur != ""; depth++ {
		if visited[cur] {
			break // cycle guard
		}
		visited[cur] = true
		p, ok := nodes[cur]
		if !ok {
			break
		}
		if p.crit.Score() > bestCrit.Score() {
			bestCrit, bestName = p.crit, p.name
		}
		cur = p.parentID
	}
	return bestCrit, bestName
}

// walkControlPlane walks the control-plane subgraph backward from `origin` up to
// maxDepth hops and returns the MAX criticality (and one served asset's name)
// among every asset `origin` is transitively the control plane of. `edges` maps a
// control-plane asset id to the ids of the assets it directly serves (the sources
// of its inbound is_control_plane edges); `crit`/`names` carry each served
// asset's own criticality and name. Only raises (returns the zero Criticality when
// `origin` serves nothing). A visited set makes cycles terminate and the depth cap
// bounds a large/adversarial graph.
func walkControlPlane(
	origin string,
	edges map[string][]string,
	crit map[string]asset.Criticality,
	names map[string]string,
	maxDepth int,
) (asset.Criticality, string) {
	var bestCrit asset.Criticality
	var bestName string
	visited := map[string]bool{origin: true}
	frontier := []string{origin}
	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, node := range frontier {
			for _, served := range edges[node] {
				if visited[served] {
					continue // cycle guard / already counted
				}
				visited[served] = true
				next = append(next, served)
				if crit[served].Score() > bestCrit.Score() {
					bestCrit, bestName = crit[served], names[served]
				}
			}
		}
		frontier = next
	}
	return bestCrit, bestName
}
