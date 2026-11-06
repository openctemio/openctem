package asset

// Discovery lineage (docs/architecture/easm.md, Discovery lineage): the chain
// of parent assets through which an asset was found, from the asset up to
// its root (a subdomain's domain, a port's host, a certificate's endpoint).

import (
	"context"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LineageMaxDepth caps how many ancestors a lineage walks. Real hierarchies
// are shallow (certificate, endpoint, address, subdomain, domain); the cap
// bounds the recursive query whatever the stored edges look like.
const LineageMaxDepth = 5

// Lineage edge kinds: how a parent leads to the asset below it.
const (
	// LineageViaParent is the asset's own parent_id.
	LineageViaParent = "parent"
	// The other kinds are relationship types (parent is the source).
	LineageViaContains          = string(RelTypeContains)
	LineageViaExposes           = string(RelTypeExposes)
	LineageViaServesCertificate = string(RelTypeServesCertificate)
	LineageViaResolvesTo        = string(RelTypeResolvesTo)
)

// LineageNode is one asset of a lineage. Depth 0 is the asset itself, depth
// 1 its parent, and so on. A node outside the caller's data scope keeps only
// its depth and edge: Hidden is set and every identifying field is empty.
type LineageNode struct {
	Depth  int
	Hidden bool
	// Via is how this node leads to the node one depth below it (empty for
	// depth 0).
	Via             string
	ID              shared.ID
	Name            string
	Type            AssetType
	DiscoverySource string
	DiscoveryTool   string
	DiscoveredAt    *time.Time
	FirstSeen       *time.Time
}

// Lineage is an asset's discovery chain, asset first (depth 0).
type Lineage struct {
	Nodes []LineageNode
	// Truncated is set when the chain goes on above the last node returned.
	Truncated bool
}

// LineageReader reads an asset's ancestor chain. Every hop is bound to the
// tenant and never revisits an asset (cycle guard). With a non-nil scope a
// node outside it comes back with Hidden set and no identifying field.
// It returns at most maxDepth+1 ancestors so the caller can tell a
// truncated chain.
type LineageReader interface {
	Lineage(ctx context.Context, tenantID, assetID shared.ID, scope *shared.DataScope, maxDepth int) ([]LineageNode, error)
}

// BuildLineage orders the rows by depth, drops anything past maxDepth (and
// marks the lineage truncated when there was), and strips every identifying
// field of a hidden node again, so a reader that forgot to cannot leak it.
func BuildLineage(rows []LineageNode, maxDepth int) Lineage {
	nodes := make([]LineageNode, 0, len(rows))
	truncated := false
	for _, n := range rows {
		if n.Depth > maxDepth {
			truncated = true
			continue
		}
		if n.Hidden {
			n = LineageNode{Depth: n.Depth, Hidden: true, Via: n.Via}
		}
		nodes = append(nodes, n)
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Depth < nodes[j].Depth })
	return Lineage{Nodes: nodes, Truncated: truncated}
}
