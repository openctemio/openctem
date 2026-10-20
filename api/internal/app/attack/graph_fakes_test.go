package attack

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeGraphNodes serves a fixed node list to the graph readers.
type fakeGraphNodes struct {
	asset.Repository // unimplemented methods panic: graph reads must not call them
	nodes            []asset.AssetNode
	calls            int
}

func (f *fakeGraphNodes) ListAllNodes(context.Context, shared.ID) ([]asset.AssetNode, error) {
	f.calls++
	out := make([]asset.AssetNode, len(f.nodes))
	copy(out, f.nodes)
	return out, nil
}

// fakeGraphEdges serves a fixed edge list to the graph readers.
type fakeGraphEdges struct {
	asset.RelationshipRepository
	edges []asset.RelationshipEdge
}

func (f *fakeGraphEdges) ListAllEdges(context.Context, shared.ID) ([]asset.RelationshipEdge, error) {
	return f.edges, nil
}
