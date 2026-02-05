package workflow

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Edge represents a connection between two nodes in a workflow.
type Edge struct {
	ID         shared.ID
	WorkflowID shared.ID

	// Connection definition
	SourceNodeKey string
	TargetNodeKey string

	// For condition nodes, specify which output handle
	// "yes" or "no" for condition nodes, empty for other types
	SourceHandle string

	// Optional label for display
	Label string

	// Timestamps
	CreatedAt time.Time
}

// NewEdge creates a new workflow edge.
func NewEdge(
	workflowID shared.ID,
	sourceNodeKey string,
	targetNodeKey string,
) (*Edge, error) {
	if sourceNodeKey == "" {
		return nil, shared.NewDomainError("VALIDATION", "source_node_key is required", shared.ErrValidation)
	}
	if targetNodeKey == "" {
		return nil, shared.NewDomainError("VALIDATION", "target_node_key is required", shared.ErrValidation)
	}
	if sourceNodeKey == targetNodeKey {
		return nil, shared.NewDomainError("VALIDATION", "cannot connect node to itself", shared.ErrValidation)
	}

	return &Edge{
		ID:            shared.NewID(),
		WorkflowID:    workflowID,
		SourceNodeKey: sourceNodeKey,
		TargetNodeKey: targetNodeKey,
		CreatedAt:     time.Now(),
	}, nil
}

// SetSourceHandle sets the source handle (for condition nodes).
func (e *Edge) SetSourceHandle(handle string) {
	e.SourceHandle = handle
}

// SetLabel sets the display label.
func (e *Edge) SetLabel(label string) {
	e.Label = label
}

// Clone creates a copy of the edge with a new ID.
func (e *Edge) Clone() *Edge {
	return &Edge{
		ID:            shared.NewID(),
		WorkflowID:    e.WorkflowID,
		SourceNodeKey: e.SourceNodeKey,
		TargetNodeKey: e.TargetNodeKey,
		SourceHandle:  e.SourceHandle,
		Label:         e.Label,
		CreatedAt:     time.Now(),
	}
}
