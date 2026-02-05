// Package workflow defines the Workflow domain entities for automation orchestration.
// Unlike Pipelines (scan execution), Workflows handle general automation:
// notifications, ticket creation, assignments, escalations, and triggering pipelines.
package workflow

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Workflow represents an automation workflow definition.
type Workflow struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string

	// Status
	IsActive bool

	// Metadata
	Tags []string

	// Nodes and edges (loaded separately)
	Nodes []*Node
	Edges []*Edge

	// Execution statistics
	TotalRuns      int
	SuccessfulRuns int
	FailedRuns     int
	LastRunID      *shared.ID
	LastRunAt      *time.Time
	LastRunStatus  string

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewWorkflow creates a new workflow.
func NewWorkflow(tenantID shared.ID, name, description string) (*Workflow, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	now := time.Now()
	return &Workflow{
		ID:          shared.NewID(),
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		IsActive:    true,
		Tags:        []string{},
		Nodes:       []*Node{},
		Edges:       []*Edge{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// SetCreatedBy sets the user who created the workflow.
func (w *Workflow) SetCreatedBy(userID shared.ID) {
	w.CreatedBy = &userID
}

// Activate activates the workflow.
func (w *Workflow) Activate() {
	w.IsActive = true
	w.UpdatedAt = time.Now()
}

// Deactivate deactivates the workflow.
func (w *Workflow) Deactivate() {
	w.IsActive = false
	w.UpdatedAt = time.Now()
}

// AddNode adds a node to the workflow.
func (w *Workflow) AddNode(node *Node) {
	node.WorkflowID = w.ID
	w.Nodes = append(w.Nodes, node)
	w.UpdatedAt = time.Now()
}

// AddEdge adds an edge to the workflow.
func (w *Workflow) AddEdge(edge *Edge) {
	edge.WorkflowID = w.ID
	w.Edges = append(w.Edges, edge)
	w.UpdatedAt = time.Now()
}

// GetNodeByKey returns a node by its key.
func (w *Workflow) GetNodeByKey(key string) *Node {
	for _, n := range w.Nodes {
		if n.NodeKey == key {
			return n
		}
	}
	return nil
}

// GetTriggerNodes returns all trigger nodes.
func (w *Workflow) GetTriggerNodes() []*Node {
	var triggers []*Node
	for _, n := range w.Nodes {
		if n.NodeType == NodeTypeTrigger {
			triggers = append(triggers, n)
		}
	}
	return triggers
}

// GetDownstreamNodes returns nodes that depend on the given node.
func (w *Workflow) GetDownstreamNodes(nodeKey string) []*Node {
	var downstream []*Node
	for _, edge := range w.Edges {
		if edge.SourceNodeKey == nodeKey {
			if node := w.GetNodeByKey(edge.TargetNodeKey); node != nil {
				downstream = append(downstream, node)
			}
		}
	}
	return downstream
}

// ValidateGraph validates the workflow graph structure.
func (w *Workflow) ValidateGraph() error {
	nodeKeys := make(map[string]bool)

	// Check for unique node keys
	for _, node := range w.Nodes {
		if nodeKeys[node.NodeKey] {
			return shared.NewDomainError("VALIDATION", "duplicate node key: "+node.NodeKey, shared.ErrValidation)
		}
		nodeKeys[node.NodeKey] = true
	}

	// Validate edges reference existing nodes
	for _, edge := range w.Edges {
		if !nodeKeys[edge.SourceNodeKey] {
			return shared.NewDomainError("VALIDATION", "edge references unknown source node: "+edge.SourceNodeKey, shared.ErrValidation)
		}
		if !nodeKeys[edge.TargetNodeKey] {
			return shared.NewDomainError("VALIDATION", "edge references unknown target node: "+edge.TargetNodeKey, shared.ErrValidation)
		}
	}

	// Check for at least one trigger
	triggers := w.GetTriggerNodes()
	if len(triggers) == 0 {
		return shared.NewDomainError("VALIDATION", "workflow must have at least one trigger node", shared.ErrValidation)
	}

	return nil
}

// RecordRun records the result of a workflow run.
func (w *Workflow) RecordRun(runID shared.ID, status string) {
	w.LastRunID = &runID
	now := time.Now()
	w.LastRunAt = &now
	w.LastRunStatus = status
	w.TotalRuns++

	if status == "completed" || status == "success" {
		w.SuccessfulRuns++
	} else if status == "failed" || status == "error" {
		w.FailedRuns++
	}

	w.UpdatedAt = now
}

// SuccessRate returns the success rate as a percentage.
func (w *Workflow) SuccessRate() int {
	if w.TotalRuns == 0 {
		return 0
	}
	return int(float64(w.SuccessfulRuns) / float64(w.TotalRuns) * 100)
}

// Clone creates a copy of the workflow with a new ID.
func (w *Workflow) Clone(newName string) *Workflow {
	now := time.Now()
	clone := &Workflow{
		ID:          shared.NewID(),
		TenantID:    w.TenantID,
		Name:        newName,
		Description: w.Description,
		IsActive:    true,
		Tags:        make([]string, len(w.Tags)),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	copy(clone.Tags, w.Tags)

	// Clone nodes
	clone.Nodes = make([]*Node, len(w.Nodes))
	for i, node := range w.Nodes {
		clone.Nodes[i] = node.Clone()
		clone.Nodes[i].WorkflowID = clone.ID
	}

	// Clone edges
	clone.Edges = make([]*Edge, len(w.Edges))
	for i, edge := range w.Edges {
		clone.Edges[i] = edge.Clone()
		clone.Edges[i].WorkflowID = clone.ID
	}

	return clone
}
