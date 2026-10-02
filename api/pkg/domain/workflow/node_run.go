package workflow

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// NodeRunStatus represents the status of a node execution.
type NodeRunStatus string

const (
	NodeRunStatusPending   NodeRunStatus = "pending"
	NodeRunStatusRunning   NodeRunStatus = "running"
	NodeRunStatusCompleted NodeRunStatus = "completed"
	NodeRunStatusFailed    NodeRunStatus = "failed"
	NodeRunStatusSkipped   NodeRunStatus = "skipped"
)

// IsValid checks if the node run status is valid.
func (s NodeRunStatus) IsValid() bool {
	switch s {
	case NodeRunStatusPending, NodeRunStatusRunning, NodeRunStatusCompleted, NodeRunStatusFailed, NodeRunStatusSkipped:
		return true
	}
	return false
}

// IsTerminal checks if the status is a terminal state.
func (s NodeRunStatus) IsTerminal() bool {
	return s == NodeRunStatusCompleted || s == NodeRunStatusFailed || s == NodeRunStatusSkipped
}

// NodeRun represents the execution of a single node in a workflow run.
type NodeRun struct {
	ID            shared.ID
	WorkflowRunID shared.ID
	NodeID        shared.ID
	NodeKey       string
	NodeType      NodeType

	// Status
	Status       NodeRunStatus
	ErrorMessage string
	ErrorCode    string

	// Input/Output
	Input  map[string]any
	Output map[string]any

	// For condition nodes, which branch was taken
	ConditionResult *bool

	// Timing
	StartedAt   *time.Time
	CompletedAt *time.Time

	// Audit
	CreatedAt time.Time
}

// NewNodeRun creates a new node run.
func NewNodeRun(
	workflowRunID shared.ID,
	nodeID shared.ID,
	nodeKey string,
	nodeType NodeType,
) (*NodeRun, error) {
	if workflowRunID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "workflow_run_id is required", shared.ErrValidation)
	}
	if nodeID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "node_id is required", shared.ErrValidation)
	}
	if nodeKey == "" {
		return nil, shared.NewDomainError("VALIDATION", "node_key is required", shared.ErrValidation)
	}

	return &NodeRun{
		ID:            shared.NewID(),
		WorkflowRunID: workflowRunID,
		NodeID:        nodeID,
		NodeKey:       nodeKey,
		NodeType:      nodeType,
		Status:        NodeRunStatusPending,
		Input:         make(map[string]any),
		Output:        make(map[string]any),
		CreatedAt:     time.Now(),
	}, nil
}

// Start marks the node run as started.
func (nr *NodeRun) Start() {
	now := time.Now()
	nr.Status = NodeRunStatusRunning
	nr.StartedAt = &now
}

// Complete marks the node run as completed.
func (nr *NodeRun) Complete(output map[string]any) {
	now := time.Now()
	nr.Status = NodeRunStatusCompleted
	nr.Output = output
	nr.CompletedAt = &now
}

// Fail marks the node run as failed.
func (nr *NodeRun) Fail(errorMessage, errorCode string) {
	now := time.Now()
	nr.Status = NodeRunStatusFailed
	nr.ErrorMessage = errorMessage
	nr.ErrorCode = errorCode
	nr.CompletedAt = &now
}

// Skip marks the node run as skipped.
func (nr *NodeRun) Skip(reason string) {
	now := time.Now()
	nr.Status = NodeRunStatusSkipped
	nr.ErrorMessage = reason
	nr.CompletedAt = &now
}

// SetInput sets the node input data.
func (nr *NodeRun) SetInput(input map[string]any) {
	nr.Input = input
}

// SetConditionResult sets the result of a condition evaluation.
func (nr *NodeRun) SetConditionResult(result bool) {
	nr.ConditionResult = &result
}

// Duration returns the node run duration.
func (nr *NodeRun) Duration() time.Duration {
	if nr.StartedAt == nil {
		return 0
	}
	if nr.CompletedAt != nil {
		return nr.CompletedAt.Sub(*nr.StartedAt)
	}
	return time.Since(*nr.StartedAt)
}
