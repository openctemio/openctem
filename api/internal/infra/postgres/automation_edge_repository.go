package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AutomationEdgeRepository implements automation.EdgeRepository using PostgreSQL.
type AutomationEdgeRepository struct {
	db *DB
}

// NewAutomationEdgeRepository creates a new AutomationEdgeRepository.
func NewAutomationEdgeRepository(db *DB) *AutomationEdgeRepository {
	return &AutomationEdgeRepository{db: db}
}

// Create creates a new workflow edge.
func (r *AutomationEdgeRepository) Create(ctx context.Context, e *automation.Edge) error {
	query := `
		INSERT INTO automation_edges (
			id, automation_id, source_node_key, target_node_key,
			source_handle, label, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(ctx, query,
		e.ID.String(),
		e.WorkflowID.String(),
		e.SourceNodeKey,
		e.TargetNodeKey,
		nullString(e.SourceHandle),
		nullString(e.Label),
		e.CreatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "edge already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create workflow edge: %w", err)
	}

	return nil
}

// CreateBatch creates multiple workflow edges.
func (r *AutomationEdgeRepository) CreateBatch(ctx context.Context, edges []*automation.Edge) error {
	if len(edges) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO automation_edges (
			id, automation_id, source_node_key, target_node_key,
			source_handle, label, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, e := range edges {
		_, err = stmt.ExecContext(ctx,
			e.ID.String(),
			e.WorkflowID.String(),
			e.SourceNodeKey,
			e.TargetNodeKey,
			nullString(e.SourceHandle),
			nullString(e.Label),
			e.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert workflow edge: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByID retrieves an edge by ID.
func (r *AutomationEdgeRepository) GetByID(ctx context.Context, id shared.ID) (*automation.Edge, error) {
	query := `
		SELECT id, automation_id, source_node_key, target_node_key,
		       source_handle, label, created_at
		FROM automation_edges
		WHERE id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query workflow edge: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanEdge(rows)
}

// GetByWorkflowID retrieves all edges for a workflow.
func (r *AutomationEdgeRepository) GetByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*automation.Edge, error) {
	query := `
		SELECT id, automation_id, source_node_key, target_node_key,
		       source_handle, label, created_at
		FROM automation_edges
		WHERE automation_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, workflowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query workflow edges: %w", err)
	}
	defer rows.Close()

	var edges []*automation.Edge
	for rows.Next() {
		edge, err := scanEdge(rows)
		if err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}

	return edges, nil
}

// Delete deletes a workflow edge.
func (r *AutomationEdgeRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM automation_edges WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete workflow edge: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteByWorkflowID deletes all edges for a workflow.
func (r *AutomationEdgeRepository) DeleteByWorkflowID(ctx context.Context, workflowID shared.ID) error {
	query := "DELETE FROM automation_edges WHERE automation_id = $1"
	_, err := r.db.ExecContext(ctx, query, workflowID.String())
	if err != nil {
		return fmt.Errorf("failed to delete workflow edges: %w", err)
	}
	return nil
}
