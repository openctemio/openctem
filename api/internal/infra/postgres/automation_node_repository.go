package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AutomationNodeRepository implements automation.NodeRepository using PostgreSQL.
type AutomationNodeRepository struct {
	db *DB
}

// NewAutomationNodeRepository creates a new AutomationNodeRepository.
func NewAutomationNodeRepository(db *DB) *AutomationNodeRepository {
	return &AutomationNodeRepository{db: db}
}

// Create creates a new workflow node.
func (r *AutomationNodeRepository) Create(ctx context.Context, n *automation.Node) error {
	config, err := json.Marshal(n.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal node config: %w", err)
	}

	query := `
		INSERT INTO automation_nodes (
			id, automation_id, node_key, node_type, name, description,
			ui_position_x, ui_position_y, config, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = r.db.ExecContext(ctx, query,
		n.ID.String(),
		n.WorkflowID.String(),
		n.NodeKey,
		string(n.NodeType),
		n.Name,
		n.Description,
		n.UIPosition.X,
		n.UIPosition.Y,
		config,
		n.CreatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "node with this key already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create workflow node: %w", err)
	}

	return nil
}

// CreateBatch creates multiple workflow nodes.
func (r *AutomationNodeRepository) CreateBatch(ctx context.Context, nodes []*automation.Node) error {
	if len(nodes) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO automation_nodes (
			id, automation_id, node_key, node_type, name, description,
			ui_position_x, ui_position_y, config, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, n := range nodes {
		config, err := json.Marshal(n.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal node config: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			n.ID.String(),
			n.WorkflowID.String(),
			n.NodeKey,
			string(n.NodeType),
			n.Name,
			n.Description,
			n.UIPosition.X,
			n.UIPosition.Y,
			config,
			n.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert workflow node: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByID retrieves a node by ID.
func (r *AutomationNodeRepository) GetByID(ctx context.Context, id shared.ID) (*automation.Node, error) {
	query := `
		SELECT id, automation_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM automation_nodes
		WHERE id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query workflow node: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanNode(rows)
}

// GetByWorkflowID retrieves all nodes for a workflow.
func (r *AutomationNodeRepository) GetByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*automation.Node, error) {
	query := `
		SELECT id, automation_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM automation_nodes
		WHERE automation_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, workflowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query workflow nodes: %w", err)
	}
	defer rows.Close()

	var nodes []*automation.Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// GetByKey retrieves a node by workflow ID and node key.
func (r *AutomationNodeRepository) GetByKey(ctx context.Context, workflowID shared.ID, nodeKey string) (*automation.Node, error) {
	query := `
		SELECT id, automation_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM automation_nodes
		WHERE automation_id = $1 AND node_key = $2
	`

	rows, err := r.db.QueryContext(ctx, query, workflowID.String(), nodeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query workflow node by key: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanNode(rows)
}

// Update updates a workflow node.
func (r *AutomationNodeRepository) Update(ctx context.Context, n *automation.Node) error {
	config, err := json.Marshal(n.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal node config: %w", err)
	}

	query := `
		UPDATE automation_nodes
		SET node_key = $2, node_type = $3, name = $4, description = $5,
		    ui_position_x = $6, ui_position_y = $7, config = $8
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		n.ID.String(),
		n.NodeKey,
		string(n.NodeType),
		n.Name,
		n.Description,
		n.UIPosition.X,
		n.UIPosition.Y,
		config,
	)

	if err != nil {
		return fmt.Errorf("failed to update workflow node: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a workflow node.
func (r *AutomationNodeRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM automation_nodes WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete workflow node: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteByWorkflowID deletes all nodes for a workflow.
func (r *AutomationNodeRepository) DeleteByWorkflowID(ctx context.Context, workflowID shared.ID) error {
	query := "DELETE FROM automation_nodes WHERE automation_id = $1"
	_, err := r.db.ExecContext(ctx, query, workflowID.String())
	if err != nil {
		return fmt.Errorf("failed to delete workflow nodes: %w", err)
	}
	return nil
}
