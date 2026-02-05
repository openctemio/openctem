package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/pagination"
)

// WorkflowRepository implements workflow.WorkflowRepository using PostgreSQL.
type WorkflowRepository struct {
	db *DB
}

// NewWorkflowRepository creates a new WorkflowRepository.
func NewWorkflowRepository(db *DB) *WorkflowRepository {
	return &WorkflowRepository{db: db}
}

// Create persists a new workflow.
func (r *WorkflowRepository) Create(ctx context.Context, w *workflow.Workflow) error {
	query := `
		INSERT INTO workflows (
			id, tenant_id, name, description, is_active, tags,
			total_runs, successful_runs, failed_runs,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.ExecContext(ctx, query,
		w.ID.String(),
		w.TenantID.String(),
		w.Name,
		w.Description,
		w.IsActive,
		pq.Array(w.Tags),
		w.TotalRuns,
		w.SuccessfulRuns,
		w.FailedRuns,
		nullID(w.CreatedBy),
		w.CreatedAt,
		w.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "workflow already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create workflow: %w", err)
	}

	return nil
}

// GetByID retrieves a workflow by its ID.
func (r *WorkflowRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.Workflow, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanWorkflow(row)
}

// GetByTenantAndID retrieves a workflow by tenant and ID.
func (r *WorkflowRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Workflow, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanWorkflow(row)
}

// GetByName retrieves a workflow by name.
func (r *WorkflowRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*workflow.Workflow, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND name = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanWorkflow(row)
}

// List lists workflows with filters and pagination.
func (r *WorkflowRepository) List(ctx context.Context, filter workflow.WorkflowFilter, page pagination.Pagination) (pagination.Result[*workflow.Workflow], error) {
	var result pagination.Result[*workflow.Workflow]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM workflows"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count workflows: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list workflows: %w", err)
	}
	defer rows.Close()

	var workflows []*workflow.Workflow
	for rows.Next() {
		w, err := r.scanWorkflowFromRows(rows)
		if err != nil {
			return result, err
		}
		workflows = append(workflows, w)
	}

	return pagination.NewResult(workflows, total, page), nil
}

// Update updates a workflow.
func (r *WorkflowRepository) Update(ctx context.Context, w *workflow.Workflow) error {
	query := `
		UPDATE workflows
		SET name = $2, description = $3, is_active = $4, tags = $5,
		    total_runs = $6, successful_runs = $7, failed_runs = $8,
		    last_run_id = $9, last_run_at = $10, last_run_status = $11,
		    updated_at = $12
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		w.ID.String(),
		w.Name,
		w.Description,
		w.IsActive,
		pq.Array(w.Tags),
		w.TotalRuns,
		w.SuccessfulRuns,
		w.FailedRuns,
		nullID(w.LastRunID),
		w.LastRunAt,
		w.LastRunStatus,
		w.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update workflow: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a workflow.
func (r *WorkflowRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM workflows WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete workflow: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetWithGraph retrieves a workflow with its nodes and edges.
func (r *WorkflowRepository) GetWithGraph(ctx context.Context, id shared.ID) (*workflow.Workflow, error) {
	w, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load nodes
	nodesQuery := `
		SELECT id, workflow_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM workflow_nodes
		WHERE workflow_id = $1
		ORDER BY created_at ASC
	`

	nodesRows, err := r.db.QueryContext(ctx, nodesQuery, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow nodes: %w", err)
	}
	defer nodesRows.Close()

	for nodesRows.Next() {
		node, err := scanNode(nodesRows)
		if err != nil {
			return nil, err
		}
		w.Nodes = append(w.Nodes, node)
	}

	// Load edges
	edgesQuery := `
		SELECT id, workflow_id, source_node_key, target_node_key,
		       source_handle, label, created_at
		FROM workflow_edges
		WHERE workflow_id = $1
	`

	edgesRows, err := r.db.QueryContext(ctx, edgesQuery, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to load workflow edges: %w", err)
	}
	defer edgesRows.Close()

	for edgesRows.Next() {
		edge, err := scanEdge(edgesRows)
		if err != nil {
			return nil, err
		}
		w.Edges = append(w.Edges, edge)
	}

	return w, nil
}

func (r *WorkflowRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, description, is_active, tags,
		       total_runs, successful_runs, failed_runs,
		       last_run_id, last_run_at, last_run_status,
		       created_by, created_at, updated_at
		FROM workflows
	`
}

func (r *WorkflowRepository) buildWhereClause(filter workflow.WorkflowFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *WorkflowRepository) scanWorkflow(row *sql.Row) (*workflow.Workflow, error) {
	w := &workflow.Workflow{}
	var (
		id            string
		tenantID      string
		tags          pq.StringArray
		lastRunID     sql.NullString
		lastRunStatus sql.NullString
		createdBy     sql.NullString
	)

	err := row.Scan(
		&id,
		&tenantID,
		&w.Name,
		&w.Description,
		&w.IsActive,
		&tags,
		&w.TotalRuns,
		&w.SuccessfulRuns,
		&w.FailedRuns,
		&lastRunID,
		&w.LastRunAt,
		&lastRunStatus,
		&createdBy,
		&w.CreatedAt,
		&w.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan workflow: %w", err)
	}

	w.ID, _ = shared.IDFromString(id)
	w.TenantID, _ = shared.IDFromString(tenantID)
	w.Tags = tags

	if lastRunID.Valid {
		runID, _ := shared.IDFromString(lastRunID.String)
		w.LastRunID = &runID
	}
	if lastRunStatus.Valid {
		w.LastRunStatus = lastRunStatus.String
	}
	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		w.CreatedBy = &createdByID
	}

	return w, nil
}

func (r *WorkflowRepository) scanWorkflowFromRows(rows *sql.Rows) (*workflow.Workflow, error) {
	w := &workflow.Workflow{}
	var (
		id            string
		tenantID      string
		tags          pq.StringArray
		lastRunID     sql.NullString
		lastRunStatus sql.NullString
		createdBy     sql.NullString
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&w.Name,
		&w.Description,
		&w.IsActive,
		&tags,
		&w.TotalRuns,
		&w.SuccessfulRuns,
		&w.FailedRuns,
		&lastRunID,
		&w.LastRunAt,
		&lastRunStatus,
		&createdBy,
		&w.CreatedAt,
		&w.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan workflow from rows: %w", err)
	}

	w.ID, _ = shared.IDFromString(id)
	w.TenantID, _ = shared.IDFromString(tenantID)
	w.Tags = tags

	if lastRunID.Valid {
		runID, _ := shared.IDFromString(lastRunID.String)
		w.LastRunID = &runID
	}
	if lastRunStatus.Valid {
		w.LastRunStatus = lastRunStatus.String
	}
	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		w.CreatedBy = &createdByID
	}

	return w, nil
}

// scanNode scans a workflow node from rows.
func scanNode(rows *sql.Rows) (*workflow.Node, error) {
	n := &workflow.Node{}
	var (
		id         string
		workflowID string
		nodeType   string
		config     []byte
	)

	err := rows.Scan(
		&id,
		&workflowID,
		&n.NodeKey,
		&nodeType,
		&n.Name,
		&n.Description,
		&n.UIPosition.X,
		&n.UIPosition.Y,
		&config,
		&n.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan workflow node: %w", err)
	}

	n.ID, _ = shared.IDFromString(id)
	n.WorkflowID, _ = shared.IDFromString(workflowID)
	n.NodeType = workflow.NodeType(nodeType)

	if len(config) > 0 {
		_ = json.Unmarshal(config, &n.Config)
	}

	return n, nil
}

// scanEdge scans a workflow edge from rows.
func scanEdge(rows *sql.Rows) (*workflow.Edge, error) {
	e := &workflow.Edge{}
	var (
		id           string
		workflowID   string
		sourceHandle sql.NullString
		label        sql.NullString
	)

	err := rows.Scan(
		&id,
		&workflowID,
		&e.SourceNodeKey,
		&e.TargetNodeKey,
		&sourceHandle,
		&label,
		&e.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan workflow edge: %w", err)
	}

	e.ID, _ = shared.IDFromString(id)
	e.WorkflowID, _ = shared.IDFromString(workflowID)

	if sourceHandle.Valid {
		e.SourceHandle = sourceHandle.String
	}
	if label.Valid {
		e.Label = label.String
	}

	return e, nil
}

// ListActiveWithTriggerType lists active workflows that have a trigger node
// with the specified trigger type. Returns workflows with their full graph.
// Uses a single optimized query with JOINs instead of N+1 queries.
func (r *WorkflowRepository) ListActiveWithTriggerType(ctx context.Context, tenantID shared.ID, triggerType workflow.TriggerType) ([]*workflow.Workflow, error) {
	// Query to find workflows with matching trigger type in their nodes
	// Uses subquery to filter workflows, then loads full graph
	query := `
		SELECT DISTINCT w.id, w.tenant_id, w.name, w.description, w.is_active, w.tags,
		       w.total_runs, w.successful_runs, w.failed_runs,
		       w.last_run_id, w.last_run_at, w.last_run_status,
		       w.created_by, w.created_at, w.updated_at
		FROM workflows w
		INNER JOIN workflow_nodes n ON w.id = n.workflow_id
		WHERE w.tenant_id = $1
		  AND w.is_active = true
		  AND n.node_type = 'trigger'
		  AND n.config->>'trigger_type' = $2
		ORDER BY w.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), string(triggerType))
	if err != nil {
		return nil, fmt.Errorf("failed to list workflows with trigger type: %w", err)
	}
	defer rows.Close()

	// Collect workflow IDs for batch loading nodes/edges
	var workflows []*workflow.Workflow
	workflowIDs := make([]string, 0)

	for rows.Next() {
		w, err := r.scanWorkflowFromRows(rows)
		if err != nil {
			return nil, err
		}
		workflows = append(workflows, w)
		workflowIDs = append(workflowIDs, w.ID.String())
	}

	if len(workflows) == 0 {
		return workflows, nil
	}

	// Batch load all nodes for all workflows in a single query
	nodesQuery := `
		SELECT id, workflow_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM workflow_nodes
		WHERE workflow_id = ANY($1)
		ORDER BY workflow_id, created_at ASC
	`

	nodesRows, err := r.db.QueryContext(ctx, nodesQuery, pq.Array(workflowIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to batch load workflow nodes: %w", err)
	}
	defer nodesRows.Close()

	// Map nodes to workflows
	nodesByWorkflow := make(map[string][]*workflow.Node)
	for nodesRows.Next() {
		node, err := scanNode(nodesRows)
		if err != nil {
			return nil, err
		}
		wfID := node.WorkflowID.String()
		nodesByWorkflow[wfID] = append(nodesByWorkflow[wfID], node)
	}

	// Batch load all edges for all workflows in a single query
	edgesQuery := `
		SELECT id, workflow_id, source_node_key, target_node_key,
		       source_handle, label, created_at
		FROM workflow_edges
		WHERE workflow_id = ANY($1)
	`

	edgesRows, err := r.db.QueryContext(ctx, edgesQuery, pq.Array(workflowIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to batch load workflow edges: %w", err)
	}
	defer edgesRows.Close()

	// Map edges to workflows
	edgesByWorkflow := make(map[string][]*workflow.Edge)
	for edgesRows.Next() {
		edge, err := scanEdge(edgesRows)
		if err != nil {
			return nil, err
		}
		wfID := edge.WorkflowID.String()
		edgesByWorkflow[wfID] = append(edgesByWorkflow[wfID], edge)
	}

	// Assign nodes and edges to workflows
	for _, w := range workflows {
		wfID := w.ID.String()
		w.Nodes = nodesByWorkflow[wfID]
		w.Edges = edgesByWorkflow[wfID]
	}

	return workflows, nil
}
