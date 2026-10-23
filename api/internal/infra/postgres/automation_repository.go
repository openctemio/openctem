package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AutomationRepository implements automation.WorkflowRepository using PostgreSQL.
type AutomationRepository struct {
	db *DB
}

// NewAutomationRepository creates a new AutomationRepository.
func NewAutomationRepository(db *DB) *AutomationRepository {
	return &AutomationRepository{db: db}
}

// Create persists a new workflow.
func (r *AutomationRepository) Create(ctx context.Context, w *automation.Workflow) error {
	query := `
		INSERT INTO automations (
			id, tenant_id, name, description, is_active, tags,
			total_runs, successful_runs, failed_runs,
			created_by, created_at, updated_at, mode
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
		string(modeOrSimulate(w.Mode)),
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
func (r *AutomationRepository) GetByID(ctx context.Context, id shared.ID) (*automation.Workflow, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanWorkflow(row)
}

// GetByTenantAndID retrieves a workflow by tenant and ID.
func (r *AutomationRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*automation.Workflow, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanWorkflow(row)
}

// GetByName retrieves a workflow by name.
func (r *AutomationRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*automation.Workflow, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND name = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanWorkflow(row)
}

// List lists workflows with filters and pagination.
func (r *AutomationRepository) List(ctx context.Context, filter automation.WorkflowFilter, page pagination.Pagination) (pagination.Result[*automation.Workflow], error) {
	var result pagination.Result[*automation.Workflow]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM automations"
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

	var workflows []*automation.Workflow
	for rows.Next() {
		w, err := r.scanWorkflowFromRows(rows)
		if err != nil {
			return result, err
		}
		workflows = append(workflows, w)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}

	return pagination.NewResult(workflows, total, page), nil
}

// Update updates a workflow.
func (r *AutomationRepository) Update(ctx context.Context, w *automation.Workflow) error {
	query := `
		UPDATE automations
		SET name = $2, description = $3, is_active = $4, tags = $5,
		    total_runs = $6, successful_runs = $7, failed_runs = $8,
		    last_run_id = $9, last_run_at = $10, last_run_status = $11,
		    updated_at = $12, disabled_reason = $13
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
		nullString(w.DisabledReason),
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
func (r *AutomationRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM automations WHERE id = $1"
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
func (r *AutomationRepository) GetWithGraph(ctx context.Context, id shared.ID) (*automation.Workflow, error) {
	w, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load nodes
	nodesQuery := `
		SELECT id, automation_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM automation_nodes
		WHERE automation_id = $1
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
		SELECT id, automation_id, source_node_key, target_node_key,
		       source_handle, label, created_at
		FROM automation_edges
		WHERE automation_id = $1
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

func (r *AutomationRepository) selectQuery() string {
	return `
		SELECT ` + automationColumns + `
		FROM automations
	`
}

func (r *AutomationRepository) buildWhereClause(filter automation.WorkflowFilter) (string, []any) {
	var conditions []string
	var args []any

	if filter.TenantID != nil {
		args = append(args, filter.TenantID.String())
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if filter.IsActive != nil {
		args = append(args, *filter.IsActive)
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", len(args)))
	}

	if filter.Search != "" {
		args = append(args, wrapLikePattern(filter.Search))
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", len(args), len(args)))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

// automationColumns is the column list every automation read selects, in
// the order scanAutomation reads it (prefix "w." where a join needs it).
const automationColumns = `id, tenant_id, name, description, is_active, tags,
		       total_runs, successful_runs, failed_runs,
		       last_run_id, last_run_at, last_run_status,
		       created_by, created_at, updated_at, disabled_reason,
		       mode, published_version_id`

// automationColumnsW is automationColumns qualified with the alias w.
const automationColumnsW = `w.id, w.tenant_id, w.name, w.description, w.is_active, w.tags,
		       w.total_runs, w.successful_runs, w.failed_runs,
		       w.last_run_id, w.last_run_at, w.last_run_status,
		       w.created_by, w.created_at, w.updated_at, w.disabled_reason,
		       w.mode, w.published_version_id`

func (r *AutomationRepository) scanWorkflow(row *sql.Row) (*automation.Workflow, error) {
	w, err := scanAutomation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan workflow: %w", err)
	}
	return w, nil
}

func (r *AutomationRepository) scanWorkflowFromRows(rows *sql.Rows) (*automation.Workflow, error) {
	w, err := scanAutomation(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to scan workflow from rows: %w", err)
	}
	return w, nil
}

// scanAutomation reads one row selected with automationColumns.
func scanAutomation(row interface{ Scan(dest ...any) error }) (*automation.Workflow, error) {
	return scanAutomationWith(row)
}

// scanAutomationWith reads automationColumns followed by extra columns.
func scanAutomationWith(row interface{ Scan(dest ...any) error }, extra ...any) (*automation.Workflow, error) {
	w := &automation.Workflow{}
	var (
		id             string
		tenantID       string
		tags           pq.StringArray
		lastRunID      sql.NullString
		lastRunStatus  sql.NullString
		createdBy      sql.NullString
		disabledReason sql.NullString
		mode           string
		publishedVer   sql.NullString
	)
	dest := []any{
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
		&disabledReason,
		&mode,
		&publishedVer,
	}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	w.Mode = automation.Mode(mode)
	if publishedVer.Valid {
		vid, _ := shared.IDFromString(publishedVer.String)
		w.PublishedVersionID = &vid
	}

	w.ID, _ = shared.IDFromString(id)
	w.TenantID, _ = shared.IDFromString(tenantID)
	w.Tags = tags
	w.DisabledReason = disabledReason.String

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
func scanNode(rows *sql.Rows) (*automation.Node, error) {
	n := &automation.Node{}
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
	n.NodeType = automation.NodeType(nodeType)

	if len(config) > 0 {
		_ = json.Unmarshal(config, &n.Config)
	}

	return n, nil
}

// scanEdge scans a workflow edge from rows.
func scanEdge(rows *sql.Rows) (*automation.Edge, error) {
	e := &automation.Edge{}
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
func (r *AutomationRepository) ListActiveWithTriggerType(ctx context.Context, tenantID shared.ID, triggerType automation.TriggerType) ([]*automation.Workflow, error) {
	// Query to find workflows with matching trigger type in their nodes
	// Uses subquery to filter workflows, then loads full graph
	// A live automation is matched on its published version's trigger, a
	// simulate one on its draft: an unpublished edit never changes what
	// starts a live automation.
	query := `
		SELECT ` + automationColumnsW + `, v.definition
		FROM automations w
		LEFT JOIN automation_versions v ON v.id = w.published_version_id AND v.tenant_id = w.tenant_id
		WHERE w.tenant_id = $1
		  AND w.is_active = true
		  AND (
		        (w.mode = 'live' AND v.definition->'nodes' @> jsonb_build_array(jsonb_build_object(
		             'node_type', 'trigger', 'config', jsonb_build_object('trigger_type', $2::text))))
		     OR (w.mode = 'simulate' AND EXISTS (
		             SELECT 1 FROM automation_nodes n
		              WHERE n.automation_id = w.id AND n.node_type = 'trigger' AND n.config->>'trigger_type' = $2))
		  )
		ORDER BY w.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), string(triggerType))
	if err != nil {
		return nil, fmt.Errorf("failed to list workflows with trigger type: %w", err)
	}
	defer rows.Close()

	// Collect workflow IDs for batch loading nodes/edges
	var workflows []*automation.Workflow
	workflowIDs := make([]string, 0)
	published := make(map[string]automation.Definition)

	for rows.Next() {
		var def []byte
		w, err := scanAutomationWith(rows, &def)
		if err != nil {
			return nil, fmt.Errorf("failed to scan workflow from rows: %w", err)
		}
		workflows = append(workflows, w)
		if w.Mode == automation.ModeLive {
			var d automation.Definition
			if err := json.Unmarshal(def, &d); err != nil {
				return nil, fmt.Errorf("decode published definition: %w", err)
			}
			published[w.ID.String()] = d
			continue
		}
		workflowIDs = append(workflowIDs, w.ID.String())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(workflowIDs) == 0 {
		for i, w := range workflows {
			workflows[i] = published[w.ID.String()].Materialize(w)
		}
		return workflows, nil
	}

	// Batch load all nodes for all workflows in a single query
	nodesQuery := `
		SELECT id, automation_id, node_key, node_type, name, description,
		       ui_position_x, ui_position_y, config, created_at
		FROM automation_nodes
		WHERE automation_id = ANY($1)
		ORDER BY automation_id, created_at ASC
	`

	nodesRows, err := r.db.QueryContext(ctx, nodesQuery, pq.Array(workflowIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to batch load workflow nodes: %w", err)
	}
	defer nodesRows.Close()

	// Map nodes to workflows
	nodesByWorkflow := make(map[string][]*automation.Node)
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
		SELECT id, automation_id, source_node_key, target_node_key,
		       source_handle, label, created_at
		FROM automation_edges
		WHERE automation_id = ANY($1)
	`

	edgesRows, err := r.db.QueryContext(ctx, edgesQuery, pq.Array(workflowIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to batch load workflow edges: %w", err)
	}
	defer edgesRows.Close()

	// Map edges to workflows
	edgesByWorkflow := make(map[string][]*automation.Edge)
	for edgesRows.Next() {
		edge, err := scanEdge(edgesRows)
		if err != nil {
			return nil, err
		}
		wfID := edge.WorkflowID.String()
		edgesByWorkflow[wfID] = append(edgesByWorkflow[wfID], edge)
	}

	// Assign nodes and edges to workflows: the published version's graph for
	// a live automation, the draft for a simulate one.
	for i, w := range workflows {
		wfID := w.ID.String()
		if d, ok := published[wfID]; ok {
			workflows[i] = d.Materialize(w)
			continue
		}
		w.Nodes = nodesByWorkflow[wfID]
		w.Edges = edgesByWorkflow[wfID]
	}

	return workflows, nil
}

// SetMode implements automation.ModeSetter.
func (r *AutomationRepository) SetMode(ctx context.Context, tenantID, id shared.ID, mode automation.Mode) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE automations SET mode = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), string(mode))
	if err != nil {
		return fmt.Errorf("failed to set automation mode: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

func modeOrSimulate(m automation.Mode) automation.Mode {
	if m.IsValid() {
		return m
	}
	return automation.ModeSimulate
}

// SetOwner implements automation.OwnerSetter.
func (r *AutomationRepository) SetOwner(ctx context.Context, tenantID, id, ownerID shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE automations SET created_by = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), ownerID.String())
	if err != nil {
		return fmt.Errorf("failed to set workflow owner: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}
