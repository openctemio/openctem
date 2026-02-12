package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// DataFlowRepository implements vulnerability.DataFlowRepository using PostgreSQL.
type DataFlowRepository struct {
	db *DB
}

// NewDataFlowRepository creates a new DataFlowRepository.
func NewDataFlowRepository(db *DB) *DataFlowRepository {
	return &DataFlowRepository{db: db}
}

// =============================================================================
// Data Flow Operations
// =============================================================================

// CreateDataFlow persists a new data flow.
func (r *DataFlowRepository) CreateDataFlow(ctx context.Context, flow *vulnerability.FindingDataFlow) error {
	query := `
		INSERT INTO finding_data_flows (
			id, finding_id, flow_index, message, importance, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.ExecContext(ctx, query,
		flow.ID().String(),
		flow.FindingID().String(),
		flow.FlowIndex(),
		nullString(flow.Message()),
		nullString(flow.Importance()),
		flow.CreatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create data flow: %w", err)
	}

	return nil
}

// CreateDataFlowBatch persists multiple data flows.
func (r *DataFlowRepository) CreateDataFlowBatch(ctx context.Context, flows []*vulnerability.FindingDataFlow) error {
	if len(flows) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO finding_data_flows (
			id, finding_id, flow_index, message, importance, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, flow := range flows {
		_, err = stmt.ExecContext(ctx,
			flow.ID().String(),
			flow.FindingID().String(),
			flow.FlowIndex(),
			nullString(flow.Message()),
			nullString(flow.Importance()),
			flow.CreatedAt(),
		)
		if err != nil {
			return fmt.Errorf("failed to create data flow: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetDataFlowByID retrieves a data flow by ID.
func (r *DataFlowRepository) GetDataFlowByID(ctx context.Context, id shared.ID) (*vulnerability.FindingDataFlow, error) {
	query := `
		SELECT id, finding_id, flow_index, message, importance, created_at
		FROM finding_data_flows
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	flow, err := r.scanDataFlow(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get data flow: %w", err)
	}

	return flow, nil
}

// ListDataFlowsByFinding retrieves all data flows for a finding.
func (r *DataFlowRepository) ListDataFlowsByFinding(ctx context.Context, findingID shared.ID) ([]*vulnerability.FindingDataFlow, error) {
	query := `
		SELECT id, finding_id, flow_index, message, importance, created_at
		FROM finding_data_flows
		WHERE finding_id = $1
		ORDER BY flow_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list data flows: %w", err)
	}
	defer rows.Close()

	return r.scanDataFlows(rows)
}

// DeleteDataFlowsByFinding removes all data flows for a finding.
func (r *DataFlowRepository) DeleteDataFlowsByFinding(ctx context.Context, findingID shared.ID) error {
	query := `DELETE FROM finding_data_flows WHERE finding_id = $1`

	_, err := r.db.ExecContext(ctx, query, findingID.String())
	if err != nil {
		return fmt.Errorf("failed to delete data flows: %w", err)
	}

	return nil
}

// GetDataFlowsWithLocations retrieves all data flows for a finding with their locations in optimized queries.
// This optimizes the N+1 query problem by:
// 1. One query to get all data flows
// 2. One query to get all locations for all data flows (using ANY clause)
// Total: 2 queries instead of 1 + N queries
func (r *DataFlowRepository) GetDataFlowsWithLocations(ctx context.Context, findingID shared.ID) ([]*vulnerability.FindingDataFlow, map[string][]*vulnerability.FindingFlowLocation, error) {
	// Step 1: Get all data flows for the finding
	flows, err := r.ListDataFlowsByFinding(ctx, findingID)
	if err != nil {
		return nil, nil, err
	}

	if len(flows) == 0 {
		return nil, nil, nil
	}

	// Step 2: Collect all flow IDs
	flowIDs := make([]string, len(flows))
	for i, f := range flows {
		flowIDs[i] = f.ID().String()
	}

	// Step 3: Get all locations for all flows in a single query using ANY
	query := `
		SELECT id, data_flow_id, step_index, location_type,
			file_path, start_line, end_line, start_column, end_column, snippet,
			function_name, class_name, fully_qualified_name, module_name,
			label, message, nesting_level, importance
		FROM finding_flow_locations
		WHERE data_flow_id = ANY($1)
		ORDER BY data_flow_id, step_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(flowIDs))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list flow locations: %w", err)
	}
	defer rows.Close()

	// Step 4: Scan all locations and group by data_flow_id
	locationsMap := make(map[string][]*vulnerability.FindingFlowLocation)
	for rows.Next() {
		loc, err := r.scanFlowLocation(rows.Scan)
		if err != nil {
			return nil, nil, err
		}
		dfID := loc.DataFlowID().String()
		locationsMap[dfID] = append(locationsMap[dfID], loc)
	}

	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating flow locations: %w", err)
	}

	return flows, locationsMap, nil
}

// GetDataFlowsWithLocationsByTenant retrieves data flows with tenant verification.
// SECURITY: This method provides defense-in-depth by verifying the finding belongs
// to the specified tenant before returning data flows. Use this when tenant context
// is available to prevent IDOR attacks.
func (r *DataFlowRepository) GetDataFlowsWithLocationsByTenant(ctx context.Context, findingID, tenantID shared.ID) ([]*vulnerability.FindingDataFlow, map[string][]*vulnerability.FindingFlowLocation, error) {
	// Step 1: Verify finding belongs to tenant (defense-in-depth)
	var count int
	verifyQuery := `SELECT COUNT(*) FROM findings WHERE id = $1 AND tenant_id = $2`
	if err := r.db.QueryRowContext(ctx, verifyQuery, findingID.String(), tenantID.String()).Scan(&count); err != nil {
		return nil, nil, fmt.Errorf("failed to verify finding tenant: %w", err)
	}
	if count == 0 {
		return nil, nil, shared.ErrNotFound
	}

	// Step 2: Now safe to load data flows
	return r.GetDataFlowsWithLocations(ctx, findingID)
}

func (r *DataFlowRepository) scanDataFlows(rows *sql.Rows) ([]*vulnerability.FindingDataFlow, error) {
	var flows []*vulnerability.FindingDataFlow
	for rows.Next() {
		flow, err := r.scanDataFlow(rows.Scan)
		if err != nil {
			return nil, err
		}
		flows = append(flows, flow)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating data flows: %w", err)
	}

	return flows, nil
}

func (r *DataFlowRepository) scanDataFlow(scan func(dest ...any) error) (*vulnerability.FindingDataFlow, error) {
	var (
		idStr        string
		findingIDStr string
		flowIndex    int
		message      sql.NullString
		importance   sql.NullString
		createdAt    sql.NullTime
	)

	err := scan(
		&idStr, &findingIDStr, &flowIndex, &message, &importance, &createdAt,
	)
	if err != nil {
		return nil, err
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data flow id: %w", err)
	}

	findingID, err := shared.IDFromString(findingIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse finding id: %w", err)
	}

	data := vulnerability.FindingDataFlowData{
		ID:         id,
		FindingID:  findingID,
		FlowIndex:  flowIndex,
		Message:    nullStringValue(message),
		Importance: nullStringValue(importance),
	}
	if createdAt.Valid {
		data.CreatedAt = createdAt.Time
	}

	return vulnerability.ReconstituteFindingDataFlow(data), nil
}

// =============================================================================
// Flow Location Operations
// =============================================================================

// CreateFlowLocation persists a new flow location.
func (r *DataFlowRepository) CreateFlowLocation(ctx context.Context, location *vulnerability.FindingFlowLocation) error {
	query := `
		INSERT INTO finding_flow_locations (
			id, data_flow_id, step_index, location_type,
			file_path, start_line, end_line, start_column, end_column, snippet,
			function_name, class_name, fully_qualified_name, module_name,
			label, message, nesting_level, importance
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err := r.db.ExecContext(ctx, query,
		location.ID().String(),
		location.DataFlowID().String(),
		location.StepIndex(),
		location.LocationType(),
		nullString(location.FilePath()),
		location.StartLine(),
		location.EndLine(),
		location.StartColumn(),
		location.EndColumn(),
		nullString(location.Snippet()),
		nullString(location.FunctionName()),
		nullString(location.ClassName()),
		nullString(location.FullyQualifiedName()),
		nullString(location.ModuleName()),
		nullString(location.Label()),
		nullString(location.Message()),
		location.NestingLevel(),
		nullString(location.Importance()),
	)
	if err != nil {
		return fmt.Errorf("failed to create flow location: %w", err)
	}

	return nil
}

// CreateFlowLocationBatch persists multiple flow locations.
func (r *DataFlowRepository) CreateFlowLocationBatch(ctx context.Context, locations []*vulnerability.FindingFlowLocation) error {
	if len(locations) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO finding_flow_locations (
			id, data_flow_id, step_index, location_type,
			file_path, start_line, end_line, start_column, end_column, snippet,
			function_name, class_name, fully_qualified_name, module_name,
			label, message, nesting_level, importance
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, loc := range locations {
		_, err = stmt.ExecContext(ctx,
			loc.ID().String(),
			loc.DataFlowID().String(),
			loc.StepIndex(),
			loc.LocationType(),
			nullString(loc.FilePath()),
			loc.StartLine(),
			loc.EndLine(),
			loc.StartColumn(),
			loc.EndColumn(),
			nullString(loc.Snippet()),
			nullString(loc.FunctionName()),
			nullString(loc.ClassName()),
			nullString(loc.FullyQualifiedName()),
			nullString(loc.ModuleName()),
			nullString(loc.Label()),
			nullString(loc.Message()),
			loc.NestingLevel(),
			nullString(loc.Importance()),
		)
		if err != nil {
			return fmt.Errorf("failed to create flow location: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetFlowLocationByID retrieves a flow location by ID.
func (r *DataFlowRepository) GetFlowLocationByID(ctx context.Context, id shared.ID) (*vulnerability.FindingFlowLocation, error) {
	query := `
		SELECT id, data_flow_id, step_index, location_type,
			file_path, start_line, end_line, start_column, end_column, snippet,
			function_name, class_name, fully_qualified_name, module_name,
			label, message, nesting_level, importance
		FROM finding_flow_locations
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	loc, err := r.scanFlowLocation(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get flow location: %w", err)
	}

	return loc, nil
}

// ListFlowLocationsByDataFlow retrieves all locations for a data flow.
func (r *DataFlowRepository) ListFlowLocationsByDataFlow(ctx context.Context, dataFlowID shared.ID) ([]*vulnerability.FindingFlowLocation, error) {
	query := `
		SELECT id, data_flow_id, step_index, location_type,
			file_path, start_line, end_line, start_column, end_column, snippet,
			function_name, class_name, fully_qualified_name, module_name,
			label, message, nesting_level, importance
		FROM finding_flow_locations
		WHERE data_flow_id = $1
		ORDER BY step_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, dataFlowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list flow locations: %w", err)
	}
	defer rows.Close()

	return r.scanFlowLocations(rows)
}

// ListFlowLocationsByFile retrieves all flow locations in a file for a specific tenant.
// SECURITY: Always requires tenantID to prevent cross-tenant data access.
func (r *DataFlowRepository) ListFlowLocationsByFile(ctx context.Context, tenantID shared.ID, filePath string, page pagination.Pagination) (pagination.Result[*vulnerability.FindingFlowLocation], error) {
	// SECURITY: Join with findings table to enforce tenant isolation
	countQuery := `
		SELECT COUNT(*)
		FROM finding_flow_locations fl
		JOIN finding_data_flows df ON df.id = fl.data_flow_id
		JOIN findings f ON f.id = df.finding_id
		WHERE fl.file_path = $1 AND f.tenant_id = $2
	`
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, filePath, tenantID.String()).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingFlowLocation]{}, fmt.Errorf("failed to count flow locations: %w", err)
	}

	query := `
		SELECT fl.id, fl.data_flow_id, fl.step_index, fl.location_type,
			fl.file_path, fl.start_line, fl.end_line, fl.start_column, fl.end_column, fl.snippet,
			fl.function_name, fl.class_name, fl.fully_qualified_name, fl.module_name,
			fl.label, fl.message, fl.nesting_level, fl.importance
		FROM finding_flow_locations fl
		JOIN finding_data_flows df ON df.id = fl.data_flow_id
		JOIN findings f ON f.id = df.finding_id
		WHERE fl.file_path = $1 AND f.tenant_id = $2
		ORDER BY fl.start_line ASC
		LIMIT $3 OFFSET $4
	`

	rows, err := r.db.QueryContext(ctx, query, filePath, tenantID.String(), page.Limit, page.Offset())
	if err != nil {
		return pagination.Result[*vulnerability.FindingFlowLocation]{}, fmt.Errorf("failed to list flow locations: %w", err)
	}
	defer rows.Close()

	items, err := r.scanFlowLocations(rows)
	if err != nil {
		return pagination.Result[*vulnerability.FindingFlowLocation]{}, err
	}

	return pagination.NewResult(items, total, page), nil
}

// ListFlowLocationsByFunction retrieves all flow locations in a function for a specific tenant.
// SECURITY: Always requires tenantID to prevent cross-tenant data access.
func (r *DataFlowRepository) ListFlowLocationsByFunction(ctx context.Context, tenantID shared.ID, functionName string, page pagination.Pagination) (pagination.Result[*vulnerability.FindingFlowLocation], error) {
	// SECURITY: Join with findings table to enforce tenant isolation
	countQuery := `
		SELECT COUNT(*)
		FROM finding_flow_locations fl
		JOIN finding_data_flows df ON df.id = fl.data_flow_id
		JOIN findings f ON f.id = df.finding_id
		WHERE fl.function_name = $1 AND f.tenant_id = $2
	`
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, functionName, tenantID.String()).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingFlowLocation]{}, fmt.Errorf("failed to count flow locations: %w", err)
	}

	query := `
		SELECT fl.id, fl.data_flow_id, fl.step_index, fl.location_type,
			fl.file_path, fl.start_line, fl.end_line, fl.start_column, fl.end_column, fl.snippet,
			fl.function_name, fl.class_name, fl.fully_qualified_name, fl.module_name,
			fl.label, fl.message, fl.nesting_level, fl.importance
		FROM finding_flow_locations fl
		JOIN finding_data_flows df ON df.id = fl.data_flow_id
		JOIN findings f ON f.id = df.finding_id
		WHERE fl.function_name = $1 AND f.tenant_id = $2
		ORDER BY fl.file_path, fl.start_line ASC
		LIMIT $3 OFFSET $4
	`

	rows, err := r.db.QueryContext(ctx, query, functionName, tenantID.String(), page.Limit, page.Offset())
	if err != nil {
		return pagination.Result[*vulnerability.FindingFlowLocation]{}, fmt.Errorf("failed to list flow locations: %w", err)
	}
	defer rows.Close()

	items, err := r.scanFlowLocations(rows)
	if err != nil {
		return pagination.Result[*vulnerability.FindingFlowLocation]{}, err
	}

	return pagination.NewResult(items, total, page), nil
}

// ListSourcesAndSinks retrieves all source and sink locations for a finding.
func (r *DataFlowRepository) ListSourcesAndSinks(ctx context.Context, findingID shared.ID) ([]*vulnerability.FindingFlowLocation, error) {
	query := `
		SELECT fl.id, fl.data_flow_id, fl.step_index, fl.location_type,
			fl.file_path, fl.start_line, fl.end_line, fl.start_column, fl.end_column, fl.snippet,
			fl.function_name, fl.class_name, fl.fully_qualified_name, fl.module_name,
			fl.label, fl.message, fl.nesting_level, fl.importance
		FROM finding_flow_locations fl
		JOIN finding_data_flows df ON df.id = fl.data_flow_id
		WHERE df.finding_id = $1 AND fl.location_type IN ('source', 'sink')
		ORDER BY df.flow_index, fl.step_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list sources and sinks: %w", err)
	}
	defer rows.Close()

	return r.scanFlowLocations(rows)
}

// DeleteFlowLocationsByDataFlow removes all locations for a data flow.
func (r *DataFlowRepository) DeleteFlowLocationsByDataFlow(ctx context.Context, dataFlowID shared.ID) error {
	query := `DELETE FROM finding_flow_locations WHERE data_flow_id = $1`

	_, err := r.db.ExecContext(ctx, query, dataFlowID.String())
	if err != nil {
		return fmt.Errorf("failed to delete flow locations: %w", err)
	}

	return nil
}

func (r *DataFlowRepository) scanFlowLocations(rows *sql.Rows) ([]*vulnerability.FindingFlowLocation, error) {
	var locations []*vulnerability.FindingFlowLocation
	for rows.Next() {
		loc, err := r.scanFlowLocation(rows.Scan)
		if err != nil {
			return nil, err
		}
		locations = append(locations, loc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating flow locations: %w", err)
	}

	return locations, nil
}

func (r *DataFlowRepository) scanFlowLocation(scan func(dest ...any) error) (*vulnerability.FindingFlowLocation, error) {
	var (
		idStr              string
		dataFlowID         string
		stepIndex          int
		locationType       string
		filePath           sql.NullString
		startLine          sql.NullInt64
		endLine            sql.NullInt64
		startColumn        sql.NullInt64
		endColumn          sql.NullInt64
		snippet            sql.NullString
		functionName       sql.NullString
		className          sql.NullString
		fullyQualifiedName sql.NullString
		moduleName         sql.NullString
		label              sql.NullString
		message            sql.NullString
		nestingLevel       sql.NullInt64
		importance         sql.NullString
	)

	err := scan(
		&idStr, &dataFlowID, &stepIndex, &locationType,
		&filePath, &startLine, &endLine, &startColumn, &endColumn, &snippet,
		&functionName, &className, &fullyQualifiedName, &moduleName,
		&label, &message, &nestingLevel, &importance,
	)
	if err != nil {
		return nil, err
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse flow location id: %w", err)
	}

	dfID, err := shared.IDFromString(dataFlowID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data flow id: %w", err)
	}

	data := vulnerability.FindingFlowLocationData{
		ID:                 id,
		DataFlowID:         dfID,
		StepIndex:          stepIndex,
		LocationType:       locationType,
		FilePath:           nullStringValue(filePath),
		StartLine:          int(startLine.Int64),
		EndLine:            int(endLine.Int64),
		StartColumn:        int(startColumn.Int64),
		EndColumn:          int(endColumn.Int64),
		Snippet:            nullStringValue(snippet),
		FunctionName:       nullStringValue(functionName),
		ClassName:          nullStringValue(className),
		FullyQualifiedName: nullStringValue(fullyQualifiedName),
		ModuleName:         nullStringValue(moduleName),
		Label:              nullStringValue(label),
		Message:            nullStringValue(message),
		NestingLevel:       int(nestingLevel.Int64),
		Importance:         nullStringValue(importance),
	}

	return vulnerability.ReconstituteFindingFlowLocation(data), nil
}
