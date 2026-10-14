package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// DataFlowRepository implements vulnerability.DataFlowRepository using
// PostgreSQL. finding_data_flows and finding_flow_locations carry no
// tenant_id: every query reaches them through findings, filtered by the
// tenant.
type DataFlowRepository struct {
	db *DB
}

// NewDataFlowRepository creates a new DataFlowRepository.
func NewDataFlowRepository(db *DB) *DataFlowRepository {
	return &DataFlowRepository{db: db}
}

var _ vulnerability.DataFlowRepository = (*DataFlowRepository)(nil)

// GetDataFlowsWithLocations returns the data flows of the tenant's finding
// and their locations, in two queries.
func (r *DataFlowRepository) GetDataFlowsWithLocations(ctx context.Context, tenantID, findingID shared.ID) ([]*vulnerability.FindingDataFlow, map[string][]*vulnerability.FindingFlowLocation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT df.id, df.finding_id, df.flow_index, df.message, df.importance, df.created_at
		FROM finding_data_flows df
		JOIN findings f ON f.id = df.finding_id
		WHERE df.finding_id = $1 AND f.tenant_id = $2
		ORDER BY df.flow_index ASC`, findingID.String(), tenantID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list data flows: %w", err)
	}
	flows, err := r.scanDataFlows(rows)
	if err != nil {
		return nil, nil, err
	}
	if len(flows) == 0 {
		return nil, nil, nil
	}

	flowIDs := make([]string, len(flows))
	for i, f := range flows {
		flowIDs[i] = f.ID().String()
	}
	// The flow ids came from the tenant-filtered query above; the join
	// repeats the tenant filter so this query is safe on its own.
	lrows, err := r.db.QueryContext(ctx, `
		SELECT fl.id, fl.data_flow_id, fl.step_index, fl.location_type,
			fl.file_path, fl.start_line, fl.end_line, fl.start_column, fl.end_column, fl.snippet,
			fl.function_name, fl.class_name, fl.fully_qualified_name, fl.module_name,
			fl.label, fl.message, fl.nesting_level, fl.importance
		FROM finding_flow_locations fl
		JOIN finding_data_flows df ON df.id = fl.data_flow_id
		JOIN findings f ON f.id = df.finding_id
		WHERE fl.data_flow_id = ANY($1) AND f.tenant_id = $2
		ORDER BY fl.data_flow_id, fl.step_index ASC`, pq.Array(flowIDs), tenantID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list flow locations: %w", err)
	}
	defer lrows.Close()

	locations := make(map[string][]*vulnerability.FindingFlowLocation, len(flows))
	for lrows.Next() {
		loc, err := r.scanFlowLocation(lrows.Scan)
		if err != nil {
			return nil, nil, err
		}
		id := loc.DataFlowID().String()
		locations[id] = append(locations[id], loc)
	}
	if err := lrows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating flow locations: %w", err)
	}
	return flows, locations, nil
}

// ReplaceDataFlows stores each trace on the tenant's finding with its
// fingerprint when the stored trace hash differs. One read resolves the
// findings and their stored hashes; each changed finding is then replaced in
// its own transaction, serialized per finding, so a concurrent ingest of the
// same finding never leaves two traces or half of one.
func (r *DataFlowRepository) ReplaceDataFlows(ctx context.Context, tenantID shared.ID, traces []vulnerability.FindingTrace) (int, error) {
	if len(traces) == 0 {
		return 0, nil
	}
	fps := make([]string, 0, len(traces))
	for _, t := range traces {
		fps = append(fps, t.Fingerprint)
	}
	byFP, err := r.storedTraceHashes(ctx, tenantID, fps)
	if err != nil {
		return 0, err
	}

	replaced := 0
	for _, t := range traces {
		s, ok := byFP[t.Fingerprint]
		if !ok || s.hash == t.Hash || len(t.Flows) == 0 {
			continue
		}
		done, err := r.replaceOne(ctx, tenantID, s.id, t)
		if err != nil {
			return replaced, err
		}
		if done {
			replaced++
		}
	}
	return replaced, nil
}

type storedTrace struct {
	id   string
	hash string
}

// storedTraceHashes resolves the tenant's findings with the fingerprints and
// the hash of the trace each one has stored ("" for none).
func (r *DataFlowRepository) storedTraceHashes(ctx context.Context, tenantID shared.ID, fps []string) (map[string]storedTrace, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.fingerprint, f.id,
			(SELECT df.trace_hash FROM finding_data_flows df WHERE df.finding_id = f.id ORDER BY df.flow_index LIMIT 1)
		FROM findings f
		WHERE f.tenant_id = $1 AND f.fingerprint = ANY($2)`, tenantID.String(), pq.Array(fps))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve findings for data flows: %w", err)
	}
	defer rows.Close()
	out := make(map[string]storedTrace, len(fps))
	for rows.Next() {
		var fp, id string
		var hash sql.NullString
		if err := rows.Scan(&fp, &id, &hash); err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		out[fp] = storedTrace{id: id, hash: hash.String}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating findings: %w", err)
	}
	return out, nil
}

// replaceOne replaces the data flows of one finding in a transaction. The
// finding is re-checked against the tenant under the lock, and the stored
// hash re-read: a concurrent ingest that stored the same trace first leaves
// nothing to do.
func (r *DataFlowRepository) replaceOne(ctx context.Context, tenantID shared.ID, findingID string, t vulnerability.FindingTrace) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin data flow transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('finding_data_flows:' || $1, 0))`, findingID); err != nil {
		return false, fmt.Errorf("failed to lock finding data flows: %w", err)
	}
	var hash sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT (SELECT df.trace_hash FROM finding_data_flows df WHERE df.finding_id = f.id ORDER BY df.flow_index LIMIT 1)
		FROM findings f WHERE f.id = $1 AND f.tenant_id = $2`, findingID, tenantID.String()).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // deleted meanwhile, or not the tenant's
		}
		return false, fmt.Errorf("failed to read data flow hash: %w", err)
	}
	if hash.String == t.Hash {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM finding_data_flows WHERE finding_id = $1`, findingID); err != nil {
		return false, fmt.Errorf("failed to delete data flows: %w", err)
	}

	var locs []any
	nLocs := 0
	for _, f := range t.Flows {
		flowID := shared.NewID().String()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO finding_data_flows (id, finding_id, flow_index, message, importance, trace_hash)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			flowID, findingID, f.Index, nullString(f.Message), f.Importance, t.Hash); err != nil {
			return false, fmt.Errorf("failed to insert data flow: %w", err)
		}
		for _, s := range f.Steps {
			var path, snippet string
			var sl, el, sc, ec int
			if l := s.Location; l != nil {
				path, snippet = l.Path, l.Snippet
				sl, el, sc, ec = l.StartLine, l.EndLine, l.StartColumn, l.EndColumn
			}
			locs = append(locs,
				shared.NewID().String(), flowID, s.Index, s.LocationType,
				nullString(path), sl, el, sc, ec, nullString(snippet),
				nullString(s.FunctionName), nullString(s.ClassName), nullString(s.FullyQualifiedName), nullString(s.ModuleName),
				nullString(s.Label), nullString(s.Message), s.NestingLevel, s.Importance)
			nLocs++
			if nLocs == flowLocationInsertBatch {
				if err := insertFlowLocations(ctx, tx, locs, nLocs); err != nil {
					return false, err
				}
				locs, nLocs = locs[:0], 0
			}
		}
	}
	if nLocs > 0 {
		if err := insertFlowLocations(ctx, tx, locs, nLocs); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit data flows: %w", err)
	}
	return true, nil
}

// flowLocationColumns is the number of values one location row takes;
// flowLocationInsertBatch rows stay well under the 65535 parameter limit.
const (
	flowLocationColumns     = 18
	flowLocationInsertBatch = 1000
)

func insertFlowLocations(ctx context.Context, tx *sql.Tx, args []any, n int) error {
	var b strings.Builder
	b.WriteString(`INSERT INTO finding_flow_locations (
		id, data_flow_id, step_index, location_type,
		file_path, start_line, end_line, start_column, end_column, snippet,
		function_name, class_name, fully_qualified_name, module_name,
		label, message, nesting_level, importance) VALUES `)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('(')
		for c := 0; c < flowLocationColumns; c++ {
			if c > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "$%d", i*flowLocationColumns+c+1)
		}
		b.WriteByte(')')
	}
	if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
		return fmt.Errorf("failed to insert flow locations: %w", err)
	}
	return nil
}

func (r *DataFlowRepository) scanDataFlows(rows *sql.Rows) ([]*vulnerability.FindingDataFlow, error) {
	defer rows.Close()
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
	if err := scan(&idStr, &findingIDStr, &flowIndex, &message, &importance, &createdAt); err != nil {
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
