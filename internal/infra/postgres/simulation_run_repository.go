package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/pagination"
)

// SimulationRunRepository implements simulation.RunRepository against the
// attack_simulation_runs table. Before this repo was wired, runs were computed
// in-memory and discarded (the service's runRepo was nil), so run history and
// the async completion path had nowhere to persist.
type SimulationRunRepository struct {
	db *DB
}

// NewSimulationRunRepository creates a new simulation run repository.
func NewSimulationRunRepository(db *DB) *SimulationRunRepository {
	return &SimulationRunRepository{db: db}
}

const simRunColumns = `id, tenant_id, simulation_id, status, result,
	detection_result, prevention_result, steps, output, error_message,
	started_at, completed_at, duration_ms, triggered_by, created_at`

func (r *SimulationRunRepository) scanRun(scan func(dest ...any) error) (*simulation.SimulationRun, error) {
	var (
		id, tenantID, simulationID string
		status                     string
		result, detection          sql.NullString
		prevention, errorMessage   sql.NullString
		stepsJSON, outputJSON      []byte
		startedAt, completedAt     sql.NullTime
		durationMs                 sql.NullInt64
		triggeredBy                sql.NullString
		createdAt                  sql.NullTime
	)

	if err := scan(
		&id, &tenantID, &simulationID, &status, &result,
		&detection, &prevention, &stepsJSON, &outputJSON, &errorMessage,
		&startedAt, &completedAt, &durationMs, &triggeredBy, &createdAt,
	); err != nil {
		return nil, err
	}

	rid, _ := shared.IDFromString(id)
	tid, _ := shared.IDFromString(tenantID)
	sid, _ := shared.IDFromString(simulationID)

	var steps []map[string]any
	if len(stepsJSON) > 0 {
		_ = json.Unmarshal(stepsJSON, &steps)
	}
	var output map[string]any
	if len(outputJSON) > 0 {
		_ = json.Unmarshal(outputJSON, &output)
	}

	var startedTime, completedTime *time.Time
	if startedAt.Valid {
		startedTime = &startedAt.Time
	}
	if completedAt.Valid {
		completedTime = &completedAt.Time
	}

	var triggeredByID *shared.ID
	if triggeredBy.Valid {
		if tbid, err := shared.IDFromString(triggeredBy.String); err == nil {
			triggeredByID = &tbid
		}
	}

	return simulation.ReconstituteRun(
		rid, tid, sid,
		simulation.RunStatus(status), simulation.RunResult(result.String),
		detection.String, prevention.String,
		steps, output, errorMessage.String,
		startedTime, completedTime, int(durationMs.Int64),
		triggeredByID, createdAt.Time,
	), nil
}

// Create inserts a new simulation run.
func (r *SimulationRunRepository) Create(ctx context.Context, run *simulation.SimulationRun) error {
	stepsJSON, _ := json.Marshal(run.Steps())
	outputJSON, _ := json.Marshal(run.Output())

	var triggeredBy *string
	if run.TriggeredBy() != nil {
		s := run.TriggeredBy().String()
		triggeredBy = &s
	}

	query := `INSERT INTO attack_simulation_runs (` + simRunColumns + `)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

	_, err := r.db.ExecContext(ctx, query,
		run.ID().String(), run.TenantID().String(), run.SimulationID().String(),
		string(run.Status()), nullableString(string(run.Result())),
		nullableString(run.DetectionResult()), nullableString(run.PreventionResult()),
		stepsJSON, outputJSON, nullableString(run.ErrorMessage()),
		run.StartedAt(), run.CompletedAt(), run.DurationMs(), triggeredBy, run.CreatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create simulation run: %w", err)
	}
	return nil
}

// GetByID loads a run scoped to its tenant.
func (r *SimulationRunRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*simulation.SimulationRun, error) {
	query := `SELECT ` + simRunColumns + ` FROM attack_simulation_runs WHERE tenant_id = $1 AND id = $2`
	run, err := r.scanRun(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if err == sql.ErrNoRows { //nolint:errorlint
			return nil, fmt.Errorf("%w: simulation run not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get simulation run: %w", err)
	}
	return run, nil
}

// Update persists a run's mutable state (status/result/timings/output).
func (r *SimulationRunRepository) Update(ctx context.Context, run *simulation.SimulationRun) error {
	stepsJSON, _ := json.Marshal(run.Steps())
	outputJSON, _ := json.Marshal(run.Output())

	query := `UPDATE attack_simulation_runs SET
		status = $3, result = $4, detection_result = $5, prevention_result = $6,
		steps = $7, output = $8, error_message = $9,
		started_at = $10, completed_at = $11, duration_ms = $12
		WHERE tenant_id = $1 AND id = $2`

	res, err := r.db.ExecContext(ctx, query,
		run.TenantID().String(), run.ID().String(),
		string(run.Status()), nullableString(string(run.Result())),
		nullableString(run.DetectionResult()), nullableString(run.PreventionResult()),
		stepsJSON, outputJSON, nullableString(run.ErrorMessage()),
		run.StartedAt(), run.CompletedAt(), run.DurationMs(),
	)
	if err != nil {
		return fmt.Errorf("failed to update simulation run: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: simulation run not found", shared.ErrNotFound)
	}
	return nil
}

// List returns runs matching the filter, newest first.
func (r *SimulationRunRepository) List(ctx context.Context, filter simulation.RunFilter, page pagination.Pagination) (pagination.Result[*simulation.SimulationRun], error) {
	where := "WHERE 1=1"
	args := []any{}
	i := 1
	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", i)
		args = append(args, filter.TenantID.String())
		i++
	}
	if filter.SimulationID != nil {
		where += fmt.Sprintf(" AND simulation_id = $%d", i)
		args = append(args, filter.SimulationID.String())
		i++
	}
	if filter.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", i)
		args = append(args, string(*filter.Status))
		i++
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM attack_simulation_runs "+where, args...).Scan(&total); err != nil {
		return pagination.Result[*simulation.SimulationRun]{}, fmt.Errorf("failed to count simulation runs: %w", err)
	}

	query := fmt.Sprintf("SELECT %s FROM attack_simulation_runs %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		simRunColumns, where, i, i+1)
	args = append(args, page.PerPage, page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*simulation.SimulationRun]{}, fmt.Errorf("failed to list simulation runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	runs := make([]*simulation.SimulationRun, 0)
	for rows.Next() {
		run, err := r.scanRun(rows.Scan)
		if err != nil {
			return pagination.Result[*simulation.SimulationRun]{}, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*simulation.SimulationRun]{}, err
	}

	return pagination.NewResult(runs, int64(total), page), nil
}
