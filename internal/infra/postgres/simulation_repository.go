package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/pagination"
)

// SimulationRepository implements simulation.SimulationRepository.
type SimulationRepository struct {
	db *DB
}

// NewSimulationRepository creates a new simulation repository.
func NewSimulationRepository(db *DB) *SimulationRepository {
	return &SimulationRepository{db: db}
}

const simSelectCols = `id, tenant_id, name, description, simulation_type, status,
	mitre_tactic, mitre_technique_id, mitre_technique_name,
	target_assets, config, schedule_cron, last_run_at, next_run_at,
	total_runs, last_result, detection_rate, prevention_rate,
	tags, created_by, created_at, updated_at`

func (r *SimulationRepository) scanSim(scan func(dest ...any) error) (*simulation.Simulation, error) {
	var (
		id, tenantID, name, description         string
		simType, status                          string
		mitreTactic, mitreTechID, mitreTechName  string
		targetAssetsJSON, configJSON              []byte
		scheduleCron                              sql.NullString
		lastRunAt, nextRunAt                     sql.NullTime
		totalRuns                                int
		lastResult                               sql.NullString
		detectionRate, preventionRate             float64
		tags                                     pq.StringArray
		createdByStr                             sql.NullString
		createdAt, updatedAt                     sql.NullTime
	)

	err := scan(
		&id, &tenantID, &name, &description,
		&simType, &status,
		&mitreTactic, &mitreTechID, &mitreTechName,
		&targetAssetsJSON, &configJSON,
		&scheduleCron, &lastRunAt, &nextRunAt,
		&totalRuns, &lastResult,
		&detectionRate, &preventionRate,
		&tags, &createdByStr,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, _ := shared.IDFromString(id)
	parsedTenantID, _ := shared.IDFromString(tenantID)

	var targetAssets []string
	_ = json.Unmarshal(targetAssetsJSON, &targetAssets)

	var config map[string]any
	_ = json.Unmarshal(configJSON, &config)

	var createdBy *shared.ID
	if createdByStr.Valid {
		cid, err := shared.IDFromString(createdByStr.String)
		if err == nil {
			createdBy = &cid
		}
	}

	var lastRun, nextRun *time.Time
	if lastRunAt.Valid {
		lastRun = &lastRunAt.Time
	}
	if nextRunAt.Valid {
		nextRun = &nextRunAt.Time
	}

	return simulation.ReconstituteSimulation(
		parsedID, parsedTenantID,
		name, description,
		simulation.SimulationType(simType), simulation.SimulationStatus(status),
		mitreTactic, mitreTechID, mitreTechName,
		targetAssets, config,
		scheduleCron.String, lastRun, nextRun,
		totalRuns, lastResult.String,
		detectionRate, preventionRate,
		[]string(tags), createdBy,
		createdAt.Time, updatedAt.Time,
	), nil
}

func (r *SimulationRepository) Create(ctx context.Context, sim *simulation.Simulation) error {
	targetAssetsJSON, _ := json.Marshal(sim.TargetAssets())
	configJSON, _ := json.Marshal(sim.Config())
	tagsArr := pq.StringArray(sim.Tags())

	var createdBy *string
	if sim.CreatedBy() != nil {
		s := sim.CreatedBy().String()
		createdBy = &s
	}

	query := `INSERT INTO attack_simulations (
		id, tenant_id, name, description, simulation_type, status,
		mitre_tactic, mitre_technique_id, mitre_technique_name,
		target_assets, config, schedule_cron,
		total_runs, last_result, detection_rate, prevention_rate,
		tags, created_by, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`

	_, err := r.db.ExecContext(ctx, query,
		sim.ID().String(), sim.TenantID().String(),
		sim.Name(), sim.Description(),
		string(sim.SimulationType()), string(sim.Status()),
		sim.MitreTactic(), sim.MitreTechniqueID(), sim.MitreTechniqueName(),
		targetAssetsJSON, configJSON, sim.ScheduleCron(),
		sim.TotalRuns(), sim.LastResult(),
		sim.DetectionRate(), sim.PreventionRate(),
		tagsArr, createdBy,
		sim.CreatedAt(), sim.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create simulation: %w", err)
	}
	return nil
}

func (r *SimulationRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*simulation.Simulation, error) {
	query := "SELECT " + simSelectCols + " FROM attack_simulations WHERE tenant_id = $1 AND id = $2"
	sim, err := r.scanSim(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: simulation not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get simulation: %w", err)
	}
	return sim, nil
}

func (r *SimulationRepository) Update(ctx context.Context, sim *simulation.Simulation) error {
	targetAssetsJSON, _ := json.Marshal(sim.TargetAssets())
	configJSON, _ := json.Marshal(sim.Config())
	tagsArr := pq.StringArray(sim.Tags())

	query := `UPDATE attack_simulations SET
		name=$3, description=$4, simulation_type=$5, status=$6,
		mitre_tactic=$7, mitre_technique_id=$8, mitre_technique_name=$9,
		target_assets=$10, config=$11, schedule_cron=$12,
		last_run_at=$13, next_run_at=$14,
		total_runs=$15, last_result=$16, detection_rate=$17, prevention_rate=$18,
		tags=$19, updated_at=$20
		WHERE tenant_id=$1 AND id=$2`

	_, err := r.db.ExecContext(ctx, query,
		sim.TenantID().String(), sim.ID().String(),
		sim.Name(), sim.Description(),
		string(sim.SimulationType()), string(sim.Status()),
		sim.MitreTactic(), sim.MitreTechniqueID(), sim.MitreTechniqueName(),
		targetAssetsJSON, configJSON, sim.ScheduleCron(),
		sim.LastRunAt(), sim.NextRunAt(),
		sim.TotalRuns(), sim.LastResult(),
		sim.DetectionRate(), sim.PreventionRate(),
		tagsArr, sim.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update simulation: %w", err)
	}
	return nil
}

func (r *SimulationRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM attack_simulations WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete simulation: %w", err)
	}
	return nil
}

func (r *SimulationRepository) List(ctx context.Context, filter simulation.SimulationFilter, page pagination.Pagination) (pagination.Result[*simulation.Simulation], error) {
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, filter.TenantID.String())
		argIdx++
	}
	if filter.SimulationType != nil {
		where += fmt.Sprintf(" AND simulation_type = $%d", argIdx)
		args = append(args, string(*filter.SimulationType))
		argIdx++
	}
	if filter.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, string(*filter.Status))
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+*filter.Search+"%")
		// argIdx not incremented — no further conditions
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM attack_simulations " + where
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*simulation.Simulation]{}, fmt.Errorf("failed to count simulations: %w", err)
	}

	// Data
	query := "SELECT " + simSelectCols + " FROM attack_simulations " + where +
		" ORDER BY created_at DESC" +
		fmt.Sprintf(" LIMIT %d OFFSET %d", page.PerPage, (page.Page-1)*page.PerPage)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*simulation.Simulation]{}, fmt.Errorf("failed to list simulations: %w", err)
	}
	defer rows.Close()

	items := make([]*simulation.Simulation, 0)
	for rows.Next() {
		sim, err := r.scanSim(rows.Scan)
		if err != nil {
			return pagination.Result[*simulation.Simulation]{}, fmt.Errorf("failed to scan simulation: %w", err)
		}
		items = append(items, sim)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*simulation.Simulation]{}, fmt.Errorf("failed to iterate simulations: %w", err)
	}

	return pagination.NewResult(items, int64(total), page), nil
}
