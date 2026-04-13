package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/pagination"
)

// ControlTestRepository implements simulation.ControlTestRepository.
type ControlTestRepository struct {
	db *DB
}

// NewControlTestRepository creates a new control test repository.
func NewControlTestRepository(db *DB) *ControlTestRepository {
	return &ControlTestRepository{db: db}
}

const ctSelectCols = `id, tenant_id, name, description, framework, control_id,
	control_name, category, test_procedure, expected_result,
	status, last_tested_at, last_tested_by, evidence, notes,
	risk_level, linked_simulation_ids, tags, created_at, updated_at`

func (r *ControlTestRepository) scanCT(scan func(dest ...any) error) (*simulation.ControlTest, error) {
	var (
		id, tenantID, name, description        string
		framework, controlID, controlName, cat string
		testProcedure, expectedResult          sql.NullString
		status                                 string
		lastTestedAt                           sql.NullTime
		lastTestedBy                           sql.NullString
		evidence, notes                        sql.NullString
		riskLevel                              string
		linkedSimIDs                           pq.StringArray
		tags                                   pq.StringArray
		createdAt, updatedAt                   time.Time
	)

	err := scan(
		&id, &tenantID, &name, &description,
		&framework, &controlID, &controlName, &cat,
		&testProcedure, &expectedResult,
		&status, &lastTestedAt, &lastTestedBy,
		&evidence, &notes,
		&riskLevel, &linkedSimIDs, &tags,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, _ := shared.IDFromString(id)
	parsedTenantID, _ := shared.IDFromString(tenantID)

	var testedBy *shared.ID
	if lastTestedBy.Valid {
		uid, err := shared.IDFromString(lastTestedBy.String)
		if err == nil {
			testedBy = &uid
		}
	}

	var testedAt *time.Time
	if lastTestedAt.Valid {
		testedAt = &lastTestedAt.Time
	}

	return simulation.ReconstituteControlTest(
		parsedID, parsedTenantID,
		name, description, framework, controlID, controlName, cat,
		testProcedure.String, expectedResult.String,
		simulation.ControlTestStatus(status),
		testedAt, testedBy,
		evidence.String, notes.String, riskLevel,
		[]string(linkedSimIDs), []string(tags),
		createdAt, updatedAt,
	), nil
}

func (r *ControlTestRepository) Create(ctx context.Context, ct *simulation.ControlTest) error {
	query := `INSERT INTO control_tests (
		id, tenant_id, name, description, framework, control_id,
		control_name, category, test_procedure, expected_result,
		status, last_tested_at, last_tested_by, evidence, notes,
		risk_level, linked_simulation_ids, tags, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`

	var testedBy *string
	if ct.LastTestedBy() != nil {
		s := ct.LastTestedBy().String()
		testedBy = &s
	}

	_, err := r.db.ExecContext(ctx, query,
		ct.ID().String(), ct.TenantID().String(),
		ct.Name(), ct.Description(), ct.Framework(), ct.ControlID(),
		ct.ControlName(), ct.Category(), ct.TestProcedure(), ct.ExpectedResult(),
		string(ct.Status()), ct.LastTestedAt(), testedBy,
		ct.Evidence(), ct.Notes(),
		ct.RiskLevel(), pq.StringArray(ct.LinkedSimulationIDs()),
		pq.StringArray(ct.Tags()),
		ct.CreatedAt(), ct.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create control test: %w", err)
	}
	return nil
}

func (r *ControlTestRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*simulation.ControlTest, error) {
	query := "SELECT " + ctSelectCols + " FROM control_tests WHERE tenant_id = $1 AND id = $2"
	ct, err := r.scanCT(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: control test not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get control test: %w", err)
	}
	return ct, nil
}

func (r *ControlTestRepository) Update(ctx context.Context, ct *simulation.ControlTest) error {
	var testedBy *string
	if ct.LastTestedBy() != nil {
		s := ct.LastTestedBy().String()
		testedBy = &s
	}

	query := `UPDATE control_tests SET
		name=$3, description=$4, framework=$5, control_id=$6,
		control_name=$7, category=$8, test_procedure=$9, expected_result=$10,
		status=$11, last_tested_at=$12, last_tested_by=$13,
		evidence=$14, notes=$15, risk_level=$16,
		linked_simulation_ids=$17, tags=$18, updated_at=$19
		WHERE tenant_id=$1 AND id=$2`

	_, err := r.db.ExecContext(ctx, query,
		ct.TenantID().String(), ct.ID().String(),
		ct.Name(), ct.Description(), ct.Framework(), ct.ControlID(),
		ct.ControlName(), ct.Category(), ct.TestProcedure(), ct.ExpectedResult(),
		string(ct.Status()), ct.LastTestedAt(), testedBy,
		ct.Evidence(), ct.Notes(), ct.RiskLevel(),
		pq.StringArray(ct.LinkedSimulationIDs()), pq.StringArray(ct.Tags()),
		ct.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update control test: %w", err)
	}
	return nil
}

func (r *ControlTestRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM control_tests WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete control test: %w", err)
	}
	return nil
}

func (r *ControlTestRepository) List(ctx context.Context, filter simulation.ControlTestFilter, page pagination.Pagination) (pagination.Result[*simulation.ControlTest], error) {
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, filter.TenantID.String())
		argIdx++
	}
	if filter.Framework != nil && *filter.Framework != "" {
		where += fmt.Sprintf(" AND framework = $%d", argIdx)
		args = append(args, *filter.Framework)
		argIdx++
	}
	if filter.Status != nil && *filter.Status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR control_name ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+*filter.Search+"%")
		argIdx++
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM control_tests "+where, args...).Scan(&total); err != nil {
		return pagination.Result[*simulation.ControlTest]{}, fmt.Errorf("failed to count control tests: %w", err)
	}

	query := "SELECT " + ctSelectCols + " FROM control_tests " + where +
		" ORDER BY framework, control_id" +
		fmt.Sprintf(" LIMIT %d OFFSET %d", page.PerPage, (page.Page-1)*page.PerPage)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*simulation.ControlTest]{}, fmt.Errorf("failed to list control tests: %w", err)
	}
	defer rows.Close()

	items := make([]*simulation.ControlTest, 0)
	for rows.Next() {
		ct, err := r.scanCT(rows.Scan)
		if err != nil {
			return pagination.Result[*simulation.ControlTest]{}, fmt.Errorf("failed to scan control test: %w", err)
		}
		items = append(items, ct)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*simulation.ControlTest]{}, fmt.Errorf("failed to iterate control tests: %w", err)
	}

	return pagination.NewResult(items, int64(total), page), nil
}

func (r *ControlTestRepository) GetStatsByFramework(ctx context.Context, tenantID shared.ID) ([]simulation.FrameworkStats, error) {
	query := `SELECT
		framework,
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE status = 'pass') as passed,
		COUNT(*) FILTER (WHERE status = 'fail') as failed,
		COUNT(*) FILTER (WHERE status = 'partial') as partial,
		COUNT(*) FILTER (WHERE status = 'untested') as untested,
		COUNT(*) FILTER (WHERE status = 'not_applicable') as not_applicable
		FROM control_tests
		WHERE tenant_id = $1
		GROUP BY framework
		ORDER BY framework`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get control test stats: %w", err)
	}
	defer rows.Close()

	var stats []simulation.FrameworkStats
	for rows.Next() {
		var s simulation.FrameworkStats
		if err := rows.Scan(&s.Framework, &s.Total, &s.Passed, &s.Failed, &s.Partial, &s.Untested, &s.NotApplicable); err != nil {
			return nil, fmt.Errorf("failed to scan framework stats: %w", err)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate framework stats: %w", err)
	}

	return stats, nil
}
