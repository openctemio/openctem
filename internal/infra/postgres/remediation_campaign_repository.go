package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// RemediationCampaignRepository implements remediation.CampaignRepository.
type RemediationCampaignRepository struct {
	db *DB
}

// NewRemediationCampaignRepository creates a new repository.
func NewRemediationCampaignRepository(db *DB) *RemediationCampaignRepository {
	return &RemediationCampaignRepository{db: db}
}

const rcSelectCols = `id, tenant_id, name, description, status, priority,
	finding_filter, finding_count, resolved_count, progress,
	risk_score_before, risk_score_after, risk_reduction,
	assigned_to, assigned_team, start_date, due_date, completed_at,
	tags, created_by, created_at, updated_at`

func (r *RemediationCampaignRepository) scanCampaign(scan func(dest ...any) error) (*remediation.Campaign, error) {
	var (
		id, tenantID, name, description string
		status, priority                string
		filterJSON                      []byte
		findingCount, resolvedCount     int
		progress                        float64
		riskBefore, riskAfter, riskRed  sql.NullFloat64
		assignedTo, assignedTeam        sql.NullString
		startDate, dueDate, completedAt sql.NullTime
		tags                            pq.StringArray
		createdByStr                    sql.NullString
		createdAt, updatedAt            time.Time
	)

	err := scan(
		&id, &tenantID, &name, &description, &status, &priority,
		&filterJSON, &findingCount, &resolvedCount, &progress,
		&riskBefore, &riskAfter, &riskRed,
		&assignedTo, &assignedTeam,
		&startDate, &dueDate, &completedAt,
		&tags, &createdByStr, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	parsedID, _ := shared.IDFromString(id)
	parsedTenantID, _ := shared.IDFromString(tenantID)

	var filter map[string]any
	_ = json.Unmarshal(filterJSON, &filter)

	var rb, ra, rr *float64
	if riskBefore.Valid {
		rb = &riskBefore.Float64
	}
	if riskAfter.Valid {
		ra = &riskAfter.Float64
	}
	if riskRed.Valid {
		rr = &riskRed.Float64
	}

	parseOptionalID := func(s sql.NullString) *shared.ID {
		if !s.Valid {
			return nil
		}
		uid, err := shared.IDFromString(s.String)
		if err != nil {
			return nil
		}
		return &uid
	}

	parseOptionalTime := func(t sql.NullTime) *time.Time {
		if !t.Valid {
			return nil
		}
		return &t.Time
	}

	return remediation.ReconstituteCampaign(
		parsedID, parsedTenantID,
		name, description,
		remediation.CampaignStatus(status), remediation.CampaignPriority(priority),
		filter, findingCount, resolvedCount, progress,
		rb, ra, rr,
		parseOptionalID(assignedTo), parseOptionalID(assignedTeam),
		parseOptionalTime(startDate), parseOptionalTime(dueDate), parseOptionalTime(completedAt),
		[]string(tags), parseOptionalID(createdByStr),
		createdAt, updatedAt,
	), nil
}

func (r *RemediationCampaignRepository) Create(ctx context.Context, c *remediation.Campaign) error {
	filterJSON, _ := json.Marshal(c.FindingFilter())

	var assignedTo, assignedTeam, createdBy *string
	if c.AssignedTo() != nil {
		s := c.AssignedTo().String()
		assignedTo = &s
	}
	if c.AssignedTeam() != nil {
		s := c.AssignedTeam().String()
		assignedTeam = &s
	}
	if c.CreatedBy() != nil {
		s := c.CreatedBy().String()
		createdBy = &s
	}

	query := `INSERT INTO remediation_campaigns (
		id, tenant_id, name, description, status, priority,
		finding_filter, finding_count, resolved_count, progress,
		risk_score_before, risk_score_after, risk_reduction,
		assigned_to, assigned_team, start_date, due_date,
		tags, created_by, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`

	_, err := r.db.ExecContext(ctx, query,
		c.ID().String(), c.TenantID().String(),
		c.Name(), c.Description(), string(c.Status()), string(c.Priority()),
		filterJSON, c.FindingCount(), c.ResolvedCount(), c.Progress(),
		c.RiskBefore(), c.RiskAfter(), c.RiskReduction(),
		assignedTo, assignedTeam, c.StartDate(), c.DueDate(),
		pq.StringArray(c.Tags()), createdBy,
		c.CreatedAt(), c.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create remediation campaign: %w", err)
	}
	return nil
}

func (r *RemediationCampaignRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*remediation.Campaign, error) {
	query := "SELECT " + rcSelectCols + " FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2"
	c, err := r.scanCampaign(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, remediation.ErrCampaignNotFound
		}
		return nil, fmt.Errorf("failed to get remediation campaign: %w", err)
	}
	return c, nil
}

func (r *RemediationCampaignRepository) Update(ctx context.Context, c *remediation.Campaign) error {
	filterJSON, _ := json.Marshal(c.FindingFilter())

	var assignedTo, assignedTeam *string
	if c.AssignedTo() != nil {
		s := c.AssignedTo().String()
		assignedTo = &s
	}
	if c.AssignedTeam() != nil {
		s := c.AssignedTeam().String()
		assignedTeam = &s
	}

	query := `UPDATE remediation_campaigns SET
		name=$3, description=$4, status=$5, priority=$6,
		finding_filter=$7, finding_count=$8, resolved_count=$9, progress=$10,
		risk_score_before=$11, risk_score_after=$12, risk_reduction=$13,
		assigned_to=$14, assigned_team=$15, start_date=$16, due_date=$17, completed_at=$18,
		tags=$19, updated_at=$20
		WHERE tenant_id=$1 AND id=$2`

	_, err := r.db.ExecContext(ctx, query,
		c.TenantID().String(), c.ID().String(),
		c.Name(), c.Description(), string(c.Status()), string(c.Priority()),
		filterJSON, c.FindingCount(), c.ResolvedCount(), c.Progress(),
		c.RiskBefore(), c.RiskAfter(), c.RiskReduction(),
		assignedTo, assignedTeam, c.StartDate(), c.DueDate(), c.CompletedAt(),
		pq.StringArray(c.Tags()), c.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update remediation campaign: %w", err)
	}
	return nil
}

func (r *RemediationCampaignRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete remediation campaign: %w", err)
	}
	return nil
}

func (r *RemediationCampaignRepository) List(ctx context.Context, filter remediation.CampaignFilter, page pagination.Pagination) (pagination.Result[*remediation.Campaign], error) {
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if filter.TenantID != nil {
		where += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, filter.TenantID.String())
		argIdx++
	}
	if filter.Status != nil {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, string(*filter.Status))
		argIdx++
	}
	if filter.Priority != nil {
		where += fmt.Sprintf(" AND priority = $%d", argIdx)
		args = append(args, string(*filter.Priority))
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx)
		args = append(args, "%"+escapeLikePattern(*filter.Search)+"%")
		// argIdx not incremented — no further conditions
	}

	var total int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM remediation_campaigns "+where, args...).Scan(&total); err != nil {
		return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to count campaigns: %w", err)
	}

	query := "SELECT " + rcSelectCols + " FROM remediation_campaigns " + where +
		" ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC" +
		fmt.Sprintf(" LIMIT %d OFFSET %d", page.PerPage, (page.Page-1)*page.PerPage)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to list campaigns: %w", err)
	}
	defer rows.Close()

	items := make([]*remediation.Campaign, 0)
	for rows.Next() {
		c, err := r.scanCampaign(rows.Scan)
		if err != nil {
			return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to scan campaign: %w", err)
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to iterate campaigns: %w", err)
	}

	return pagination.NewResult(items, int64(total), page), nil
}
