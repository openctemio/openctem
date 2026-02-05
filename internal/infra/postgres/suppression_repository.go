package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
)

// SuppressionRepository handles suppression rule persistence.
type SuppressionRepository struct {
	db *DB
}

// NewSuppressionRepository creates a new SuppressionRepository.
func NewSuppressionRepository(db *DB) *SuppressionRepository {
	return &SuppressionRepository{db: db}
}

// Save persists a suppression rule.
func (r *SuppressionRepository) Save(ctx context.Context, rule *suppression.Rule) error {
	query := `
		INSERT INTO suppression_rules (
			id, tenant_id, rule_id, tool_name, path_pattern, asset_id,
			name, description, suppression_type, status,
			requested_by, requested_at, approved_by, approved_at,
			rejected_by, rejected_at, rejection_reason, expires_at,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (id) DO UPDATE SET
			rule_id = EXCLUDED.rule_id,
			tool_name = EXCLUDED.tool_name,
			path_pattern = EXCLUDED.path_pattern,
			asset_id = EXCLUDED.asset_id,
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			suppression_type = EXCLUDED.suppression_type,
			status = EXCLUDED.status,
			approved_by = EXCLUDED.approved_by,
			approved_at = EXCLUDED.approved_at,
			rejected_by = EXCLUDED.rejected_by,
			rejected_at = EXCLUDED.rejected_at,
			rejection_reason = EXCLUDED.rejection_reason,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at
	`

	_, err := r.db.ExecContext(ctx, query,
		rule.ID().String(),
		rule.TenantID().String(),
		nullString(rule.RuleID()),
		nullString(rule.ToolName()),
		nullString(rule.PathPattern()),
		nullIDPtr(rule.AssetID()),
		rule.Name(),
		nullString(rule.Description()),
		string(rule.SuppressionType()),
		string(rule.Status()),
		rule.RequestedBy().String(),
		rule.RequestedAt(),
		nullIDPtr(rule.ApprovedBy()),
		nullTime(rule.ApprovedAt()),
		nullIDPtr(rule.RejectedBy()),
		nullTime(rule.RejectedAt()),
		nullString(rule.RejectionReason()),
		nullTime(rule.ExpiresAt()),
		rule.CreatedAt(),
		rule.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to save suppression rule: %w", err)
	}

	return nil
}

// FindByID retrieves a suppression rule by ID.
func (r *SuppressionRepository) FindByID(ctx context.Context, tenantID, id shared.ID) (*suppression.Rule, error) {
	query := r.selectQuery() + " WHERE sr.tenant_id = $1 AND sr.id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanRule(row)
}

// Delete removes a suppression rule.
func (r *SuppressionRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM suppression_rules WHERE tenant_id = $1 AND id = $2`
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete suppression rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return suppression.ErrRuleNotFound
	}

	return nil
}

// FindByTenant retrieves suppression rules for a tenant with filters.
func (r *SuppressionRepository) FindByTenant(ctx context.Context, tenantID shared.ID, filter suppression.RuleFilter) ([]*suppression.Rule, error) {
	query := r.selectQuery() + " WHERE sr.tenant_id = $1"
	args := []any{tenantID.String()}
	argIdx := 2

	if filter.Status != nil {
		query += fmt.Sprintf(" AND sr.status = $%d", argIdx)
		args = append(args, string(*filter.Status))
		argIdx++
	}

	if filter.SuppressionType != nil {
		query += fmt.Sprintf(" AND sr.suppression_type = $%d", argIdx)
		args = append(args, string(*filter.SuppressionType))
		argIdx++
	}

	if filter.ToolName != nil {
		query += fmt.Sprintf(" AND sr.tool_name = $%d", argIdx)
		args = append(args, *filter.ToolName)
		argIdx++
	}

	if filter.AssetID != nil {
		query += fmt.Sprintf(" AND sr.asset_id = $%d", argIdx)
		args = append(args, filter.AssetID.String())
		argIdx++
	}

	if filter.RequestedBy != nil {
		query += fmt.Sprintf(" AND sr.requested_by = $%d", argIdx)
		args = append(args, filter.RequestedBy.String())
		argIdx++
	}

	if !filter.IncludeExpired {
		query += " AND (sr.expires_at IS NULL OR sr.expires_at > NOW())"
	}

	query += " ORDER BY sr.created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query suppression rules: %w", err)
	}
	defer rows.Close()

	return r.scanRules(rows)
}

// FindActiveByTenant retrieves all active (approved, not expired) rules.
func (r *SuppressionRepository) FindActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	query := r.selectQuery() + `
		WHERE sr.tenant_id = $1
		AND sr.status = 'approved'
		AND (sr.expires_at IS NULL OR sr.expires_at > NOW())
		ORDER BY sr.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query active suppression rules: %w", err)
	}
	defer rows.Close()

	return r.scanRules(rows)
}

// FindPendingByTenant retrieves all pending rules.
func (r *SuppressionRepository) FindPendingByTenant(ctx context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	query := r.selectQuery() + `
		WHERE sr.tenant_id = $1
		AND sr.status = 'pending'
		ORDER BY sr.created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query pending suppression rules: %w", err)
	}
	defer rows.Close()

	return r.scanRules(rows)
}

// FindMatchingRules finds rules that match a given finding.
func (r *SuppressionRepository) FindMatchingRules(ctx context.Context, tenantID shared.ID, match suppression.FindingMatch) ([]*suppression.Rule, error) {
	// Get all active rules and filter in Go for complex matching
	rules, err := r.FindActiveByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var matchingRules []*suppression.Rule
	for _, rule := range rules {
		if rule.Matches(match) {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, nil
}

// ExpireRules marks expired rules as expired.
func (r *SuppressionRepository) ExpireRules(ctx context.Context) (int64, error) {
	query := `
		UPDATE suppression_rules
		SET status = 'expired', updated_at = NOW()
		WHERE status = 'approved'
		AND expires_at IS NOT NULL
		AND expires_at < NOW()
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to expire suppression rules: %w", err)
	}

	return result.RowsAffected()
}

// RecordSuppression records that a finding was suppressed by a rule.
func (r *SuppressionRepository) RecordSuppression(ctx context.Context, findingID, ruleID shared.ID, appliedBy string) error {
	query := `
		INSERT INTO finding_suppressions (finding_id, suppression_rule_id, applied_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (finding_id, suppression_rule_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, findingID.String(), ruleID.String(), appliedBy)
	if err != nil {
		return fmt.Errorf("failed to record finding suppression: %w", err)
	}

	return nil
}

// FindSuppressionsByFinding retrieves suppressions for a finding.
func (r *SuppressionRepository) FindSuppressionsByFinding(ctx context.Context, findingID shared.ID) ([]*suppression.FindingSuppression, error) {
	query := `
		SELECT id, finding_id, suppression_rule_id, applied_at, applied_by
		FROM finding_suppressions
		WHERE finding_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, findingID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query finding suppressions: %w", err)
	}
	defer rows.Close()

	var suppressions []*suppression.FindingSuppression
	for rows.Next() {
		var (
			id        string
			findingID string
			ruleID    string
			appliedAt time.Time
			appliedBy string
		)

		if err := rows.Scan(&id, &findingID, &ruleID, &appliedAt, &appliedBy); err != nil {
			return nil, fmt.Errorf("failed to scan finding suppression: %w", err)
		}

		idParsed, _ := shared.IDFromString(id)
		findingIDParsed, _ := shared.IDFromString(findingID)
		ruleIDParsed, _ := shared.IDFromString(ruleID)

		suppressions = append(suppressions, &suppression.FindingSuppression{
			ID:                idParsed,
			FindingID:         findingIDParsed,
			SuppressionRuleID: ruleIDParsed,
			AppliedAt:         appliedAt.Format(time.RFC3339),
			AppliedBy:         appliedBy,
		})
	}

	return suppressions, rows.Err()
}

// RemoveSuppression removes a suppression from a finding.
func (r *SuppressionRepository) RemoveSuppression(ctx context.Context, findingID, ruleID shared.ID) error {
	query := `DELETE FROM finding_suppressions WHERE finding_id = $1 AND suppression_rule_id = $2`
	_, err := r.db.ExecContext(ctx, query, findingID.String(), ruleID.String())
	if err != nil {
		return fmt.Errorf("failed to remove finding suppression: %w", err)
	}
	return nil
}

// RecordAudit records an audit log entry for a suppression rule.
func (r *SuppressionRepository) RecordAudit(ctx context.Context, ruleID shared.ID, action string, actorID *shared.ID, details map[string]any) error {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("failed to marshal audit details: %w", err)
	}

	query := `
		INSERT INTO suppression_rule_audit (suppression_rule_id, action, actor_id, details)
		VALUES ($1, $2, $3, $4)
	`

	_, err = r.db.ExecContext(ctx, query, ruleID.String(), action, nullIDPtr(actorID), detailsJSON)
	if err != nil {
		return fmt.Errorf("failed to record audit: %w", err)
	}

	return nil
}

// selectQuery returns the base SELECT query for suppression rules.
func (r *SuppressionRepository) selectQuery() string {
	return `
		SELECT
			sr.id, sr.tenant_id, sr.rule_id, sr.tool_name, sr.path_pattern, sr.asset_id,
			sr.name, sr.description, sr.suppression_type, sr.status,
			sr.requested_by, sr.requested_at, sr.approved_by, sr.approved_at,
			sr.rejected_by, sr.rejected_at, sr.rejection_reason, sr.expires_at,
			sr.created_at, sr.updated_at
		FROM suppression_rules sr
	`
}

// scanRule scans a single row into a Rule.
func (r *SuppressionRepository) scanRule(row *sql.Row) (*suppression.Rule, error) {
	var (
		id              string
		tenantID        string
		ruleID          sql.NullString
		toolName        sql.NullString
		pathPattern     sql.NullString
		assetID         sql.NullString
		name            string
		description     sql.NullString
		suppressionType string
		status          string
		requestedBy     string
		requestedAt     time.Time
		approvedBy      sql.NullString
		approvedAt      sql.NullTime
		rejectedBy      sql.NullString
		rejectedAt      sql.NullTime
		rejectionReason sql.NullString
		expiresAt       sql.NullTime
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := row.Scan(
		&id, &tenantID, &ruleID, &toolName, &pathPattern, &assetID,
		&name, &description, &suppressionType, &status,
		&requestedBy, &requestedAt, &approvedBy, &approvedAt,
		&rejectedBy, &rejectedAt, &rejectionReason, &expiresAt,
		&createdAt, &updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan suppression rule: %w", err)
	}

	return r.buildRule(
		id, tenantID, ruleID, toolName, pathPattern, assetID,
		name, description, suppressionType, status,
		requestedBy, requestedAt, approvedBy, approvedAt,
		rejectedBy, rejectedAt, rejectionReason, expiresAt,
		createdAt, updatedAt,
	), nil
}

// scanRules scans multiple rows into Rules.
func (r *SuppressionRepository) scanRules(rows *sql.Rows) ([]*suppression.Rule, error) {
	var rules []*suppression.Rule

	for rows.Next() {
		var (
			id              string
			tenantID        string
			ruleID          sql.NullString
			toolName        sql.NullString
			pathPattern     sql.NullString
			assetID         sql.NullString
			name            string
			description     sql.NullString
			suppressionType string
			status          string
			requestedBy     string
			requestedAt     time.Time
			approvedBy      sql.NullString
			approvedAt      sql.NullTime
			rejectedBy      sql.NullString
			rejectedAt      sql.NullTime
			rejectionReason sql.NullString
			expiresAt       sql.NullTime
			createdAt       time.Time
			updatedAt       time.Time
		)

		err := rows.Scan(
			&id, &tenantID, &ruleID, &toolName, &pathPattern, &assetID,
			&name, &description, &suppressionType, &status,
			&requestedBy, &requestedAt, &approvedBy, &approvedAt,
			&rejectedBy, &rejectedAt, &rejectionReason, &expiresAt,
			&createdAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan suppression rule: %w", err)
		}

		rules = append(rules, r.buildRule(
			id, tenantID, ruleID, toolName, pathPattern, assetID,
			name, description, suppressionType, status,
			requestedBy, requestedAt, approvedBy, approvedAt,
			rejectedBy, rejectedAt, rejectionReason, expiresAt,
			createdAt, updatedAt,
		))
	}

	return rules, rows.Err()
}

// buildRule constructs a Rule from scanned values.
func (r *SuppressionRepository) buildRule(
	id, tenantID string,
	ruleID, toolName, pathPattern, assetID sql.NullString,
	name string, description sql.NullString,
	suppressionType, status string,
	requestedBy string, requestedAt time.Time,
	approvedBy sql.NullString, approvedAt sql.NullTime,
	rejectedBy sql.NullString, rejectedAt sql.NullTime,
	rejectionReason sql.NullString, expiresAt sql.NullTime,
	createdAt, updatedAt time.Time,
) *suppression.Rule {
	idParsed, _ := shared.IDFromString(id)
	tenantIDParsed, _ := shared.IDFromString(tenantID)
	requestedByParsed, _ := shared.IDFromString(requestedBy)

	data := suppression.RuleData{
		ID:              idParsed,
		TenantID:        tenantIDParsed,
		RuleID:          ruleID.String,
		ToolName:        toolName.String,
		PathPattern:     pathPattern.String,
		Name:            name,
		Description:     description.String,
		SuppressionType: suppression.SuppressionType(suppressionType),
		Status:          suppression.RuleStatus(status),
		RequestedBy:     requestedByParsed,
		RequestedAt:     requestedAt,
		RejectionReason: rejectionReason.String,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}

	if assetID.Valid {
		assetIDParsed, _ := shared.IDFromString(assetID.String)
		data.AssetID = &assetIDParsed
	}

	if approvedBy.Valid {
		approvedByParsed, _ := shared.IDFromString(approvedBy.String)
		data.ApprovedBy = &approvedByParsed
	}
	if approvedAt.Valid {
		data.ApprovedAt = &approvedAt.Time
	}

	if rejectedBy.Valid {
		rejectedByParsed, _ := shared.IDFromString(rejectedBy.String)
		data.RejectedBy = &rejectedByParsed
	}
	if rejectedAt.Valid {
		data.RejectedAt = &rejectedAt.Time
	}

	if expiresAt.Valid {
		data.ExpiresAt = &expiresAt.Time
	}

	return suppression.ReconstituteRule(data)
}
