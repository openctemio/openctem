package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// --- EPSS Adapter (implements app.EPSSRepository) ---

// EPSSAdapter wraps the existing EPSS repository to implement the priority service interface.
type EPSSAdapter struct {
	repo *EPSSRepository
}

// NewEPSSAdapter creates a new adapter.
func NewEPSSAdapter(repo *EPSSRepository) *EPSSAdapter {
	return &EPSSAdapter{repo: repo}
}

func (a *EPSSAdapter) GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]app.EPSSData, error) {
	scores, err := a.repo.GetByCVEIDs(ctx, cveIDs)
	if err != nil {
		return nil, err
	}
	result := make(map[string]app.EPSSData, len(scores))
	for _, s := range scores {
		result[s.CVEID()] = app.EPSSData{
			Score:      s.Score(),
			Percentile: s.Percentile(),
		}
	}
	return result, nil
}

// --- KEV Adapter (implements app.KEVRepository) ---

// KEVAdapter wraps the existing KEV repository.
type KEVAdapter struct {
	repo *KEVRepository
}

// NewKEVAdapter creates a new adapter.
func NewKEVAdapter(repo *KEVRepository) *KEVAdapter {
	return &KEVAdapter{repo: repo}
}

func (a *KEVAdapter) GetByCVEIDs(ctx context.Context, cveIDs []string) (map[string]app.KEVData, error) {
	entries, err := a.repo.GetByCVEIDs(ctx, cveIDs)
	if err != nil {
		return nil, err
	}
	result := make(map[string]app.KEVData, len(entries))
	for _, e := range entries {
		d := app.KEVData{
			Ransomware: e.KnownRansomwareCampaignUse(),
		}
		if dueDate := e.DueDate(); !dueDate.IsZero() {
			d.DueDate = &dueDate
		}
		result[e.CVEID()] = d
	}
	return result, nil
}

// --- Priority Rule Repository (implements app.PriorityRuleRepository) ---

// PriorityRuleRepository handles priority override rules.
type PriorityRuleRepository struct {
	db *DB
}

// NewPriorityRuleRepository creates a new repository.
func NewPriorityRuleRepository(db *DB) *PriorityRuleRepository {
	return &PriorityRuleRepository{db: db}
}

func (r *PriorityRuleRepository) ListActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*vulnerability.PriorityOverrideRule, error) {
	query := `
		SELECT id, tenant_id, name, description, priority_class, conditions,
			is_active, evaluation_order, created_by, updated_by, created_at, updated_at
		FROM priority_override_rules
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY evaluation_order DESC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list priority rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []*vulnerability.PriorityOverrideRule
	for rows.Next() {
		var (
			id, tid                        string
			name, description, pc          string
			conditionsJSON                 []byte
			isActive                       bool
			evalOrder                      int
			createdBy, updatedBy           sql.NullString
			createdAt, updatedAt           time.Time
		)
		if err := rows.Scan(&id, &tid, &name, &description, &pc, &conditionsJSON,
			&isActive, &evalOrder, &createdBy, &updatedBy, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan priority rule: %w", err)
		}

		var conditions []vulnerability.RuleCondition
		if err := json.Unmarshal(conditionsJSON, &conditions); err != nil {
			continue // skip corrupted rules
		}

		ruleID, _ := shared.IDFromString(id)
		tenID, _ := shared.IDFromString(tid)
		priorityClass, _ := vulnerability.ParsePriorityClass(pc)

		data := vulnerability.PriorityOverrideRuleData{
			ID:              ruleID,
			TenantID:        tenID,
			Name:            name,
			Description:     description,
			PriorityClass:   priorityClass,
			Conditions:      conditions,
			IsActive:        isActive,
			EvaluationOrder: evalOrder,
			CreatedAt:       createdAt,
			UpdatedAt:       updatedAt,
		}
		if createdBy.Valid {
			cbID, _ := shared.IDFromString(createdBy.String)
			data.CreatedBy = &cbID
		}

		rules = append(rules, vulnerability.ReconstitutePriorityOverrideRule(data))
	}

	return rules, nil
}

// Create inserts a new priority override rule.
func (r *PriorityRuleRepository) Create(ctx context.Context, rule *vulnerability.PriorityOverrideRule) error {
	condJSON, err := json.Marshal(rule.Conditions())
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}

	query := `
		INSERT INTO priority_override_rules (id, tenant_id, name, description, priority_class,
			conditions, is_active, evaluation_order, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	var createdBy sql.NullString
	// CreatedBy not exposed via getter yet — use nil
	_, err = r.db.ExecContext(ctx, query,
		rule.ID().String(), rule.TenantID().String(), rule.Name(), rule.Description(),
		string(rule.PriorityClass()), condJSON, rule.IsActive(), rule.EvaluationOrder(),
		createdBy, rule.CreatedAt(), rule.UpdatedAt(),
	)
	return err
}

// Delete removes a priority override rule.
func (r *PriorityRuleRepository) Delete(ctx context.Context, tenantID, ruleID shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM priority_override_rules WHERE id = $1 AND tenant_id = $2",
		ruleID.String(), tenantID.String(),
	)
	return err
}

// --- Priority Audit Repository (implements app.PriorityAuditRepository) ---

// PriorityAuditRepository logs priority class changes.
type PriorityAuditRepository struct {
	db *DB
}

// NewPriorityAuditRepository creates a new repository.
func NewPriorityAuditRepository(db *DB) *PriorityAuditRepository {
	return &PriorityAuditRepository{db: db}
}

// CountOlderThan reports how many priority audit rows are older than before.
// Used by the retention controller to report work-to-do before deleting.
func (r *PriorityAuditRepository) CountOlderThan(ctx context.Context, before time.Time) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM priority_class_audit_log WHERE created_at < $1`,
		before,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count old priority audit rows: %w", err)
	}
	return count, nil
}

// DeleteOlderThan removes priority audit rows older than before, across all
// tenants. Intended for the platform retention controller (F-13). Per-tenant
// retention can be layered later via DeleteOlderThanForTenant when tenant
// policy configuration exists.
func (r *PriorityAuditRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM priority_class_audit_log WHERE created_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete old priority audit rows: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

func (r *PriorityAuditRepository) LogChange(ctx context.Context, entry app.PriorityAuditEntry) error {
	query := `
		INSERT INTO priority_class_audit_log (tenant_id, finding_id, previous_class, new_class,
			reason, source, rule_id, actor_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
	`
	var prevClass sql.NullString
	if entry.PreviousClass != nil {
		prevClass = sql.NullString{String: string(*entry.PreviousClass), Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		entry.TenantID.String(), entry.FindingID.String(),
		prevClass, string(entry.NewClass),
		entry.Reason, entry.Source,
		nullIDPtr(entry.RuleID), nullIDPtr(entry.ActorID),
	)
	return err
}

// CompensatingControlLookupRepo provides batch effective control lookups.
type CompensatingControlLookupRepo struct {
	db *sql.DB
}

// NewCompensatingControlLookupRepo creates a new lookup adapter.
func NewCompensatingControlLookupRepo(db *sql.DB) *CompensatingControlLookupRepo {
	return &CompensatingControlLookupRepo{db: db}
}

// GetEffectiveForAssets returns max reduction_factor per asset with active,
// tested-passing, non-expired controls.
func (r *CompensatingControlLookupRepo) GetEffectiveForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]float64, error) {
	if len(assetIDs) == 0 {
		return map[shared.ID]float64{}, nil
	}

	idStrings := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		idStrings[i] = id.String()
	}

	query := `
		SELECT cca.asset_id, MAX(cc.reduction_factor)
		FROM compensating_controls cc
		JOIN compensating_control_assets cca ON cca.control_id = cc.id
		WHERE cc.tenant_id = $1
		  AND cca.asset_id = ANY($2)
		  AND cc.status = 'active'
		  AND (cc.test_result IS NULL OR cc.test_result != 'fail')
		  AND (cc.expires_at IS NULL OR cc.expires_at > NOW())
		GROUP BY cca.asset_id
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(idStrings))
	if err != nil {
		return nil, fmt.Errorf("compensating controls lookup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[shared.ID]float64)
	for rows.Next() {
		var aidStr string
		var factor float64
		if err := rows.Scan(&aidStr, &factor); err != nil {
			continue
		}
		if aid, err := shared.IDFromString(aidStr); err == nil {
			result[aid] = factor
		}
	}
	return result, nil
}

// Verify interface compliance
var (
	_ app.EPSSRepository              = (*EPSSAdapter)(nil)
	_ app.KEVRepository               = (*KEVAdapter)(nil)
	_ app.PriorityRuleRepository      = (*PriorityRuleRepository)(nil)
	_ app.PriorityAuditRepository     = (*PriorityAuditRepository)(nil)
	_ app.CompensatingControlLookup   = (*CompensatingControlLookupRepo)(nil)
)
