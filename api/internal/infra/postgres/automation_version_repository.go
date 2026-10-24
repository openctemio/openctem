package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AutomationVersionRepository stores automation versions (RFC-125 §5). Every
// query carries the tenant.
type AutomationVersionRepository struct {
	db *DB
}

// NewAutomationVersionRepository creates an AutomationVersionRepository.
func NewAutomationVersionRepository(db *DB) *AutomationVersionRepository {
	return &AutomationVersionRepository{db: db}
}

var _ automation.VersionRepository = (*AutomationVersionRepository)(nil)

const automationVersionColumns = `id, tenant_id, automation_id, version, definition, digest, risk_class, status,
	published_by, published_at, approved_by, approved_at, step_up_at, created_at`

// Create stores v with the next number of its automation. The automation
// must belong to v's tenant.
func (r *AutomationVersionRepository) Create(ctx context.Context, v *automation.Version) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertAutomationVersion(ctx, tx, v); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateAndPublish stores v (a pending version) and makes it the published
// version in one transaction: a failure leaves neither a stray pending row
// nor a half-switched automation.
func (r *AutomationVersionRepository) CreateAndPublish(ctx context.Context, v *automation.Version, approvedBy *shared.ID, at time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertAutomationVersion(ctx, tx, v); err != nil {
		return err
	}
	if err := publishAutomationVersion(ctx, tx, v.TenantID, v.AutomationID, v.ID, approvedBy, at); err != nil {
		return err
	}
	return tx.Commit()
}

// RepairBackfilledDigests computes the canonical digest of the versions the
// migration backfilled (digest = 'backfill'), so their stored digest equals
// Definition.Digest like every version published through the API.
func (r *AutomationVersionRepository) RepairBackfilledDigests(ctx context.Context) (int, error) {
	fixes, err := r.backfilledDigestFixes(ctx)
	if err != nil {
		return 0, err
	}
	for _, f := range fixes {
		if _, err := r.db.ExecContext(ctx, `UPDATE automation_versions SET digest = $3 WHERE tenant_id = $1 AND id = $2 AND digest = $4`,
			f.tenant, f.id, f.digest, automation.BackfillDigest); err != nil {
			return 0, fmt.Errorf("store digest of version %s: %w", f.id, err)
		}
	}
	return len(fixes), nil
}

type digestFix struct{ id, tenant, digest string }

func (r *AutomationVersionRepository) backfilledDigestFixes(ctx context.Context) ([]digestFix, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, tenant_id, definition FROM automation_versions WHERE digest = $1`, automation.BackfillDigest)
	if err != nil {
		return nil, fmt.Errorf("list backfilled versions: %w", err)
	}
	defer rows.Close()
	var fixes []digestFix
	for rows.Next() {
		var id, tenant string
		var raw []byte
		if err := rows.Scan(&id, &tenant, &raw); err != nil {
			return nil, err
		}
		var d automation.Definition
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("decode backfilled definition %s: %w", id, err)
		}
		fixes = append(fixes, digestFix{id, tenant, d.Digest()})
	}
	return fixes, rows.Err()
}

func insertAutomationVersion(ctx context.Context, tx *sql.Tx, v *automation.Version) error {
	def, err := json.Marshal(v.Definition)
	if err != nil {
		return fmt.Errorf("marshal definition: %w", err)
	}
	// The number is max+1 under the automation's row lock, so two publishes
	// never race to the same number.
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM automations WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		v.TenantID.String(), v.AutomationID.String()).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("lock automation: %w", err)
	}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO automation_versions (id, tenant_id, automation_id, version, definition, digest, risk_class, status,
		                                 published_by, published_at, approved_by, approved_at, step_up_at, created_at)
		SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		  FROM automation_versions WHERE automation_id = $3
		RETURNING version`,
		v.ID.String(), v.TenantID.String(), v.AutomationID.String(), def, v.Digest, string(v.RiskClass), string(v.Status),
		nullID(v.PublishedBy), v.PublishedAt, nullID(v.ApprovedBy), v.ApprovedAt, v.StepUpAt, v.CreatedAt,
	).Scan(&v.Version)
	if err != nil {
		return fmt.Errorf("create automation version: %w", err)
	}
	return nil
}

// GetByTenantAndID returns one version of the tenant.
func (r *AutomationVersionRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*automation.Version, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+automationVersionColumns+` FROM automation_versions WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	v, err := scanAutomationVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	return v, err
}

// ListByAutomation lists an automation's versions, newest first.
func (r *AutomationVersionRepository) ListByAutomation(ctx context.Context, tenantID, automationID shared.ID, limit int) ([]*automation.Version, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+automationVersionColumns+` FROM automation_versions
		WHERE tenant_id = $1 AND automation_id = $2 ORDER BY version DESC LIMIT $3`,
		tenantID.String(), automationID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list automation versions: %w", err)
	}
	defer rows.Close()
	var out []*automation.Version
	for rows.Next() {
		v, err := scanAutomationVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Publish makes versionID the published version in one transaction.
func (r *AutomationVersionRepository) Publish(ctx context.Context, tenantID, automationID, versionID shared.ID, approvedBy *shared.ID, at time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := publishAutomationVersion(ctx, tx, tenantID, automationID, versionID, approvedBy, at); err != nil {
		return err
	}
	return tx.Commit()
}

func publishAutomationVersion(ctx context.Context, tx *sql.Tx, tenantID, automationID, versionID shared.ID, approvedBy *shared.ID, at time.Time) error {
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT v.status FROM automation_versions v
		JOIN automations a ON a.id = v.automation_id AND a.tenant_id = v.tenant_id
		WHERE v.tenant_id = $1 AND v.automation_id = $2 AND v.id = $3 FOR UPDATE OF a, v`,
		tenantID.String(), automationID.String(), versionID.String()).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("lock version: %w", err)
	}
	switch automation.VersionStatus(status) {
	case automation.VersionPublished:
		return nil // already live
	case automation.VersionPendingApproval:
	default:
		return automation.ErrVersionNotPending
	}
	if _, err := tx.ExecContext(ctx, `UPDATE automation_versions SET status = 'superseded'
		WHERE tenant_id = $1 AND automation_id = $2 AND status = 'published'`, tenantID.String(), automationID.String()); err != nil {
		return fmt.Errorf("supersede published version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE automation_versions SET status = 'retired'
		WHERE tenant_id = $1 AND automation_id = $2 AND status = 'pending_approval' AND id <> $3`,
		tenantID.String(), automationID.String(), versionID.String()); err != nil {
		return fmt.Errorf("retire pending versions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE automation_versions
		SET status = 'published', published_at = COALESCE(published_at, $4), approved_by = $5,
		    approved_at = CASE WHEN $5::uuid IS NULL THEN NULL ELSE $4 END
		WHERE tenant_id = $1 AND automation_id = $2 AND id = $3`,
		tenantID.String(), automationID.String(), versionID.String(), at, nullID(approvedBy)); err != nil {
		return fmt.Errorf("publish version: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE automations SET mode = 'live', published_version_id = $3, updated_at = $4
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), automationID.String(), versionID.String(), at); err != nil {
		return fmt.Errorf("switch automation to live: %w", err)
	}
	return nil
}

func scanAutomationVersion(row interface{ Scan(dest ...any) error }) (*automation.Version, error) {
	v := &automation.Version{}
	var (
		id, tenantID, automationID string
		def                        []byte
		risk, status               string
		publishedBy, approvedBy    sql.NullString
	)
	if err := row.Scan(&id, &tenantID, &automationID, &v.Version, &def, &v.Digest, &risk, &status,
		&publishedBy, &v.PublishedAt, &approvedBy, &v.ApprovedAt, &v.StepUpAt, &v.CreatedAt); err != nil {
		return nil, err
	}
	v.ID, _ = shared.IDFromString(id)
	v.TenantID, _ = shared.IDFromString(tenantID)
	v.AutomationID, _ = shared.IDFromString(automationID)
	v.RiskClass = automation.RiskClass(risk)
	v.Status = automation.VersionStatus(status)
	if err := json.Unmarshal(def, &v.Definition); err != nil {
		return nil, fmt.Errorf("decode version definition: %w", err)
	}
	if publishedBy.Valid {
		pid, _ := shared.IDFromString(publishedBy.String)
		v.PublishedBy = &pid
	}
	if approvedBy.Valid {
		aid, _ := shared.IDFromString(approvedBy.String)
		v.ApprovedBy = &aid
	}
	return v, nil
}
