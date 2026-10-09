package postgres

// Scan window policies and overrides (RFC-067,
// docs/architecture/scan-windows.md; migration 001660). Every statement is
// tenant-scoped.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanWindowPolicyRepository implements scanwindow.Repository.
type ScanWindowPolicyRepository struct {
	db *DB
}

// NewScanWindowPolicyRepository creates a ScanWindowPolicyRepository.
func NewScanWindowPolicyRepository(db *DB) *ScanWindowPolicyRepository {
	return &ScanWindowPolicyRepository{db: db}
}

var _ swdom.Repository = (*ScanWindowPolicyRepository)(nil)

const scanWindowPolicyColumns = `id, tenant_id, name, description, enabled, kind, min_tier, selector, timezone,
	slots, one_offs, grace_minutes, rate_limit_rps, max_concurrent, created_by, created_at, updated_at`

func policyJSON(p *swdom.Policy) (sel, slots, oneOffs []byte, err error) {
	if sel, err = json.Marshal(p.Selector); err != nil {
		return nil, nil, nil, err
	}
	s := p.Slots
	if s == nil {
		s = []swdom.Slot{}
	}
	if slots, err = json.Marshal(s); err != nil {
		return nil, nil, nil, err
	}
	o := p.OneOffs
	if o == nil {
		o = []swdom.OneOff{}
	}
	oneOffs, err = json.Marshal(o)
	return sel, slots, oneOffs, err
}

// Create inserts a policy.
func (r *ScanWindowPolicyRepository) Create(ctx context.Context, p *swdom.Policy) error {
	sel, slots, oneOffs, err := policyJSON(p)
	if err != nil {
		return fmt.Errorf("encode scan window policy: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO scan_window_policies (`+scanWindowPolicyColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		p.ID.String(), p.TenantID.String(), p.Name, p.Description, p.Enabled, string(p.Kind), p.MinTier,
		sel, p.Timezone, slots, oneOffs, p.GraceMinutes, p.RateLimitRPS, p.MaxConcurrent,
		nullIDString(p.CreatedBy), p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create scan window policy: %w", err)
	}
	return nil
}

// Update writes a policy's settings.
func (r *ScanWindowPolicyRepository) Update(ctx context.Context, p *swdom.Policy) error {
	sel, slots, oneOffs, err := policyJSON(p)
	if err != nil {
		return fmt.Errorf("encode scan window policy: %w", err)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_window_policies
		SET name = $3, description = $4, enabled = $5, kind = $6, min_tier = $7, selector = $8, timezone = $9,
		    slots = $10, one_offs = $11, grace_minutes = $12, rate_limit_rps = $13, max_concurrent = $14, updated_at = $15
		WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.Name, p.Description, p.Enabled, string(p.Kind), p.MinTier,
		sel, p.Timezone, slots, oneOffs, p.GraceMinutes, p.RateLimitRPS, p.MaxConcurrent, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update scan window policy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return swdom.ErrNotFound
	}
	return nil
}

// Delete removes a policy of the tenant (its overrides go with it).
func (r *ScanWindowPolicyRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scan_window_policies WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete scan window policy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return swdom.ErrNotFound
	}
	return nil
}

// Count counts the tenant's policies.
func (r *ScanWindowPolicyRepository) Count(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_window_policies WHERE tenant_id = $1`,
		tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count scan window policies: %w", err)
	}
	return n, nil
}

// GetByID returns a policy of the tenant.
func (r *ScanWindowPolicyRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*swdom.Policy, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+scanWindowPolicyColumns+` FROM scan_window_policies
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	p, err := scanWindowPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, swdom.ErrNotFound
	}
	return p, err
}

// List returns the tenant's policies ordered by name.
func (r *ScanWindowPolicyRepository) List(ctx context.Context, tenantID shared.ID, f swdom.Filter) ([]*swdom.Policy, error) {
	q := `SELECT ` + scanWindowPolicyColumns + ` FROM scan_window_policies WHERE tenant_id = $1`
	if f.EnabledOnly {
		q += ` AND enabled`
	}
	q += fmt.Sprintf(` ORDER BY lower(name), id LIMIT %d`, swdom.MaxPoliciesPerTenant*2)
	rows, err := r.db.QueryContext(ctx, q, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scan window policies: %w", err)
	}
	defer rows.Close()
	var out []*swdom.Policy
	for rows.Next() {
		p, err := scanWindowPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type swRowScanner interface {
	Scan(dest ...any) error
}

func scanWindowPolicy(row swRowScanner) (*swdom.Policy, error) {
	var (
		p                      swdom.Policy
		id, tenantID, kind     string
		sel, slots, oneOffs    []byte
		createdBy              sql.NullString
		grace, rate, maxConcur int
	)
	if err := row.Scan(&id, &tenantID, &p.Name, &p.Description, &p.Enabled, &kind, &p.MinTier, &sel, &p.Timezone,
		&slots, &oneOffs, &grace, &rate, &maxConcur, &createdBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if p.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("scan window policy id: %w", err)
	}
	if p.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("scan window policy tenant id: %w", err)
	}
	p.Kind = swdom.Kind(kind)
	p.GraceMinutes, p.RateLimitRPS, p.MaxConcurrent = grace, rate, maxConcur
	if err := json.Unmarshal(sel, &p.Selector); err != nil {
		return nil, fmt.Errorf("scan window policy selector: %w", err)
	}
	if err := json.Unmarshal(slots, &p.Slots); err != nil {
		return nil, fmt.Errorf("scan window policy slots: %w", err)
	}
	if err := json.Unmarshal(oneOffs, &p.OneOffs); err != nil {
		return nil, fmt.Errorf("scan window policy one-offs: %w", err)
	}
	if createdBy.Valid {
		if uid, err := shared.IDFromString(createdBy.String); err == nil {
			p.CreatedBy = &uid
		}
	}
	return &p, nil
}

// CheckReferences returns scanwindow.ErrUnknownReference unless every id of
// the selector is one of the tenant's own asset groups, business units,
// scope entries, scan zones and programs. One statement; the answer is the
// same whether an unknown id exists in another tenant or nowhere.
func (r *ScanWindowPolicyRepository) CheckReferences(ctx context.Context, tenantID shared.ID, sel swdom.Selector) error {
	checks := []struct {
		table string
		ids   []string
	}{
		{"asset_groups", sel.AssetGroupIDs},
		{"business_units", sel.BusinessUnitIDs},
		{"scope_targets", sel.ScopeTargetIDs},
		{"scan_zones", sel.ScanZoneIDs},
		{"bounty_programs", sel.ProgramIDs},
	}
	for _, c := range checks {
		if len(c.ids) == 0 {
			continue
		}
		var n int
		// The table name is one of the constants above, never input.
		q := `SELECT count(DISTINCT id) FROM ` + c.table + ` WHERE tenant_id = $1 AND id = ANY($2::uuid[])`
		if err := r.db.QueryRowContext(ctx, q, tenantID.String(), pq.Array(c.ids)).Scan(&n); err != nil {
			return fmt.Errorf("check scan window selector: %w", err)
		}
		if n != len(c.ids) {
			return swdom.ErrUnknownReference
		}
	}
	return nil
}

// ScanWindowOverrideRepository implements scanwindow.OverrideRepository.
type ScanWindowOverrideRepository struct {
	db *DB
}

// NewScanWindowOverrideRepository creates a ScanWindowOverrideRepository.
func NewScanWindowOverrideRepository(db *DB) *ScanWindowOverrideRepository {
	return &ScanWindowOverrideRepository{db: db}
}

var _ swdom.OverrideRepository = (*ScanWindowOverrideRepository)(nil)

const scanWindowOverrideSelect = `SELECT o.id, o.tenant_id, o.policy_id, o.reason, o.starts_at, o.ends_at,
	o.created_by, o.created_at, o.revoked_at, o.revoked_by, COALESCE(p.name, '')
	FROM scan_window_overrides o
	LEFT JOIN scan_window_policies p ON p.tenant_id = o.tenant_id AND p.id = o.policy_id`

// Create inserts an override. A policy of another tenant fails the
// composite foreign key and is ErrNotFound.
func (r *ScanWindowOverrideRepository) Create(ctx context.Context, o *swdom.Override) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_window_overrides (id, tenant_id, policy_id, reason, starts_at, ends_at, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		o.ID.String(), o.TenantID.String(), nullIDString(o.PolicyID), o.Reason, o.StartsAt, o.EndsAt,
		nullIDString(o.CreatedBy), o.CreatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			return swdom.ErrNotFound
		}
		return fmt.Errorf("create scan window override: %w", err)
	}
	return nil
}

// GetByID returns an override of the tenant.
func (r *ScanWindowOverrideRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*swdom.Override, error) {
	row := r.db.QueryRowContext(ctx, scanWindowOverrideSelect+` WHERE o.tenant_id = $1 AND o.id = $2`,
		tenantID.String(), id.String())
	o, err := scanWindowOverride(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, swdom.ErrOverrideNotFound
	}
	return o, err
}

// ListActive returns the overrides of the tenant active at t.
func (r *ScanWindowOverrideRepository) ListActive(ctx context.Context, tenantID shared.ID, t time.Time) ([]*swdom.Override, error) {
	return r.query(ctx, scanWindowOverrideSelect+`
		WHERE o.tenant_id = $1 AND o.revoked_at IS NULL AND o.starts_at <= $2 AND o.ends_at > $2
		ORDER BY o.ends_at`, tenantID.String(), t.UTC())
}

// ListRecent returns the tenant's most recent overrides, newest first.
func (r *ScanWindowOverrideRepository) ListRecent(ctx context.Context, tenantID shared.ID, limit int) ([]*swdom.Override, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return r.query(ctx, scanWindowOverrideSelect+`
		WHERE o.tenant_id = $1 ORDER BY o.created_at DESC, o.id LIMIT $2`, tenantID.String(), limit)
}

// Revoke ends an active override of the tenant.
func (r *ScanWindowOverrideRepository) Revoke(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_window_overrides SET revoked_at = $3, revoked_by = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL AND ends_at > $3`,
		tenantID.String(), id.String(), at.UTC(), by.String())
	if err != nil {
		return fmt.Errorf("revoke scan window override: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return swdom.ErrOverrideNotFound
	}
	return nil
}

func (r *ScanWindowOverrideRepository) query(ctx context.Context, q string, args ...any) ([]*swdom.Override, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list scan window overrides: %w", err)
	}
	defer rows.Close()
	var out []*swdom.Override
	for rows.Next() {
		o, err := scanWindowOverride(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func scanWindowOverride(row swRowScanner) (*swdom.Override, error) {
	var (
		o                             swdom.Override
		id, tenantID                  string
		policyID, createdBy, revokedB sql.NullString
		revokedAt                     sql.NullTime
	)
	if err := row.Scan(&id, &tenantID, &policyID, &o.Reason, &o.StartsAt, &o.EndsAt, &createdBy, &o.CreatedAt,
		&revokedAt, &revokedB, &o.PolicyName); err != nil {
		return nil, err
	}
	var err error
	if o.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("scan window override id: %w", err)
	}
	if o.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("scan window override tenant id: %w", err)
	}
	o.PolicyID = optionalID(policyID)
	o.CreatedBy = optionalID(createdBy)
	o.RevokedBy = optionalID(revokedB)
	o.RevokedAt = nullTimeValue(revokedAt)
	o.StartsAt, o.EndsAt, o.CreatedAt = o.StartsAt.UTC(), o.EndsAt.UTC(), o.CreatedAt.UTC()
	return &o, nil
}

// TenantsWithWindows lists the tenants that have an enabled scan window
// policy or a bug-bounty program with testing windows (the closing-window
// controller looks only at their running work).
func (r *ScanWindowPolicyRepository) TenantsWithWindows(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id FROM scan_window_policies WHERE enabled
		UNION
		SELECT tenant_id FROM bounty_programs
		WHERE jsonb_typeof(rules->'testing_windows') = 'array' AND jsonb_array_length(rules->'testing_windows') > 0`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with scan windows: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if tid, err := shared.IDFromString(id); err == nil {
			out = append(out, tid)
		}
	}
	return out, rows.Err()
}
