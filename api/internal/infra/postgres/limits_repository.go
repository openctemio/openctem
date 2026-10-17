package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// LimitsRepository stores per-organization limits (tenant_limits), feature
// denies (tenant_feature_denies), the read-only grace of lost features
// (tenant_module_grace), the self-service defaults (platform_settings
// 'self_service_default_limits'), and counts usage
// (docs/architecture/limits.md). Every per-organization query is scoped by
// tenant_id.
type LimitsRepository struct {
	db *DB
}

// NewLimitsRepository creates the repository.
func NewLimitsRepository(db *DB) *LimitsRepository { return &LimitsRepository{db: db} }

var _ limits.Repository = (*LimitsRepository)(nil)

// GetSelfServiceDefaults returns the stored defaults, or shared.ErrNotFound.
func (r *LimitsRepository) GetSelfServiceDefaults(ctx context.Context) (limits.Limits, int, error) {
	var (
		raw     []byte
		version int
	)
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		limits.SelfServiceDefaultsKey).Scan(&raw, &version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, shared.ErrNotFound
		}
		return nil, 0, fmt.Errorf("get self-service default limits: %w", err)
	}
	l, err := limits.DecodeLimits(raw)
	if err != nil {
		return nil, 0, err
	}
	return l, version, nil
}

// SaveSelfServiceDefaults stores the defaults when the stored version is
// expected (0: nothing stored yet).
func (r *LimitsRepository) SaveSelfServiceDefaults(ctx context.Context, l limits.Limits, expectedVersion int, by *shared.ID, at time.Time) (int, error) {
	raw, err := l.Encode()
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, limits.SelfServiceDefaultsKey, raw, nullID(by), at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, limits.SelfServiceDefaultsKey, raw, nullID(by), at, expectedVersion).Scan(&version)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("%w: the self-service defaults were changed by someone else; reload and try again", shared.ErrConflict)
		}
		return 0, fmt.Errorf("save self-service default limits: %w", err)
	}
	return version, nil
}

// ListLimits returns the organization's limits of one origin.
func (r *LimitsRepository) ListLimits(ctx context.Context, tenantID shared.ID, origin limits.Origin) ([]limits.Limit, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT limit_key, value, reason, expires_at, set_by, set_at
		  FROM tenant_limits WHERE tenant_id = $1 AND origin = $2 ORDER BY limit_key`, tenantID.String(), string(origin))
	if err != nil {
		return nil, fmt.Errorf("list limits: %w", err)
	}
	defer rows.Close()
	out := []limits.Limit{}
	for rows.Next() {
		var (
			l       limits.Limit
			key     string
			expires sql.NullTime
			setBy   sql.NullString
		)
		if err := rows.Scan(&key, &l.Value, &l.Reason, &expires, &setBy, &l.SetAt); err != nil {
			return nil, fmt.Errorf("scan limit: %w", err)
		}
		l.TenantID, l.Key, l.Origin, l.ExpiresAt, l.SetBy = tenantID, limits.Key(key), origin, nullTimeValue(expires), parseNullID(setBy)
		out = append(out, l)
	}
	return out, rows.Err()
}

const upsertLimitSQL = `
	INSERT INTO tenant_limits (tenant_id, limit_key, value, reason, expires_at, set_by, set_at, origin)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (tenant_id, limit_key, origin) DO UPDATE SET
	  value = EXCLUDED.value, reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
	  set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at`

func limitArgs(l limits.Limit) []any {
	return []any{l.TenantID.String(), string(l.Key), l.Value, l.Reason, nullTimePtr(l.ExpiresAt), nullID(l.SetBy), l.SetAt, string(l.Origin)}
}

// SetLimit creates or replaces one limit.
func (r *LimitsRepository) SetLimit(ctx context.Context, l limits.Limit) error {
	if _, err := r.db.ExecContext(ctx, upsertLimitSQL, limitArgs(l)...); err != nil {
		return fmt.Errorf("set limit: %w", err)
	}
	return nil
}

// DeleteLimit removes one limit; shared.ErrNotFound when there is none.
func (r *LimitsRepository) DeleteLimit(ctx context.Context, tenantID shared.ID, key limits.Key, origin limits.Origin) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_limits WHERE tenant_id = $1 AND limit_key = $2 AND origin = $3`,
		tenantID.String(), string(key), string(origin))
	if err != nil {
		return fmt.Errorf("delete limit: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ListDenies returns the organization's feature denies of one origin.
func (r *LimitsRepository) ListDenies(ctx context.Context, tenantID shared.ID, origin limits.Origin) ([]limits.FeatureDeny, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT feature, reason, expires_at, set_by, set_at
		  FROM tenant_feature_denies WHERE tenant_id = $1 AND origin = $2 ORDER BY feature`, tenantID.String(), string(origin))
	if err != nil {
		return nil, fmt.Errorf("list feature denies: %w", err)
	}
	defer rows.Close()
	out := []limits.FeatureDeny{}
	for rows.Next() {
		var (
			d       limits.FeatureDeny
			expires sql.NullTime
			setBy   sql.NullString
		)
		if err := rows.Scan(&d.Feature, &d.Reason, &expires, &setBy, &d.SetAt); err != nil {
			return nil, fmt.Errorf("scan feature deny: %w", err)
		}
		d.TenantID, d.Origin, d.ExpiresAt, d.SetBy = tenantID, origin, nullTimeValue(expires), parseNullID(setBy)
		out = append(out, d)
	}
	return out, rows.Err()
}

const upsertDenySQL = `
	INSERT INTO tenant_feature_denies (tenant_id, feature, reason, expires_at, set_by, set_at, origin)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	ON CONFLICT (tenant_id, feature, origin) DO UPDATE SET
	  reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at, set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at`

func denyArgs(d limits.FeatureDeny) []any {
	return []any{d.TenantID.String(), d.Feature, d.Reason, nullTimePtr(d.ExpiresAt), nullID(d.SetBy), d.SetAt, string(d.Origin)}
}

// SetDeny creates or replaces one feature deny.
func (r *LimitsRepository) SetDeny(ctx context.Context, d limits.FeatureDeny) error {
	if _, err := r.db.ExecContext(ctx, upsertDenySQL, denyArgs(d)...); err != nil {
		return fmt.Errorf("set feature deny: %w", err)
	}
	return nil
}

// DeleteDeny removes one feature deny; shared.ErrNotFound when there is none.
func (r *LimitsRepository) DeleteDeny(ctx context.Context, tenantID shared.ID, feature string, origin limits.Origin) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_feature_denies WHERE tenant_id = $1 AND feature = $2 AND origin = $3`,
		tenantID.String(), feature, string(origin))
	if err != nil {
		return fmt.Errorf("delete feature deny: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ReplaceOrigin replaces every limit and deny of one origin for the
// organization in one transaction. Rows of the other origin are untouched.
func (r *LimitsRepository) ReplaceOrigin(ctx context.Context, tenantID shared.ID, origin limits.Origin, lims []limits.Limit, denies []limits.FeatureDeny) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenant_limits WHERE tenant_id = $1 AND origin = $2`, tenantID.String(), string(origin)); err != nil {
			return fmt.Errorf("clear limits: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenant_feature_denies WHERE tenant_id = $1 AND origin = $2`, tenantID.String(), string(origin)); err != nil {
			return fmt.Errorf("clear feature denies: %w", err)
		}
		for _, l := range lims {
			if l.TenantID != tenantID || l.Origin != origin {
				return fmt.Errorf("%w: limit for another organization or origin", shared.ErrValidation)
			}
			if _, err := tx.ExecContext(ctx, upsertLimitSQL, limitArgs(l)...); err != nil {
				return fmt.Errorf("write limit: %w", err)
			}
		}
		for _, d := range denies {
			if d.TenantID != tenantID || d.Origin != origin {
				return fmt.Errorf("%w: deny for another organization or origin", shared.ErrValidation)
			}
			if _, err := tx.ExecContext(ctx, upsertDenySQL, denyArgs(d)...); err != nil {
				return fmt.Errorf("write feature deny: %w", err)
			}
		}
		return nil
	})
}

// Usage counts what the organization uses, one query, every count scoped
// by tenant_id. A seat is every member who is not offboarded: a suspended
// member, or a sign-up awaiting approval, still holds one. Findings are
// counted (a second query) only when withFindings is set, that is while a
// findings limit applies: the count runs over the largest table, so an
// organization without that limit never pays for it.
func (r *LimitsRepository) Usage(ctx context.Context, tenantID shared.ID, withFindings bool) (map[limits.Key]int, error) {
	var seats, assets, sensors, keys, trusts, invites, subStatuses, schemes int
	err := r.db.QueryRowContext(ctx, `
		SELECT
		  (SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND status <> 'offboarded'),
		  (SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL AND status <> 'archived'),
		  (SELECT count(*) FROM sensors WHERE tenant_id = $1 AND scope = 'organization' AND status <> 'revoked'),
		  (SELECT count(*) FROM api_keys WHERE tenant_id = $1 AND status = 'active'),
		  (SELECT count(*) FROM ci_trust_configs WHERE tenant_id = $1),
		  (SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND created_at > now() - interval '24 hours'),
		  (SELECT count(*) FROM lifecycle_sub_statuses WHERE tenant_id = $1 AND archived_at IS NULL),
		  (SELECT count(*) FROM lifecycle_schemes WHERE tenant_id = $1 AND archived_at IS NULL)`,
		tenantID.String()).Scan(&seats, &assets, &sensors, &keys, &trusts, &invites, &subStatuses, &schemes)
	if err != nil {
		return nil, fmt.Errorf("count usage: %w", err)
	}
	usage := map[limits.Key]int{
		limits.Seats: seats, limits.Assets: assets, limits.Sensors: sensors,
		limits.APIKeys: keys, limits.CITrusts: trusts, limits.InvitesPerDay: invites,
		limits.LifecycleSubStatuses: subStatuses, limits.LifecycleSchemes: schemes,
	}
	// Shared-sensor scans started today (UTC): one per run (a run's chunks
	// count once), or per command outside a run.
	var sharedToday int
	if err := r.db.QueryRowContext(ctx, `
		SELECT count(DISTINCT COALESCE(payload->>'scan_run_id', id::text)) FROM commands
		WHERE tenant_id = $1 AND is_platform_job
		  AND created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`,
		tenantID.String()).Scan(&sharedToday); err != nil {
		return nil, fmt.Errorf("count shared sensor scans: %w", err)
	}
	usage[limits.PlatformScansPerDay] = sharedToday
	if withFindings {
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1`, tenantID.String()).Scan(&n); err != nil {
			return nil, fmt.Errorf("count findings: %w", err)
		}
		usage[limits.Findings] = n
	}
	return usage, nil
}

// CountOwnedTenants counts the organizations the person actively owns.
func (r *LimitsRepository) CountOwnedTenants(ctx context.Context, userID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM tenant_members WHERE user_id = $1 AND role = 'owner' AND status = 'active'`,
		userID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count owned organizations: %w", err)
	}
	return n, nil
}

// ListGrace returns the organization's read-only grace per feature.
func (r *LimitsRepository) ListGrace(ctx context.Context, tenantID shared.ID) (map[string]time.Time, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT module_id, read_only_until FROM tenant_module_grace WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list feature grace: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var (
			id    string
			until time.Time
		)
		if err := rows.Scan(&id, &until); err != nil {
			return nil, fmt.Errorf("scan feature grace: %w", err)
		}
		out[id] = until
	}
	return out, rows.Err()
}

// StartGrace starts grace for features the organization just lost; a grace
// already running is kept as it is. Only module features have a grace row.
func (r *LimitsRepository) StartGrace(ctx context.Context, tenantID shared.ID, features []string, until time.Time) error {
	if len(features) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_module_grace (tenant_id, module_id, read_only_until)
		SELECT $1, m.id, $3 FROM modules m WHERE m.id = ANY($2)
		ON CONFLICT (tenant_id, module_id) DO NOTHING`,
		tenantID.String(), pq.Array(features), until)
	if err != nil {
		return fmt.Errorf("start feature grace: %w", err)
	}
	return nil
}

// EndGrace ends the grace of features the organization has again.
func (r *LimitsRepository) EndGrace(ctx context.Context, tenantID shared.ID, features []string) error {
	if len(features) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM tenant_module_grace WHERE tenant_id = $1 AND module_id = ANY($2)`,
		tenantID.String(), pq.Array(features))
	if err != nil {
		return fmt.Errorf("end feature grace: %w", err)
	}
	return nil
}

// OrganizationExists reports whether the organization exists (the internal
// API checks it before writing; the platform system organization is never
// one).
func (r *LimitsRepository) OrganizationExists(ctx context.Context, id shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1 AND id <> $2)`,
		id.String(), tenant.SystemTenantID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check organization: %w", err)
	}
	return ok, nil
}

// OrganizationPage lists organization ids and creation times in id order,
// after the given id (the platform system organization excluded). It reads
// nothing else.
func (r *LimitsRepository) OrganizationPage(ctx context.Context, after *shared.ID, limit int) ([]shared.ID, []time.Time, error) {
	from := "00000000-0000-0000-0000-000000000000"
	if after != nil {
		from = after.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, created_at FROM tenants WHERE id > $1 AND id <> $2 ORDER BY id LIMIT $3`,
		from, tenant.SystemTenantID, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()
	var ids []shared.ID
	var created []time.Time
	for rows.Next() {
		var (
			s  string
			at time.Time
		)
		if err := rows.Scan(&s, &at); err != nil {
			return nil, nil, fmt.Errorf("scan organization: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			continue
		}
		ids, created = append(ids, id), append(created, at)
	}
	return ids, created, rows.Err()
}
