package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ProxyPoolRepository implements proxypool.Repository. Every statement is
// tenant-scoped; endpoint and assignment membership is also enforced by the
// composite (tenant_id, id) foreign keys, so a row can never point at a pool
// or sensor of another tenant.
type ProxyPoolRepository struct {
	db *DB
}

// NewProxyPoolRepository creates a ProxyPoolRepository.
func NewProxyPoolRepository(db *DB) *ProxyPoolRepository {
	return &ProxyPoolRepository{db: db}
}

var _ proxypool.Repository = (*ProxyPoolRepository)(nil)

const proxyPoolColumns = `p.id, p.tenant_id, p.name, p.description, p.enabled, p.is_default, p.strategy, p.revision,
	p.created_by, p.created_at, p.updated_at,
	(SELECT COUNT(*) FROM proxy_sensor_assignments a WHERE a.tenant_id = p.tenant_id AND a.pool_id = p.id)`

const proxyEndpointColumns = `id, tenant_id, pool_id, scheme, host, port, label, priority, enabled,
	credentials_encrypted, credentials_updated_at,
	state, score, success_ewma, consecutive_failures, probation_ok, quarantine_count, ok_total, fail_total,
	handshake_ms_p95, last_error, last_ok_at, last_failure_at, quarantined_until, state_changed_at,
	created_at, updated_at`

// CreatePool inserts a pool (no endpoints).
func (r *ProxyPoolRepository) CreatePool(ctx context.Context, p *proxypool.Pool) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO proxy_pools (id, tenant_id, name, description, enabled, is_default, strategy, revision, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		p.ID.String(), p.TenantID.String(), p.Name, p.Description, p.Enabled, p.IsDefault, p.Strategy, p.Revision,
		nullIDString(p.CreatedBy), p.CreatedAt, p.UpdatedAt)
	return mapProxyPoolWriteError(err)
}

// UpdatePool writes the pool's own fields.
func (r *ProxyPoolRepository) UpdatePool(ctx context.Context, p *proxypool.Pool) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE proxy_pools
		SET name = $3, description = $4, enabled = $5, is_default = $6, strategy = $7, revision = $8, updated_at = $9
		WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.Name, p.Description, p.Enabled, p.IsDefault, p.Strategy, p.Revision, p.UpdatedAt)
	if err != nil {
		return mapProxyPoolWriteError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return proxypool.ErrPoolNotFound
	}
	return nil
}

func mapProxyPoolWriteError(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch {
		case pqErr.Code == "23505" && pqErr.Constraint == "uq_proxy_pools_default":
			return proxypool.ErrDefaultTaken
		case pqErr.Code == "23505" && pqErr.Constraint == "uq_proxy_pools_tenant_name":
			return proxypool.ErrPoolNameTaken
		case pqErr.Code == "23505":
			return fmt.Errorf("%w: proxy endpoint listed twice", shared.ErrValidation)
		case isForeignKeyCode(string(pqErr.Code)) && pqErr.Constraint == "fk_proxy_sensor_assignments_pool":
			return proxypool.ErrPoolInUse
		}
	}
	if isCheckViolation(err) {
		return fmt.Errorf("%w: proxy pool violates a constraint", shared.ErrValidation)
	}
	return fmt.Errorf("write proxy pool: %w", err)
}

// DeletePool removes a pool and its endpoints. The assignment foreign key
// (ON DELETE RESTRICT) refuses it while a sensor names the pool.
func (r *ProxyPoolRepository) DeletePool(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM proxy_pools WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		if isForeignKeyViolation(err) {
			return proxypool.ErrPoolInUse
		}
		return fmt.Errorf("delete proxy pool: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return proxypool.ErrPoolNotFound
	}
	return nil
}

// GetPool returns one pool of the tenant with its endpoints.
func (r *ProxyPoolRepository) GetPool(ctx context.Context, tenantID, id shared.ID) (*proxypool.Pool, error) {
	pools, err := r.queryPools(ctx, `WHERE p.tenant_id = $1 AND p.id = $2`, tenantID.String(), id.String())
	if err != nil {
		return nil, err
	}
	if len(pools) == 0 {
		return nil, proxypool.ErrPoolNotFound
	}
	return pools[0], nil
}

// DefaultPool returns the tenant's default pool, nil without one.
func (r *ProxyPoolRepository) DefaultPool(ctx context.Context, tenantID shared.ID) (*proxypool.Pool, error) {
	pools, err := r.queryPools(ctx, `WHERE p.tenant_id = $1 AND p.is_default`, tenantID.String())
	if err != nil || len(pools) == 0 {
		return nil, err
	}
	return pools[0], nil
}

// ListPools returns the tenant's pools, default first, then by name.
func (r *ProxyPoolRepository) ListPools(ctx context.Context, tenantID shared.ID) ([]*proxypool.Pool, error) {
	return r.queryPools(ctx, `WHERE p.tenant_id = $1`, tenantID.String())
}

// CountPools counts the tenant's pools.
func (r *ProxyPoolRepository) CountPools(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxy_pools WHERE tenant_id = $1`, tenantID.String()).Scan(&n)
	return n, err
}

func (r *ProxyPoolRepository) queryPools(ctx context.Context, where string, args ...any) ([]*proxypool.Pool, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+proxyPoolColumns+` FROM proxy_pools p `+where+
		` ORDER BY p.is_default DESC, p.name LIMIT 100`, args...)
	if err != nil {
		return nil, fmt.Errorf("query proxy pools: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*proxypool.Pool
	byID := map[string]*proxypool.Pool{}
	var ids []string
	var tenant string
	for rows.Next() {
		var (
			p                proxypool.Pool
			id, tid          string
			createdBy        sql.NullString
			createdAt, updAt time.Time
		)
		if err := rows.Scan(&id, &tid, &p.Name, &p.Description, &p.Enabled, &p.IsDefault, &p.Strategy, &p.Revision,
			&createdBy, &createdAt, &updAt, &p.AssignedSensors); err != nil {
			return nil, fmt.Errorf("scan proxy pool: %w", err)
		}
		p.ID, p.TenantID = shared.MustIDFromString(id), shared.MustIDFromString(tid)
		if createdBy.Valid {
			cb := shared.MustIDFromString(createdBy.String)
			p.CreatedBy = &cb
		}
		p.CreatedAt, p.UpdatedAt = createdAt, updAt
		p.Endpoints = []*proxypool.Endpoint{}
		out = append(out, &p)
		byID[id] = &p
		ids = append(ids, id)
		tenant = tid
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return out, nil
	}
	eps, err := r.queryEndpoints(ctx, r.db, `WHERE tenant_id = $1 AND pool_id = ANY($2::uuid[]) ORDER BY pool_id, priority, id`,
		tenant, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	for _, e := range eps {
		if p := byID[e.PoolID.String()]; p != nil {
			p.Endpoints = append(p.Endpoints, e)
		}
	}
	return out, nil
}

type proxyQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (r *ProxyPoolRepository) queryEndpoints(ctx context.Context, q proxyQueryer, where string, args ...any) ([]*proxypool.Endpoint, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+proxyEndpointColumns+` FROM proxy_endpoints `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query proxy endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*proxypool.Endpoint
	for rows.Next() {
		var (
			e                         proxypool.Endpoint
			id, tid, pid              string
			creds                     sql.NullString
			credsAt                   sql.NullTime
			score, ewma               float64
			p95                       sql.NullInt64
			lastOK, lastFail, qUntil  sql.NullTime
			stateAt, created, updated time.Time
		)
		if err := rows.Scan(&id, &tid, &pid, &e.Scheme, &e.Host, &e.Port, &e.Label, &e.Priority, &e.Enabled,
			&creds, &credsAt,
			&e.Health.State, &score, &ewma, &e.Health.ConsecutiveFailures, &e.Health.ProbationOK, &e.Health.QuarantineCount,
			&e.Health.OKTotal, &e.Health.FailTotal, &p95, &e.Health.LastError, &lastOK, &lastFail, &qUntil, &stateAt,
			&created, &updated); err != nil {
			return nil, fmt.Errorf("scan proxy endpoint: %w", err)
		}
		e.ID, e.TenantID, e.PoolID = shared.MustIDFromString(id), shared.MustIDFromString(tid), shared.MustIDFromString(pid)
		e.CredentialsEncrypted = creds.String
		e.CredentialsUpdatedAt = timePtr(credsAt)
		e.Health.Score, e.Health.SuccessEWMA = score, ewma
		if p95.Valid {
			v := int(p95.Int64)
			e.Health.HandshakeMsP95 = &v
		}
		e.Health.LastOKAt, e.Health.LastFailureAt, e.Health.QuarantinedUntil = timePtr(lastOK), timePtr(lastFail), timePtr(qUntil)
		e.Health.StateChangedAt, e.CreatedAt, e.UpdatedAt = stateAt, created, updated
		out = append(out, &e)
	}
	return out, rows.Err()
}

// ReplaceEndpoints makes endpoints the pool's whole list.
func (r *ProxyPoolRepository) ReplaceEndpoints(ctx context.Context, p *proxypool.Pool, endpoints []*proxypool.Endpoint) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPool(ctx, tx, p); err != nil {
		return err
	}
	keep := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		keep = append(keep, e.ID.String())
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_endpoints WHERE tenant_id = $1 AND pool_id = $2 AND NOT (id = ANY($3::uuid[]))`,
		p.TenantID.String(), p.ID.String(), pq.Array(keep)); err != nil {
		return fmt.Errorf("delete proxy endpoints: %w", err)
	}
	// Two passes: move kept rows out of the way of the unique address key
	// first, so swapping two lines' addresses cannot collide mid-update.
	if _, err := tx.ExecContext(ctx, `UPDATE proxy_endpoints SET host = '~' || id::text WHERE tenant_id = $1 AND pool_id = $2`,
		p.TenantID.String(), p.ID.String()); err != nil {
		return fmt.Errorf("stage proxy endpoints: %w", err)
	}
	for _, e := range endpoints {
		if err := upsertEndpoint(ctx, tx, e); err != nil {
			return err
		}
	}
	if err := storeRevision(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit()
}

func lockPool(ctx context.Context, tx *sql.Tx, p *proxypool.Pool) error {
	var locked string
	err := tx.QueryRowContext(ctx, `SELECT id FROM proxy_pools WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		p.TenantID.String(), p.ID.String()).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return proxypool.ErrPoolNotFound
	}
	if err != nil {
		return fmt.Errorf("lock proxy pool: %w", err)
	}
	return nil
}

func storeRevision(ctx context.Context, tx *sql.Tx, p *proxypool.Pool) error {
	_, err := tx.ExecContext(ctx, `UPDATE proxy_pools SET revision = $3, updated_at = $4 WHERE tenant_id = $1 AND id = $2`,
		p.TenantID.String(), p.ID.String(), p.Revision, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store proxy pool revision: %w", err)
	}
	return nil
}

func upsertEndpoint(ctx context.Context, tx *sql.Tx, e *proxypool.Endpoint) error {
	h := e.Health
	var creds sql.NullString
	if e.CredentialsEncrypted != "" {
		creds = sql.NullString{String: e.CredentialsEncrypted, Valid: true}
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO proxy_endpoints (id, tenant_id, pool_id, scheme, host, port, label, priority, enabled,
			credentials_encrypted, credentials_updated_at,
			state, score, success_ewma, consecutive_failures, probation_ok, quarantine_count, ok_total, fail_total,
			handshake_ms_p95, last_error, last_ok_at, last_failure_at, quarantined_until, state_changed_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
		ON CONFLICT (id) DO UPDATE SET
			scheme = EXCLUDED.scheme, host = EXCLUDED.host, port = EXCLUDED.port, label = EXCLUDED.label,
			priority = EXCLUDED.priority, enabled = EXCLUDED.enabled,
			credentials_encrypted = EXCLUDED.credentials_encrypted, credentials_updated_at = EXCLUDED.credentials_updated_at,
			state = EXCLUDED.state, score = EXCLUDED.score, success_ewma = EXCLUDED.success_ewma,
			consecutive_failures = EXCLUDED.consecutive_failures, probation_ok = EXCLUDED.probation_ok,
			quarantine_count = EXCLUDED.quarantine_count, ok_total = EXCLUDED.ok_total, fail_total = EXCLUDED.fail_total,
			handshake_ms_p95 = EXCLUDED.handshake_ms_p95, last_error = EXCLUDED.last_error,
			last_ok_at = EXCLUDED.last_ok_at, last_failure_at = EXCLUDED.last_failure_at,
			quarantined_until = EXCLUDED.quarantined_until, state_changed_at = EXCLUDED.state_changed_at,
			updated_at = EXCLUDED.updated_at
		WHERE proxy_endpoints.tenant_id = EXCLUDED.tenant_id AND proxy_endpoints.pool_id = EXCLUDED.pool_id`,
		e.ID.String(), e.TenantID.String(), e.PoolID.String(), e.Scheme, e.Host, e.Port, e.Label, e.Priority, e.Enabled,
		creds, nullTimePtr(e.CredentialsUpdatedAt),
		h.State, h.Score, h.SuccessEWMA, h.ConsecutiveFailures, h.ProbationOK, h.QuarantineCount, h.OKTotal, h.FailTotal,
		nullIntPtr(h.HandshakeMsP95), h.LastError, nullTimePtr(h.LastOKAt), nullTimePtr(h.LastFailureAt),
		nullTimePtr(h.QuarantinedUntil), h.StateChangedAt, e.CreatedAt, e.UpdatedAt)
	return mapProxyPoolWriteError(err)
}

// UpdateEndpoint stores one endpoint's enabled flag and health, and the
// pool's revision.
func (r *ProxyPoolRepository) UpdateEndpoint(ctx context.Context, p *proxypool.Pool, e *proxypool.Endpoint) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPool(ctx, tx, p); err != nil {
		return err
	}
	if err := writeHealth(ctx, tx, e); err != nil {
		return err
	}
	if err := storeRevision(ctx, tx, p); err != nil {
		return err
	}
	return tx.Commit()
}

func writeHealth(ctx context.Context, tx *sql.Tx, e *proxypool.Endpoint) error {
	h := e.Health
	res, err := tx.ExecContext(ctx, `
		UPDATE proxy_endpoints SET enabled = $4,
			state = $5, score = $6, success_ewma = $7, consecutive_failures = $8, probation_ok = $9,
			quarantine_count = $10, ok_total = $11, fail_total = $12, handshake_ms_p95 = $13, last_error = $14,
			last_ok_at = $15, last_failure_at = $16, quarantined_until = $17, state_changed_at = $18, updated_at = now()
		WHERE tenant_id = $1 AND pool_id = $2 AND id = $3`,
		e.TenantID.String(), e.PoolID.String(), e.ID.String(), e.Enabled,
		h.State, h.Score, h.SuccessEWMA, h.ConsecutiveFailures, h.ProbationOK, h.QuarantineCount, h.OKTotal, h.FailTotal,
		nullIntPtr(h.HandshakeMsP95), h.LastError, nullTimePtr(h.LastOKAt), nullTimePtr(h.LastFailureAt),
		nullTimePtr(h.QuarantinedUntil), h.StateChangedAt)
	if err != nil {
		return mapProxyPoolWriteError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return proxypool.ErrEndpointNotFound
	}
	return nil
}

// UpdateHealth locks the pool's endpoints and stores what apply changed.
func (r *ProxyPoolRepository) UpdateHealth(ctx context.Context, tenantID, poolID shared.ID, apply func([]*proxypool.Endpoint)) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	eps, err := r.queryEndpoints(ctx, tx, `WHERE tenant_id = $1 AND pool_id = $2 ORDER BY priority, id FOR UPDATE`,
		tenantID.String(), poolID.String())
	if err != nil {
		return err
	}
	if len(eps) == 0 {
		return nil
	}
	apply(eps)
	for _, e := range eps {
		if err := writeHealth(ctx, tx, e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetAssignment returns a sensor's assignment, nil when it inherits.
func (r *ProxyPoolRepository) GetAssignment(ctx context.Context, tenantID, sensorID shared.ID) (*proxypool.Assignment, error) {
	var (
		a    proxypool.Assignment
		pool sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `SELECT mode, pool_id FROM proxy_sensor_assignments WHERE tenant_id = $1 AND sensor_id = $2`,
		tenantID.String(), sensorID.String()).Scan(&a.Mode, &pool)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get proxy assignment: %w", err)
	}
	a.SensorID = sensorID
	if pool.Valid {
		id := shared.MustIDFromString(pool.String)
		a.PoolID = &id
	}
	return &a, nil
}

// ListAssignments returns every assignment of the tenant.
func (r *ProxyPoolRepository) ListAssignments(ctx context.Context, tenantID shared.ID) ([]proxypool.Assignment, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT sensor_id, mode, pool_id FROM proxy_sensor_assignments WHERE tenant_id = $1 ORDER BY sensor_id LIMIT 10000`,
		tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list proxy assignments: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []proxypool.Assignment{}
	for rows.Next() {
		var (
			a        proxypool.Assignment
			sid      string
			poolNull sql.NullString
		)
		if err := rows.Scan(&sid, &a.Mode, &poolNull); err != nil {
			return nil, fmt.Errorf("scan proxy assignment: %w", err)
		}
		a.SensorID = shared.MustIDFromString(sid)
		if poolNull.Valid {
			id := shared.MustIDFromString(poolNull.String)
			a.PoolID = &id
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAssignment inserts or replaces a sensor's assignment.
func (r *ProxyPoolRepository) SetAssignment(ctx context.Context, tenantID shared.ID, a proxypool.Assignment, by *shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO proxy_sensor_assignments (sensor_id, tenant_id, mode, pool_id, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (sensor_id) DO UPDATE SET mode = EXCLUDED.mode, pool_id = EXCLUDED.pool_id,
			updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE proxy_sensor_assignments.tenant_id = EXCLUDED.tenant_id`,
		a.SensorID.String(), tenantID.String(), a.Mode, nullIDString(a.PoolID), nullIDString(by))
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			if pqErr.Constraint == "fk_proxy_sensor_assignments_pool" {
				return proxypool.ErrPoolNotFound
			}
			return proxypool.ErrSensorNotFound
		}
		return mapProxyPoolWriteError(err)
	}
	return nil
}

// DeleteAssignment removes a sensor's assignment (it inherits again).
func (r *ProxyPoolRepository) DeleteAssignment(ctx context.Context, tenantID, sensorID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM proxy_sensor_assignments WHERE tenant_id = $1 AND sensor_id = $2`,
		tenantID.String(), sensorID.String())
	if err != nil {
		return fmt.Errorf("delete proxy assignment: %w", err)
	}
	return nil
}
