package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/certmonitor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CTMonitorStateRepository stores the Certificate-Transparency sweep's
// per-domain rotation record (table ct_monitor_state). It implements
// certmonitor.StateStore.
type CTMonitorStateRepository struct {
	db *DB
}

// NewCTMonitorStateRepository creates the repository.
func NewCTMonitorStateRepository(db *DB) *CTMonitorStateRepository {
	return &CTMonitorStateRepository{db: db}
}

var (
	_ certmonitor.StateStore   = (*CTMonitorStateRepository)(nil)
	_ certmonitor.TenantLocker = (*CTMonitorStateRepository)(nil)
)

// ListStates returns every domain state of one tenant, keyed by domain.
func (r *CTMonitorStateRepository) ListStates(ctx context.Context, tenantID shared.ID) (map[string]certmonitor.DomainState, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT domain, last_checked_at, last_success_at, last_source, last_error,
		       consecutive_failures, next_attempt_at, subdomains_seen
		FROM ct_monitor_state
		WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list ct monitor state: %w", err)
	}
	defer rows.Close()

	out := map[string]certmonitor.DomainState{}
	for rows.Next() {
		var (
			st                       certmonitor.DomainState
			checked, success, nextAt sql.NullTime
		)
		if err := rows.Scan(&st.Domain, &checked, &success, &st.LastSource, &st.LastError,
			&st.ConsecutiveFailures, &nextAt, &st.SubdomainsSeen); err != nil {
			return nil, fmt.Errorf("scan ct monitor state: %w", err)
		}
		st.LastCheckedAt = nullTimeValue(checked)
		st.LastSuccessAt = nullTimeValue(success)
		st.NextAttemptAt = nullTimeValue(nextAt)
		out[st.Domain] = st
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ct monitor state: %w", err)
	}
	return out, nil
}

// SaveState inserts or replaces one domain's state.
func (r *CTMonitorStateRepository) SaveState(ctx context.Context, tenantID shared.ID, st certmonitor.DomainState) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ct_monitor_state (
			tenant_id, domain, last_checked_at, last_success_at, last_source, last_error,
			consecutive_failures, next_attempt_at, subdomains_seen
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, domain) DO UPDATE SET
			last_checked_at      = EXCLUDED.last_checked_at,
			last_success_at      = EXCLUDED.last_success_at,
			last_source          = EXCLUDED.last_source,
			last_error           = EXCLUDED.last_error,
			consecutive_failures = EXCLUDED.consecutive_failures,
			next_attempt_at      = EXCLUDED.next_attempt_at,
			subdomains_seen      = EXCLUDED.subdomains_seen,
			updated_at           = now()`,
		tenantID.String(), st.Domain,
		nullTimePtr(st.LastCheckedAt), nullTimePtr(st.LastSuccessAt),
		st.LastSource, st.LastError, st.ConsecutiveFailures,
		nullTimePtr(st.NextAttemptAt), st.SubdomainsSeen)
	if err != nil {
		return fmt.Errorf("save ct monitor state: %w", err)
	}
	return nil
}

// ctMonitorLeaseTTL bounds how long a crashed replica's per-tenant sweep
// lease blocks the others; a live holder renews it every third of it.
const ctMonitorLeaseTTL = 10 * time.Minute

// TryLockTenant makes one tenant's CT sweep run on one API replica at a time
// (each would read the rotation state before the other wrote it and query the
// same domains), with the controller lease "ct_monitor:<tenant>" (RFC-046
// P1.8; it was a session advisory lock on a dedicated connection).
func (r *CTMonitorStateRepository) TryLockTenant(ctx context.Context, tenantID shared.ID) (func(), bool, error) {
	release, ok, err := tryLeaseLock(ctx, NewControllerLeaseRepository(r.db), "ct_monitor:"+tenantID.String(), ctMonitorLeaseTTL)
	if err != nil {
		return nil, false, fmt.Errorf("ct monitor lock: %w", err)
	}
	return release, ok, nil
}
