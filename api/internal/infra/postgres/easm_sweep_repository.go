package postgres

// Run-now limiter and freshness for EASM sweeps (research/22 P0-11).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMSweepRepository backs run-now and the overview freshness.
type EASMSweepRepository struct {
	db     *DB
	leases *ControllerLeaseRepository
}

// NewEASMSweepRepository creates the repository.
func NewEASMSweepRepository(db *DB) *EASMSweepRepository {
	return &EASMSweepRepository{db: db, leases: NewControllerLeaseRepository(db)}
}

func runNowLease(tenantID shared.ID) string { return "easm_run_now:" + tenantID.String() }

// Acquire takes the tenant\x27s run-now lease for window and never releases
// it, so the next run-now is allowed once it expires (across replicas). When
// the lease is held it returns false and its expiry.
func (r *EASMSweepRepository) Acquire(ctx context.Context, tenantID shared.ID, window time.Duration) (bool, time.Time, error) {
	_, ok, err := r.leases.TryAcquire(ctx, runNowLease(tenantID), LeaseHolderID(), window)
	if err != nil || ok {
		return ok, time.Time{}, err
	}
	until, err := r.RunNowAvailableAt(ctx, tenantID)
	return false, until, err
}

// RunNowAvailableAt is when the tenant may ask for a sweep again (zero:
// now).
func (r *EASMSweepRepository) RunNowAvailableAt(ctx context.Context, tenantID shared.ID) (time.Time, error) {
	var until time.Time
	err := r.db.QueryRowContext(ctx, `SELECT expires_at FROM controller_leases WHERE name = $1 AND expires_at > NOW()`,
		runNowLease(tenantID)).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read run-now lease: %w", err)
	}
	return until, nil
}

// Freshness returns when the tenant\x27s CT monitor and DNS checks last ran
// (nil: never).
func (r *EASMSweepRepository) Freshness(ctx context.Context, tenantID shared.ID) (lastCT, lastDNS *time.Time, err error) {
	var ct, dns sql.NullTime
	if err := r.db.QueryRowContext(ctx, `
		SELECT (SELECT max(last_checked_at) FROM ct_monitor_state WHERE tenant_id = $1),
		       (SELECT max(last_checked_at) FROM easm_dns_check_state WHERE tenant_id = $1)`,
		tenantID.String()).Scan(&ct, &dns); err != nil {
		return nil, nil, fmt.Errorf("read easm freshness: %w", err)
	}
	if ct.Valid {
		lastCT = &ct.Time
	}
	if dns.Valid {
		lastDNS = &dns.Time
	}
	return lastCT, lastDNS, nil
}
