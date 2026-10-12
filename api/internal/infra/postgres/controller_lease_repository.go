package postgres

// Controller leases (RFC-046 §11, B1, P1.8).
// See docs/rfcs/RFC-046-scans-redesign.md.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/controllerlease"
)

// ControllerLeaseRepository stores controller leases.
type ControllerLeaseRepository struct {
	db *DB
}

// NewControllerLeaseRepository creates a ControllerLeaseRepository.
func NewControllerLeaseRepository(db *DB) *ControllerLeaseRepository {
	return &ControllerLeaseRepository{db: db}
}

var _ controllerlease.Store = (*ControllerLeaseRepository)(nil)

// TryAcquire takes name when nobody holds it or the holder's lease expired,
// in one statement: an insert, or an update guarded on the expiry. Two
// replicas racing for it: exactly one gets a row back.
func (r *ControllerLeaseRepository) TryAcquire(ctx context.Context, name, holder string, ttl time.Duration) (controllerlease.Lease, bool, error) {
	ttl = controllerlease.ClampTTL(ttl)
	var epoch int64
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO controller_leases (name, holder, epoch, expires_at, acquired_at)
		VALUES ($1, $2, 1, NOW() + make_interval(secs => $3), NOW())
		ON CONFLICT (name) DO UPDATE
		SET holder = EXCLUDED.holder,
		    epoch = controller_leases.epoch + 1,
		    expires_at = EXCLUDED.expires_at,
		    acquired_at = NOW()
		WHERE controller_leases.expires_at < NOW()
		RETURNING epoch`,
		name, holder, ttl.Seconds()).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return controllerlease.Lease{}, false, nil
	}
	if err != nil {
		return controllerlease.Lease{}, false, fmt.Errorf("failed to acquire lease %q: %w", name, err)
	}
	return controllerlease.Lease{Name: name, Holder: holder, Epoch: epoch}, true, nil
}

// Renew extends l by ttl, only while l still holds it and has not expired.
func (r *ControllerLeaseRepository) Renew(ctx context.Context, l controllerlease.Lease, ttl time.Duration) (bool, error) {
	ttl = controllerlease.ClampTTL(ttl)
	res, err := r.db.ExecContext(ctx, `
		UPDATE controller_leases
		SET expires_at = NOW() + make_interval(secs => $4)
		WHERE name = $1 AND holder = $2 AND epoch = $3 AND expires_at > NOW()`,
		l.Name, l.Holder, l.Epoch, ttl.Seconds())
	if err != nil {
		return false, fmt.Errorf("failed to renew lease %q: %w", l.Name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n > 0, nil
}

// Release expires l at once if it still holds it; the epoch is kept so the
// next holder's take bumps it.
func (r *ControllerLeaseRepository) Release(ctx context.Context, l controllerlease.Lease) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE controller_leases SET expires_at = NOW()
		WHERE name = $1 AND holder = $2 AND epoch = $3`,
		l.Name, l.Holder, l.Epoch); err != nil {
		return fmt.Errorf("failed to release lease %q: %w", l.Name, err)
	}
	return nil
}

var (
	holderOnce sync.Once
	holderID   string
)

// LeaseHolderID identifies this API process as a lease holder: host, pid and
// a random suffix, so two processes never share an identity.
func LeaseHolderID() string {
	holderOnce.Do(func() {
		host, _ := os.Hostname()
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		holderID = fmt.Sprintf("%s:%d:%s", host, os.Getpid(), hex.EncodeToString(b))
		if len(holderID) > 200 {
			holderID = holderID[len(holderID)-200:]
		}
	})
	return holderID
}

// tryLeaseLock takes the lease name for this process and keeps renewing it
// every ttl/3 until the returned release is called. The lease outlives a
// crashed process by at most ttl. ok is false when another holder has it.
func tryLeaseLock(ctx context.Context, store controllerlease.Store, name string, ttl time.Duration) (func(), bool, error) {
	ttl = controllerlease.ClampTTL(ttl)
	l, ok, err := store.TryAcquire(ctx, name, LeaseHolderID(), ttl)
	if err != nil || !ok {
		return nil, ok, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(ttl / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, _ = store.Renew(rctx, l, ttl)
				cancel()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(stop)
			<-done
			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = store.Release(rctx, l)
		})
	}, true, nil
}
