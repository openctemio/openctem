package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DurableJobRepository stores durable jobs (durable_jobs).
type DurableJobRepository struct {
	db *DB
}

// NewDurableJobRepository creates the repository.
func NewDurableJobRepository(db *DB) *DurableJobRepository {
	return &DurableJobRepository{db: db}
}

var _ durablejob.Store = (*DurableJobRepository)(nil)

// insertDurableJobsTx queues jobs in tx. A pending job for the same kind and
// subject is replaced (payload and due time): its subject changed again
// before it ran, and the newest payload wins (a rotated invitation token).
func insertDurableJobsTx(ctx context.Context, tx *sql.Tx, jobs []durablejob.Job) error {
	for _, j := range jobs {
		var payload any
		if j.Payload != "" {
			payload = j.Payload
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO durable_jobs (tenant_id, kind, subject_id, payload)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (kind, subject_id) WHERE status = 'pending'
			DO UPDATE SET payload = EXCLUDED.payload, next_attempt_at = now()
			WHERE durable_jobs.tenant_id = EXCLUDED.tenant_id`,
			j.TenantID.String(), string(j.Kind), j.SubjectID.String(), payload); err != nil {
			return fmt.Errorf("queue %s job: %w", j.Kind, err)
		}
	}
	return nil
}

// enqueueContextJobsTx queues the jobs durablejob.WithEnqueue put on ctx,
// when the write before it changed a row.
func enqueueContextJobsTx(ctx context.Context, tx *sql.Tx, res sql.Result) error {
	jobs := durablejob.FromContext(ctx)
	if len(jobs) == 0 {
		return nil
	}
	if res != nil {
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected: %w", err)
		}
		if n == 0 {
			return nil
		}
	}
	return insertDurableJobsTx(ctx, tx, jobs)
}

// Claim (see durablejob.Store). A processing job whose lease passed is due
// again: its worker died before finishing it.
func (r *DurableJobRepository) Claim(ctx context.Context, kinds []durablejob.Kind, limit int, lease time.Duration) ([]durablejob.Claimed, error) {
	if len(kinds) == 0 || limit <= 0 {
		return nil, nil
	}
	ks := make([]string, len(kinds))
	for i, k := range kinds {
		ks[i] = string(k)
	}
	rows, err := r.db.QueryContext(ctx, `
		UPDATE durable_jobs d
		   SET status = 'processing', attempts = d.attempts + 1,
		       locked_until = now() + make_interval(secs => $3)
		  FROM (SELECT id FROM durable_jobs
		         WHERE kind = ANY($1)
		           AND ((status = 'pending' AND next_attempt_at <= now())
		             OR (status = 'processing' AND locked_until < now()))
		         ORDER BY next_attempt_at
		         LIMIT $2
		         FOR UPDATE SKIP LOCKED) due
		 WHERE d.id = due.id
		RETURNING d.id, d.tenant_id, d.kind, d.subject_id, COALESCE(d.payload, ''), d.attempts`,
		pq.Array(ks), limit, lease.Seconds())
	if err != nil {
		return nil, fmt.Errorf("claim durable jobs: %w", err)
	}
	defer rows.Close()
	var out []durablejob.Claimed
	for rows.Next() {
		var id, tenant, subject, kind string
		var c durablejob.Claimed
		if err := rows.Scan(&id, &tenant, &kind, &subject, &c.Payload, &c.Attempts); err != nil {
			return nil, fmt.Errorf("scan durable job: %w", err)
		}
		c.ID, c.TenantID, c.SubjectID = shared.MustIDFromString(id), shared.MustIDFromString(tenant), shared.MustIDFromString(subject)
		c.Kind = durablejob.Kind(kind)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Complete (see durablejob.Store).
func (r *DurableJobRepository) Complete(ctx context.Context, j durablejob.Claimed) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM durable_jobs WHERE id = $1 AND tenant_id = $2`,
		j.ID.String(), j.TenantID.String()); err != nil {
		return fmt.Errorf("complete durable job: %w", err)
	}
	return nil
}

// Retry (see durablejob.Store). When a newer pending job for the same
// subject was queued while this one ran, that one supersedes it.
func (r *DurableJobRepository) Retry(ctx context.Context, j durablejob.Claimed, at time.Time, reason string) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var newer bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM durable_jobs
			                WHERE tenant_id = $1 AND kind = $2 AND subject_id = $3 AND status = 'pending')`,
			j.TenantID.String(), string(j.Kind), j.SubjectID.String()).Scan(&newer); err != nil {
			return fmt.Errorf("retry durable job: %w", err)
		}
		if newer {
			_, err := tx.ExecContext(ctx, `DELETE FROM durable_jobs WHERE id = $1 AND tenant_id = $2`, j.ID.String(), j.TenantID.String())
			return err
		}
		_, err := tx.ExecContext(ctx, `
			UPDATE durable_jobs SET status = 'pending', next_attempt_at = $3, locked_until = NULL, last_error = LEFT($4, 1000)
			 WHERE id = $1 AND tenant_id = $2`, j.ID.String(), j.TenantID.String(), at, reason)
		if err != nil {
			return fmt.Errorf("retry durable job: %w", err)
		}
		return nil
	})
}

// Bury (see durablejob.Store). The payload is cleared: a sealed invitation
// token has no use once the job is given up.
func (r *DurableJobRepository) Bury(ctx context.Context, j durablejob.Claimed, reason string) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE durable_jobs SET status = 'dead', payload = NULL, locked_until = NULL, last_error = LEFT($3, 1000)
		 WHERE id = $1 AND tenant_id = $2`, j.ID.String(), j.TenantID.String(), reason); err != nil {
		return fmt.Errorf("bury durable job: %w", err)
	}
	return nil
}
