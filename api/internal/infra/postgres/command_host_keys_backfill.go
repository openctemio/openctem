package postgres

// Host keys for commands queued before every command got them at create
// (command.AssignHostKeys, research/130).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// hostKeysBackfillBatch bounds the rows one backfill statement reads.
const hostKeysBackfillBatch = 500

// BackfillPendingHostKeys gives the pending commands that name targets but
// have no host keys yet (queued before command.AssignHostKeys ran on every
// create) their keys, in the column and in the payload, so the claim holds
// them back while their hosts are busy instead of offering them to a
// sensor that hands them back. Idempotent and safe across replicas: a row
// is written only while it is still pending without keys, and rows another
// replica holds are skipped. Returns the rows updated.
func BackfillPendingHostKeys(ctx context.Context, db *sql.DB) (int, error) {
	total := 0
	for {
		n, more, err := backfillHostKeysBatch(ctx, db)
		total += n
		if err != nil || !more {
			return total, err
		}
	}
}

func backfillHostKeysBatch(ctx context.Context, db *sql.DB) (int, bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("backfill host keys: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	batch, err := pendingWithoutHostKeys(ctx, tx)
	if err != nil {
		return 0, false, err
	}
	n := 0
	for _, r := range batch {
		cmd := &command.Command{Payload: r.payload}
		if err := command.AssignHostKeys(cmd); err != nil {
			continue
		}
		if cmd.HostKeys == nil {
			// Its targets name no host: an empty list marks it done, so
			// it is not read again.
			cmd.HostKeys = []string{}
			if err := command.AssignHostKeys(cmd); err != nil {
				continue
			}
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE commands SET host_keys = $2, payload = $3
			WHERE id = $1 AND status = 'pending' AND host_keys IS NULL`,
			r.id, hostKeysArg(cmd.HostKeys), cmd.Payload)
		if err != nil {
			return 0, false, fmt.Errorf("backfill host keys: %w", err)
		}
		if k, _ := res.RowsAffected(); k > 0 {
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("backfill host keys: %w", err)
	}
	return n, n > 0 && len(batch) == hostKeysBackfillBatch, nil
}

// keylessRow is a pending command without host keys.
type keylessRow struct {
	id      string
	payload json.RawMessage
}

// pendingWithoutHostKeys locks and reads one batch of pending commands that
// name targets and have no host keys yet.
func pendingWithoutHostKeys(ctx context.Context, tx *sql.Tx) ([]keylessRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, payload FROM commands
		WHERE status = 'pending' AND host_keys IS NULL
		  AND jsonb_typeof(payload) = 'object'
		  AND NOT payload ? 'host_keys'
		  AND (payload ? 'targets' OR payload ? 'target')
		ORDER BY id
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, hostKeysBackfillBatch)
	if err != nil {
		return nil, fmt.Errorf("backfill host keys: %w", err)
	}
	defer rows.Close()
	var batch []keylessRow
	for rows.Next() {
		var r keylessRow
		if err := rows.Scan(&r.id, &r.payload); err != nil {
			return nil, fmt.Errorf("backfill host keys: %w", err)
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backfill host keys: %w", err)
	}
	return batch, nil
}
