package postgres

// Per-task logs from sensors: the command_logs table (migration 001130,
// RFC-029 §4.4.1). One row per batch keyed by (command_id, seq); seq -1 counts
// the lines refused by the per-command caps.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// dropSeq is the row that counts dropped lines.
const dropSeq = -1

// CommandLogRepository implements commandlog.Store.
type CommandLogRepository struct {
	db *DB
}

// NewCommandLogRepository creates a CommandLogRepository.
func NewCommandLogRepository(db *DB) *CommandLogRepository {
	return &CommandLogRepository{db: db}
}

var _ commandlog.Store = (*CommandLogRepository)(nil)

// Append stores one batch in one transaction, serialized per command (an
// advisory lock), so the per-command caps hold under concurrent batches.
//
// The command must be b.TenantID's and held (or last held) by b.SensorID;
// anything else is commandlog.ErrNotFound. A command that finished more than
// acceptAfterFinish ago is commandlog.ErrClosed.
func (r *CommandLogRepository) Append(ctx context.Context, b commandlog.Batch, acceptAfterFinish time.Duration,
	maxBatches, maxBytes int,
) (commandlog.AppendResult, error) {
	var out commandlog.AppendResult
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 1130))`, b.CommandID.String()); err != nil {
			return fmt.Errorf("lock command logs: %w", err)
		}
		var (
			status string
			closed bool
		)
		err := tx.QueryRowContext(ctx, `
			SELECT status,
			       status IN ('completed', 'failed', 'canceled', 'expired')
			         AND COALESCE(completed_at, created_at) < NOW() - make_interval(secs => $4)
			FROM commands
			WHERE tenant_id = $1 AND id = $2 AND sensor_id = $3`,
			b.TenantID.String(), b.CommandID.String(), b.SensorID.String(), acceptAfterFinish.Seconds()).
			Scan(&status, &closed)
		if errors.Is(err, sql.ErrNoRows) {
			return commandlog.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read command: %w", err)
		}
		if closed {
			return fmt.Errorf("%w: the command is %s", commandlog.ErrClosed, status)
		}

		// A replay of a stored batch answers what it stored.
		var stored int
		err = tx.QueryRowContext(ctx, `SELECT line_count FROM command_logs WHERE command_id = $1 AND seq = $2`,
			b.CommandID.String(), b.Seq).Scan(&stored)
		if err == nil {
			out = commandlog.AppendResult{Stored: stored}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read batch: %w", err)
		}

		var batches, bytes int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FILTER (WHERE seq >= 0), COALESCE(sum(bytes), 0)
			FROM command_logs WHERE command_id = $1`, b.CommandID.String()).Scan(&batches, &bytes); err != nil {
			return fmt.Errorf("count batches: %w", err)
		}
		if batches >= maxBatches || bytes+len(b.JSON) > maxBytes {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO command_logs (tenant_id, command_id, seq, dropped)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (command_id, seq) DO UPDATE SET dropped = command_logs.dropped + EXCLUDED.dropped`,
				b.TenantID.String(), b.CommandID.String(), dropSeq, len(b.Lines)); err != nil {
				return fmt.Errorf("count dropped lines: %w", err)
			}
			out = commandlog.AppendResult{Dropped: len(b.Lines), Truncated: true}
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO command_logs (tenant_id, command_id, seq, lines, line_count, bytes)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			b.TenantID.String(), b.CommandID.String(), b.Seq, b.JSON, len(b.Lines), len(b.JSON)); err != nil {
			return fmt.Errorf("store batch: %w", err)
		}
		out = commandlog.AppendResult{Stored: len(b.Lines)}
		return nil
	})
	return out, err
}

// ListForRunTask returns the lines of commandID in batch order, at most
// maxLines. The command must be a task of runID in tenantID (the run id its
// dispatcher wrote into the payload, as the run's task list reads it).
func (r *CommandLogRepository) ListForRunTask(ctx context.Context, tenantID, runID, commandID shared.ID, maxLines int) (commandlog.Page, error) {
	var one int
	err := r.db.QueryRowContext(ctx, `
		SELECT 1 FROM commands
		WHERE tenant_id = $1 AND id = $2 AND (payload->>'pipeline_run_id') = $3::text`,
		tenantID.String(), commandID.String(), runID.String()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return commandlog.Page{}, commandlog.ErrNotFound
	}
	if err != nil {
		return commandlog.Page{}, fmt.Errorf("read task: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT seq, lines, dropped FROM command_logs
		WHERE tenant_id = $1 AND command_id = $2
		ORDER BY seq`, tenantID.String(), commandID.String())
	if err != nil {
		return commandlog.Page{}, fmt.Errorf("list task logs: %w", err)
	}
	defer rows.Close()
	page := commandlog.Page{Lines: []commandlog.Line{}}
	for rows.Next() {
		var (
			seq, dropped int
			raw          []byte
		)
		if err := rows.Scan(&seq, &raw, &dropped); err != nil {
			return commandlog.Page{}, fmt.Errorf("scan task logs: %w", err)
		}
		if dropped > 0 {
			page.Truncated = true
		}
		if seq < 0 {
			continue
		}
		var lines []commandlog.Line
		if err := json.Unmarshal(raw, &lines); err != nil {
			return commandlog.Page{}, fmt.Errorf("decode task logs: %w", err)
		}
		for _, l := range lines {
			if len(page.Lines) >= maxLines {
				page.Truncated = true
				break
			}
			page.Lines = append(page.Lines, l)
		}
	}
	return page, rows.Err()
}

// DeleteOlderThan deletes at most limit batches created before before.
func (r *CommandLogRepository) DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 5000
	}
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM command_logs
		WHERE (command_id, seq) IN (
			SELECT command_id, seq FROM command_logs WHERE created_at < $1 ORDER BY created_at LIMIT $2)`,
		before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old command logs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
