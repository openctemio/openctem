package postgres

// Per-task logs from sensors: the command_logs table (RFC-029 §4.4.1). One
// row per batch keyed by (command_id, lease_epoch, seq): every claim of a
// command is a new lease epoch and its sensor numbers that attempt's batches
// from 0 again. seq -1 counts the lines refused by the per-command caps.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/app/commandlog"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
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
// acceptAfterFinish ago is commandlog.ErrClosed. The batch is filed under the
// command's current lease epoch, read here under the lock: the sensor never
// says which attempt it is. When the sensor states the epoch it holds the
// command under (b.StatedEpoch) and that is not the current one, the batch
// is from an attempt that lost its lease: commandlog.ErrStaleLease, so it is
// never filed under another attempt.
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
			epoch  int
		)
		err := tx.QueryRowContext(ctx, `
			SELECT status, lease_epoch,
			       status IN ('completed', 'failed', 'canceled', 'expired')
			         AND COALESCE(completed_at, created_at) < NOW() - make_interval(secs => $4)
			FROM commands
			WHERE tenant_id = $1 AND id = $2 AND sensor_id = $3`,
			b.TenantID.String(), b.CommandID.String(), b.SensorID.String(), acceptAfterFinish.Seconds()).
			Scan(&status, &epoch, &closed)
		if errors.Is(err, sql.ErrNoRows) {
			return commandlog.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read command: %w", err)
		}
		if closed {
			return fmt.Errorf("%w: the command is %s", commandlog.ErrClosed, status)
		}

		if b.StatedEpoch != nil && *b.StatedEpoch != epoch {
			return fmt.Errorf("%w: stated lease epoch %d, current %d", commandlog.ErrStaleLease, *b.StatedEpoch, epoch)
		}
		out.Attempt = epoch

		// A replay of a stored batch answers what it stored. A batch with
		// the seq of a stored one but another line count is not a replay
		// (the sensor reused a seq within one attempt): it is refused and
		// reported as a collision, never answered as stored.
		var stored int
		err = tx.QueryRowContext(ctx, `
			SELECT line_count FROM command_logs
			WHERE tenant_id = $1 AND command_id = $2 AND lease_epoch = $3 AND seq = $4`,
			b.TenantID.String(), b.CommandID.String(), epoch, b.Seq).Scan(&stored)
		if err == nil {
			if stored != len(b.Lines) {
				out.Dropped, out.Collided = len(b.Lines), true
				return nil
			}
			out.Stored = stored
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read batch: %w", err)
		}

		var batches, bytes int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*) FILTER (WHERE seq >= 0), COALESCE(sum(bytes), 0)
			FROM command_logs WHERE tenant_id = $1 AND command_id = $2`, b.TenantID.String(), b.CommandID.String()).Scan(&batches, &bytes); err != nil {
			return fmt.Errorf("count batches: %w", err)
		}
		if batches >= maxBatches || bytes+len(b.JSON) > maxBytes {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO command_logs (tenant_id, command_id, lease_epoch, seq, dropped)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (command_id, lease_epoch, seq) DO UPDATE SET dropped = command_logs.dropped + EXCLUDED.dropped`,
				b.TenantID.String(), b.CommandID.String(), epoch, dropSeq, len(b.Lines)); err != nil {
				return fmt.Errorf("count dropped lines: %w", err)
			}
			out.Dropped, out.Truncated = len(b.Lines), true
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO command_logs (tenant_id, command_id, lease_epoch, seq, lines, line_count, bytes)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			b.TenantID.String(), b.CommandID.String(), epoch, b.Seq, b.JSON, len(b.Lines), len(b.JSON)); err != nil {
			return fmt.Errorf("store batch: %w", err)
		}
		out.Stored = len(b.Lines)
		return nil
	})
	return out, err
}

// ListForRunTask returns the lines of commandID in batch order, at most
// maxLines. The command must be a task of runID in tenantID (the run id its
// dispatcher wrote into the payload, as the run's task list reads it).
func (r *CommandLogRepository) ListForRunTask(ctx context.Context, tenantID, runID, commandID shared.ID, maxLines int) (commandlog.Page, error) {
	var platform bool
	err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(is_platform_job, FALSE) FROM commands
		WHERE tenant_id = $1 AND id = $2 AND (payload->>'scan_run_id') = $3::text`,
		tenantID.String(), commandID.String(), runID.String()).Scan(&platform)
	if errors.Is(err, sql.ErrNoRows) {
		return commandlog.Page{}, commandlog.ErrNotFound
	}
	if err != nil {
		return commandlog.Page{}, fmt.Errorf("read task: %w", err)
	}

	page, err := r.readLogs(ctx, tenantID, commandID, maxLines)
	page.Platform = platform
	return page, err
}

// ListForCommand returns a command's logs, for any command kind (scan,
// retest, validate, system). A command of another tenant is not found.
func (r *CommandLogRepository) ListForCommand(ctx context.Context, tenantID, commandID shared.ID, maxLines int) (commandlog.Page, error) {
	var platform bool
	err := r.db.QueryRowContext(ctx, `SELECT COALESCE(is_platform_job, FALSE) FROM commands WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), commandID.String()).Scan(&platform)
	if errors.Is(err, sql.ErrNoRows) {
		return commandlog.Page{}, commandlog.ErrNotFound
	}
	if err != nil {
		return commandlog.Page{}, fmt.Errorf("read command: %w", err)
	}
	page, err := r.readLogs(ctx, tenantID, commandID, maxLines)
	page.Platform = platform
	return page, err
}

// SubjectFindings maps each of commandIDs that is about a finding to that
// finding: an AI analysis job (the finding of its run, ai_runs.command_id),
// a retest's check or reach command (finding_retests), or a validate job (its
// payload's finding_id). A command about no finding is left out. A command
// whose subject cannot be read (an analysis job without its run, or about
// something other than a finding; an unreadable id) maps to the zero id,
// which nobody may read (fail closed).
func (r *CommandLogRepository) SubjectFindings(ctx context.Context, tenantID shared.ID, commandIDs []shared.ID) (map[shared.ID]shared.ID, error) {
	out := make(map[shared.ID]shared.ID)
	if len(commandIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(commandIDs))
	for i, id := range commandIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id::text,
		       CASE WHEN c.type = 'analyze' THEN COALESCE(
		                (SELECT CASE WHEN ar.subject_type = 'finding' THEN ar.subject_id::text ELSE '' END
		                   FROM ai_runs ar
		                  WHERE ar.tenant_id = c.tenant_id AND ar.command_id = c.id
		                  LIMIT 1), '')
		            ELSE COALESCE(
		                (SELECT fr.finding_id::text FROM finding_retests fr
		                  WHERE fr.tenant_id = c.tenant_id AND (fr.check_command_id = c.id OR fr.reach_command_id = c.id)
		                  LIMIT 1),
		                CASE WHEN c.type = 'validate' THEN c.payload->>'finding_id' END)
		       END
		  FROM commands c
		 WHERE c.tenant_id = $1 AND c.id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read command subjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cmd string
		var subject sql.NullString
		if err := rows.Scan(&cmd, &subject); err != nil {
			return nil, fmt.Errorf("scan command subject: %w", err)
		}
		if !subject.Valid {
			continue
		}
		cid, err := shared.IDFromString(cmd)
		if err != nil {
			continue
		}
		fid, err := shared.IDFromString(subject.String)
		if err != nil {
			fid = shared.ID{} // an unreadable subject: nobody may read it
		}
		out[cid] = fid
	}
	return out, rows.Err()
}

// SubjectFinding is SubjectFindings for one command: nil when it is about
// no finding, the zero id when its subject cannot be read.
func (r *CommandLogRepository) SubjectFinding(ctx context.Context, tenantID, commandID shared.ID) (*shared.ID, error) {
	m, err := r.SubjectFindings(ctx, tenantID, []shared.ID{commandID})
	if err != nil {
		return nil, err
	}
	fid, ok := m[commandID]
	if !ok {
		return nil, nil
	}
	return &fid, nil
}

// readLogs reads a command's stored batches, oldest attempt first, each
// attempt in batch order; every line carries its attempt (lease epoch).
func (r *CommandLogRepository) readLogs(ctx context.Context, tenantID, commandID shared.ID, maxLines int) (commandlog.Page, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT lease_epoch, seq, lines, dropped FROM command_logs
		WHERE tenant_id = $1 AND command_id = $2
		ORDER BY lease_epoch, seq`, tenantID.String(), commandID.String())
	if err != nil {
		return commandlog.Page{}, fmt.Errorf("list task logs: %w", err)
	}
	defer rows.Close()
	page := commandlog.Page{Lines: []commandlog.Line{}}
	for rows.Next() {
		var (
			epoch, seq, dropped int
			raw                 []byte
		)
		if err := rows.Scan(&epoch, &seq, &raw, &dropped); err != nil {
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
			l.Attempt = epoch
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
		WHERE (command_id, lease_epoch, seq) IN (
			SELECT command_id, lease_epoch, seq FROM command_logs WHERE created_at < $1 ORDER BY created_at LIMIT $2)`,
		before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old command logs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
