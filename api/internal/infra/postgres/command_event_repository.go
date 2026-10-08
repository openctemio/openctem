package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CommandEventRepository reads command_events (written by the
// trg_command_events trigger on commands) and expires them.
type CommandEventRepository struct {
	db *DB
}

// NewCommandEventRepository creates the repository.
func NewCommandEventRepository(db *DB) *CommandEventRepository {
	return &CommandEventRepository{db: db}
}

var _ command.EventReader = (*CommandEventRepository)(nil)

// ListForRun returns the events of the run's commands in the tenant, oldest
// first.
func (r *CommandEventRepository) ListForRun(ctx context.Context, tenantID, runID shared.ID, limit int) ([]command.Event, bool, error) {
	if limit <= 0 || limit > command.MaxRunEvents {
		limit = command.MaxRunEvents
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, command_id, event, COALESCE(status, ''), attempt, platform, sensor_id,
		       COALESCE(code, ''), COALESCE(message, ''), created_at
		FROM command_events
		WHERE tenant_id = $1 AND run_id = $2
		ORDER BY created_at, id
		LIMIT $3`, tenantID.String(), runID.String(), limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("list run events: %w", err)
	}
	defer rows.Close()
	out := make([]command.Event, 0, 64)
	for rows.Next() {
		var (
			e             command.Event
			id, commandID string
			sensorID      sql.NullString
		)
		if err := rows.Scan(&id, &commandID, &e.Event, &e.Status, &e.Attempt, &e.Platform, &sensorID,
			&e.Code, &e.Message, &e.CreatedAt); err != nil {
			return nil, false, fmt.Errorf("scan run event: %w", err)
		}
		e.ID, _ = shared.IDFromString(id)
		e.CommandID, _ = shared.IDFromString(commandID)
		if sensorID.Valid {
			if sid, err := shared.IDFromString(sensorID.String); err == nil {
				e.SensorID = &sid
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list run events: %w", err)
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// DeleteOlderThan removes up to limit events older than before.
func (r *CommandEventRepository) DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 5000
	}
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM command_events
		WHERE id IN (SELECT id FROM command_events WHERE created_at < $1 ORDER BY created_at LIMIT $2)`,
		before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old command events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
