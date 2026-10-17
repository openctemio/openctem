package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
)

// TicketLinkRepository stores ticket links. Every query is tenant-scoped.
type TicketLinkRepository struct {
	db *DB
}

// NewTicketLinkRepository creates the repository.
func NewTicketLinkRepository(db *DB) *TicketLinkRepository { return &TicketLinkRepository{db: db} }

var _ ticketlink.Repository = (*TicketLinkRepository)(nil)

const tlCols = `id, tenant_id, integration_id, provider, finding_id, campaign_id, task_id, external_id, external_key,
	project_key, url, role, state, source, created_by, last_status, last_pushed_state, last_synced_at, sync_error, created_at, updated_at`

func optID(s sql.NullString) *shared.ID {
	if !s.Valid {
		return nil
	}
	id, err := shared.IDFromString(s.String)
	if err != nil {
		return nil
	}
	return &id
}

func scanTicketLink(s rowScanner) (*ticketlink.Link, error) {
	var (
		l            ticketlink.Link
		id, tid, iid string
		fid, cid     sql.NullString
		taskID, by   sql.NullString
		synced       sql.NullTime
	)
	if err := s.Scan(&id, &tid, &iid, &l.Provider, &fid, &cid, &taskID, &l.ExternalID, &l.ExternalKey, &l.ProjectKey, &l.URL,
		&l.Role, &l.State, &l.Source, &by, &l.LastStatus, &l.LastPushedState, &synced, &l.SyncError, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return nil, err
	}
	l.ID, _ = shared.IDFromString(id)
	l.TenantID, _ = shared.IDFromString(tid)
	l.IntegrationID, _ = shared.IDFromString(iid)
	l.FindingID, l.CampaignID, l.TaskID, l.CreatedBy = optID(fid), optID(cid), optID(taskID), optID(by)
	if synced.Valid {
		t := synced.Time
		l.LastSyncedAt = &t
	}
	return &l, nil
}

// Create inserts a link; an active link of the same object and issue is
// ErrAlreadyLinked.
func (r *TicketLinkRepository) Create(ctx context.Context, l *ticketlink.Link) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO ticket_links (`+tlCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		l.ID.String(), l.TenantID.String(), l.IntegrationID.String(), l.Provider, nullID(l.FindingID), nullID(l.CampaignID),
		nullID(l.TaskID), l.ExternalID, l.ExternalKey, l.ProjectKey, l.URL, l.Role, l.State, l.Source, nullID(l.CreatedBy),
		l.LastStatus, l.LastPushedState, l.LastSyncedAt, l.SyncError, l.CreatedAt, l.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ticketlink.ErrAlreadyLinked
		}
		return fmt.Errorf("create ticket link: %w", err)
	}
	return nil
}

// Get loads one link of the tenant.
func (r *TicketLinkRepository) Get(ctx context.Context, tenantID, id shared.ID) (*ticketlink.Link, error) {
	l, err := scanTicketLink(r.db.QueryRowContext(ctx, `SELECT `+tlCols+` FROM ticket_links WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ticketlink.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get ticket link: %w", err)
	}
	return l, nil
}

func (r *TicketLinkRepository) list(ctx context.Context, query string, args ...any) ([]*ticketlink.Link, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list ticket links: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []*ticketlink.Link{}
	for rows.Next() {
		l, err := scanTicketLink(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ticket link: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list ticket links: %w", err)
	}
	return out, nil
}

// ListForFinding lists a finding's links (every state, newest first).
func (r *TicketLinkRepository) ListForFinding(ctx context.Context, tenantID, findingID shared.ID) ([]*ticketlink.Link, error) {
	return r.list(ctx, `SELECT `+tlCols+` FROM ticket_links WHERE tenant_id = $1 AND finding_id = $2
		ORDER BY created_at DESC LIMIT 100`, tenantID.String(), findingID.String())
}

// ListForCampaign lists a campaign's links (every state, newest first).
func (r *TicketLinkRepository) ListForCampaign(ctx context.Context, tenantID, campaignID shared.ID) ([]*ticketlink.Link, error) {
	return r.list(ctx, `SELECT `+tlCols+` FROM ticket_links WHERE tenant_id = $1 AND campaign_id = $2
		ORDER BY created_at DESC LIMIT 100`, tenantID.String(), campaignID.String())
}

// ListForTask lists a remediation task's links (every state, newest first).
func (r *TicketLinkRepository) ListForTask(ctx context.Context, tenantID, taskID shared.ID) ([]*ticketlink.Link, error) {
	return r.list(ctx, `SELECT `+tlCols+` FROM ticket_links WHERE tenant_id = $1 AND task_id = $2
		ORDER BY created_at DESC LIMIT 100`, tenantID.String(), taskID.String())
}

// FindByIssue lists the active links of one issue of an integration.
func (r *TicketLinkRepository) FindByIssue(ctx context.Context, tenantID, integrationID shared.ID, key string) ([]*ticketlink.Link, error) {
	return r.list(ctx, `SELECT `+tlCols+` FROM ticket_links
		WHERE tenant_id = $1 AND integration_id = $2 AND external_key = $3 AND state = 'active'
		ORDER BY created_at LIMIT $4`, tenantID.String(), integrationID.String(), key, ticketlink.MaxLinksPerIssue)
}

// SetState moves a link to unlinked or deleted.
func (r *TicketLinkRepository) SetState(ctx context.Context, tenantID, id shared.ID, state string) error {
	if state != ticketlink.StateUnlinked && state != ticketlink.StateDeleted {
		return fmt.Errorf("%w: invalid link state", shared.ErrValidation)
	}
	res, err := r.db.ExecContext(ctx, `UPDATE ticket_links SET state = $3, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state = 'active'`, tenantID.String(), id.String(), state)
	if err != nil {
		return fmt.Errorf("update ticket link: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ticketlink.ErrNotFound
	}
	return nil
}

// RecordSync stores the last status and error of a link.
func (r *TicketLinkRepository) RecordSync(ctx context.Context, tenantID, id shared.ID, status, syncErr string, at time.Time) error {
	if len(syncErr) > 500 {
		syncErr = syncErr[:500]
	}
	if len(status) > 128 {
		status = status[:128]
	}
	res, err := r.db.ExecContext(ctx, `UPDATE ticket_links SET last_status = $3, sync_error = $4, last_synced_at = $5, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), status, syncErr, at)
	if err != nil {
		return fmt.Errorf("record ticket link sync: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ticketlink.ErrNotFound
	}
	return nil
}

// RecordPush stores the state last pushed to the issue and its status after
// the push, and clears the last error.
func (r *TicketLinkRepository) RecordPush(ctx context.Context, tenantID, id shared.ID, state, status string, at time.Time) error {
	if len(state) > 32 {
		state = state[:32]
	}
	if len(status) > 128 {
		status = status[:128]
	}
	res, err := r.db.ExecContext(ctx, `UPDATE ticket_links SET last_pushed_state = $3, last_status = $4, sync_error = '',
			last_synced_at = $5, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), state, status, at)
	if err != nil {
		return fmt.Errorf("record ticket link push: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ticketlink.ErrNotFound
	}
	return nil
}

// TaskLinksBehindForPlatform lists active task links (own issues) whose task state
// differs from the state last pushed, oldest first. The join pairs the task
// with the link's own tenant.
func (r *TicketLinkRepository) TaskLinksBehindForPlatform(ctx context.Context, limit int) ([]ticketlink.TaskLinkRef, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT l.tenant_id, l.task_id
		FROM ticket_links l
		JOIN remediation_tasks t ON t.tenant_id = l.tenant_id AND t.id = l.task_id
		WHERE l.task_id IS NOT NULL AND l.state = 'active' AND l.role = 'own'
		  AND t.state <> l.last_pushed_state
		ORDER BY l.updated_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list task links behind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ticketlink.TaskLinkRef
	for rows.Next() {
		var tid, taskID string
		if err := rows.Scan(&tid, &taskID); err != nil {
			return nil, fmt.Errorf("scan task link: %w", err)
		}
		ref := ticketlink.TaskLinkRef{}
		ref.TenantID, _ = shared.IDFromString(tid)
		ref.TaskID, _ = shared.IDFromString(taskID)
		out = append(out, ref)
	}
	return out, rows.Err()
}
