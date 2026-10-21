package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WorkItemSubscriptionRepository stores the watchers of findings and
// remediation tasks (table work_item_subscriptions, RFC-120). Every query
// carries the tenant; the database ties each row to an item of that tenant
// through composite foreign keys.
type WorkItemSubscriptionRepository struct {
	db *DB
}

// NewWorkItemSubscriptionRepository creates the repository.
func NewWorkItemSubscriptionRepository(db *DB) *WorkItemSubscriptionRepository {
	return &WorkItemSubscriptionRepository{db: db}
}

var _ participation.Repository = (*WorkItemSubscriptionRepository)(nil)

// itemColumn is the column and the unique-index predicate of an item kind.
func itemColumn(item participation.Item) (col string, err error) {
	switch item.Kind {
	case participation.ItemFinding:
		return "finding_id", nil
	case participation.ItemTask:
		return "task_id", nil
	}
	return "", fmt.Errorf("unknown item kind %q", item.Kind)
}

const wisColumns = `s.id, s.tenant_id, s.finding_id, s.task_id, s.user_id, s.state, s.reason, s.added_by, s.created_at, s.updated_at`

func scanSubscription(sc interface{ Scan(...any) error }, extra ...any) (participation.Subscription, error) {
	var (
		s       participation.Subscription
		finding sql.NullString
		task    sql.NullString
		added   sql.NullString
		state   string
		reason  string
	)
	dest := append([]any{&s.ID, &s.TenantID, &finding, &task, &s.UserID, &state, &reason, &added, &s.CreatedAt, &s.UpdatedAt}, extra...)
	if err := sc.Scan(dest...); err != nil {
		return s, err
	}
	s.State, s.Reason = participation.State(state), participation.Reason(reason)
	switch {
	case finding.Valid:
		id, err := shared.IDFromString(finding.String)
		if err != nil {
			return s, err
		}
		s.Item = participation.Item{Kind: participation.ItemFinding, ID: id}
	case task.Valid:
		id, err := shared.IDFromString(task.String)
		if err != nil {
			return s, err
		}
		s.Item = participation.Item{Kind: participation.ItemTask, ID: id}
	}
	if added.Valid {
		id, err := shared.IDFromString(added.String)
		if err == nil {
			s.AddedBy = &id
		}
	}
	return s, nil
}

// Get returns the person's row on the item, or nil.
func (r *WorkItemSubscriptionRepository) Get(ctx context.Context, tenantID shared.ID, item participation.Item, userID shared.ID) (*participation.Subscription, error) {
	col, err := itemColumn(item)
	if err != nil {
		return nil, err
	}
	row := r.db.QueryRowContext(ctx, `SELECT `+wisColumns+` FROM work_item_subscriptions s
		WHERE s.tenant_id = $1 AND s.`+col+` = $2 AND s.user_id = $3`,
		tenantID.String(), item.ID.String(), userID.String())
	s, err := scanSubscription(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no row is an answer, not an error
	}
	if err != nil {
		return nil, fmt.Errorf("get subscription: %w", err)
	}
	return &s, nil
}

// ListSubscribed returns the subscribed rows of the item with the person's
// name and avatar (never the email), oldest first.
func (r *WorkItemSubscriptionRepository) ListSubscribed(ctx context.Context, tenantID shared.ID, item participation.Item) ([]participation.Watcher, error) {
	col, err := itemColumn(item)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+wisColumns+`, COALESCE(u.name, ''), COALESCE(u.avatar_url, '')
		FROM work_item_subscriptions s
		JOIN users u ON u.id = s.user_id
		WHERE s.tenant_id = $1 AND s.`+col+` = $2 AND s.state = 'subscribed'
		ORDER BY s.created_at, s.id
		LIMIT $3`, tenantID.String(), item.ID.String(), participation.MaxWatchersPerItem*2)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	defer rows.Close()
	var out []participation.Watcher
	for rows.Next() {
		var w participation.Watcher
		s, err := scanSubscription(rows, &w.Name, &w.AvatarURL)
		if err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		w.Subscription = s
		out = append(out, w)
	}
	return out, rows.Err()
}

// CountSubscribed counts the subscribed rows of the item.
func (r *WorkItemSubscriptionRepository) CountSubscribed(ctx context.Context, tenantID shared.ID, item participation.Item) (int, error) {
	col, err := itemColumn(item)
	if err != nil {
		return 0, err
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM work_item_subscriptions
		WHERE tenant_id = $1 AND `+col+` = $2 AND state = 'subscribed'`,
		tenantID.String(), item.ID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count subscriptions: %w", err)
	}
	return n, nil
}

// upsertSubscribed inserts or updates a row to `subscribed` unless the item is
// at its limit (the person's own subscribed row does not count against it).
// reason and addedBy apply on insert and on a switch from unsubscribed.
func (r *WorkItemSubscriptionRepository) upsertSubscribed(ctx context.Context, tenantID shared.ID, item participation.Item, userID shared.ID, reason participation.Reason, addedBy *shared.ID) error {
	col, err := itemColumn(item)
	if err != nil {
		return err
	}
	var added any
	if addedBy != nil {
		added = addedBy.String()
	}
	// The cap is checked in the same statement as the write.
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO work_item_subscriptions (tenant_id, `+col+`, user_id, state, reason, added_by)
		SELECT $1, $2, $3, 'subscribed', $4, $5
		WHERE (SELECT COUNT(*) FROM work_item_subscriptions
		       WHERE tenant_id = $1 AND `+col+` = $2 AND state = 'subscribed' AND user_id <> $3) < $6
		ON CONFLICT (tenant_id, `+col+`, user_id) WHERE `+col+` IS NOT NULL
		DO UPDATE SET state = 'subscribed', reason = EXCLUDED.reason, added_by = EXCLUDED.added_by, updated_at = now()
		  WHERE work_item_subscriptions.state <> 'subscribed'`,
		tenantID.String(), item.ID.String(), userID.String(), string(reason), added, participation.MaxWatchersPerItem)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Either already subscribed (nothing to change) or at the limit.
		cur, gerr := r.Get(ctx, tenantID, item, userID)
		if gerr != nil {
			return gerr
		}
		if cur != nil && cur.State == participation.StateSubscribed {
			return nil
		}
		return participation.ErrWatcherLimit
	}
	return nil
}

// SetState writes the person's own choice.
func (r *WorkItemSubscriptionRepository) SetState(ctx context.Context, tenantID shared.ID, item participation.Item, userID shared.ID, state participation.State, reason participation.Reason) error {
	if state == participation.StateSubscribed {
		return r.upsertSubscribed(ctx, tenantID, item, userID, reason, nil)
	}
	col, err := itemColumn(item)
	if err != nil {
		return err
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO work_item_subscriptions (tenant_id, `+col+`, user_id, state, reason)
		VALUES ($1, $2, $3, 'unsubscribed', $4)
		ON CONFLICT (tenant_id, `+col+`, user_id) WHERE `+col+` IS NOT NULL
		DO UPDATE SET state = 'unsubscribed', updated_at = now()`,
		tenantID.String(), item.ID.String(), userID.String(), string(reason)); err != nil {
		return fmt.Errorf("unsubscribe: %w", err)
	}
	return nil
}

// Add subscribes a person on someone's behalf.
func (r *WorkItemSubscriptionRepository) Add(ctx context.Context, tenantID shared.ID, item participation.Item, userID, addedBy shared.ID) error {
	return r.upsertSubscribed(ctx, tenantID, item, userID, participation.ReasonAdded, &addedBy)
}

// AutoSubscribe records a person who took part. An existing row, subscribed or
// not, is never changed, so an explicit unsubscribe wins; at the limit nothing
// is added.
func (r *WorkItemSubscriptionRepository) AutoSubscribe(ctx context.Context, tenantID shared.ID, item participation.Item, userID shared.ID, reason participation.Reason) (bool, error) {
	col, err := itemColumn(item)
	if err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO work_item_subscriptions (tenant_id, `+col+`, user_id, state, reason)
		SELECT $1, $2, $3, 'subscribed', $4
		WHERE (SELECT COUNT(*) FROM work_item_subscriptions
		       WHERE tenant_id = $1 AND `+col+` = $2 AND state = 'subscribed') < $5
		ON CONFLICT DO NOTHING`,
		tenantID.String(), item.ID.String(), userID.String(), string(reason), participation.MaxWatchersPerItem)
	if err != nil {
		return false, fmt.Errorf("auto subscribe: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Remove deletes the person's row.
func (r *WorkItemSubscriptionRepository) Remove(ctx context.Context, tenantID shared.ID, item participation.Item, userID shared.ID) (bool, error) {
	col, err := itemColumn(item)
	if err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM work_item_subscriptions
		WHERE tenant_id = $1 AND `+col+` = $2 AND user_id = $3`,
		tenantID.String(), item.ID.String(), userID.String())
	if err != nil {
		return false, fmt.Errorf("remove subscription: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AssetOwners lists the named user owners of the asset a finding is on, so the
// People section can show whose system it is (context only: owners are not
// watchers).
func (r *WorkItemSubscriptionRepository) AssetOwners(ctx context.Context, tenantID, findingID shared.ID) ([]participation.AssetOwner, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT ao.user_id, COALESCE(u.name, ''), COALESCE(u.avatar_url, ''), ao.ownership_type
		FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		JOIN asset_owners ao ON ao.asset_id = a.id AND ao.user_id IS NOT NULL
		JOIN users u ON u.id = ao.user_id
		JOIN tenant_members tm ON tm.tenant_id = f.tenant_id AND tm.user_id = ao.user_id AND tm.status = 'active'
		WHERE f.tenant_id = $1 AND f.id = $2
		ORDER BY CASE ao.ownership_type WHEN 'primary' THEN 0 WHEN 'secondary' THEN 1 ELSE 2 END, u.name
		LIMIT 20`, tenantID.String(), findingID.String())
	if err != nil {
		return nil, fmt.Errorf("list asset owners: %w", err)
	}
	defer rows.Close()
	var out []participation.AssetOwner
	for rows.Next() {
		var o participation.AssetOwner
		if err := rows.Scan(&o.UserID, &o.Name, &o.AvatarURL, &o.Type); err != nil {
			return nil, fmt.Errorf("scan asset owner: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListStates returns the people who watch the item and the people who stopped
// watching it.
func (r *WorkItemSubscriptionRepository) ListStates(ctx context.Context, tenantID shared.ID, item participation.Item) (subscribed, unsubscribed []shared.ID, err error) {
	col, err := itemColumn(item)
	if err != nil {
		return nil, nil, err
	}
	// Subscribed rows are capped per item; unsubscribed rows are not, and
	// are read on their own: a LIMIT over both could drop an unsubscribe
	// and tell someone who opted out. They are ids of workspace members.
	if subscribed, err = r.listUsers(ctx, tenantID, col, item, participation.StateSubscribed, participation.MaxWatchersPerItem*4); err != nil {
		return nil, nil, err
	}
	if unsubscribed, err = r.listUsers(ctx, tenantID, col, item, participation.StateUnsubscribed, 0); err != nil {
		return nil, nil, err
	}
	return subscribed, unsubscribed, nil
}

// listUsers returns the users whose row on the item is in state (limit 0 = all).
func (r *WorkItemSubscriptionRepository) listUsers(ctx context.Context, tenantID shared.ID, col string, item participation.Item, state participation.State, limit int) ([]shared.ID, error) {
	q := `SELECT user_id FROM work_item_subscriptions WHERE tenant_id = $1 AND ` + col + ` = $2 AND state = $3 ORDER BY user_id`
	args := []any{tenantID.String(), item.ID.String(), string(state)}
	if limit > 0 {
		q += ` LIMIT $4`
		args = append(args, limit)
	}
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list subscription states: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan subscription state: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
