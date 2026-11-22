package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// NotificationGroupRepository stores notification groups (grouped channel
// alerts, docs/architecture/notification-system.md "Grouped alerts"). Every
// query filters on the tenant.
type NotificationGroupRepository struct {
	db *DB
}

// NewNotificationGroupRepository creates the repository.
func NewNotificationGroupRepository(db *DB) *NotificationGroupRepository {
	return &NotificationGroupRepository{db: db}
}

var _ outbox.GroupRepository = (*NotificationGroupRepository)(nil)

// aggregateTypeFinding is the aggregate type of a finding event.
const aggregateTypeFinding = "finding"

func pgInterval(d time.Duration) string { return fmt.Sprintf("%d milliseconds", d.Milliseconds()) }

// AddBatch implements outbox.GroupRepository: one transaction per group,
// whatever the number of items (a burst of one channel and kind costs a
// handful of statements per worker batch, not per event). The group row is
// locked by the upsert until its items are in, so a concurrent claim never
// closes a group with items half added.
func (r *NotificationGroupRepository) AddBatch(ctx context.Context, reqs []outbox.GroupAddRequest, now time.Time) ([]outbox.GroupAddResult, error) {
	type groupKey struct {
		tenant, integration shared.ID
		key                 string
	}
	results := make([]outbox.GroupAddResult, len(reqs))
	var order []groupKey
	byGroup := map[groupKey][]int{}
	for i, req := range reqs {
		k := groupKey{req.TenantID, req.IntegrationID, req.Key}
		if _, ok := byGroup[k]; !ok {
			order = append(order, k)
		}
		byGroup[k] = append(byGroup[k], i)
	}
	var firstErr error
	for _, k := range order {
		if err := r.addToGroup(ctx, reqs, byGroup[k], results, now); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return results, firstErr
}

// groupRow is one item row of a batch insert (jsonb_to_recordset).
type groupRow struct {
	ItemKey       string          `json:"item_key"`
	OutboxID      string          `json:"outbox_id"`
	EventType     string          `json:"event_type"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   *string         `json:"aggregate_id"`
	Title         string          `json:"title"`
	Body          string          `json:"body"`
	Severity      string          `json:"severity"`
	URL           string          `json:"url"`
	Metadata      json.RawMessage `json:"metadata"`
	Urgent        bool            `json:"urgent"`
	SentAlone     bool            `json:"sent_alone"`
	EventAt       time.Time       `json:"event_at"`
	Updates       int             `json:"updates"`
}

//nolint:cyclop // one transaction: burst check, open, KEV, dedupe, budget, insert, count
func (r *NotificationGroupRepository) addToGroup(ctx context.Context, reqs []outbox.GroupAddRequest, idx []int,
	results []outbox.GroupAddResult, now time.Time,
) error {
	first := reqs[idx[0]]
	tenant, integrationID := first.TenantID.String(), first.IntegrationID.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin group add: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// A group opened within the window after the previous one of this
	// channel and kind was sent is a burst: it collects until quiet.
	var burst bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM notification_groups
			WHERE tenant_id = $1 AND integration_id = $2 AND group_key = $3
			  AND status = 'closed' AND sent_count > 0 AND closed_at > $4)`,
		tenant, integrationID, first.Key, now.Add(-first.Window)).Scan(&burst); err != nil {
		return fmt.Errorf("read previous notification group: %w", err)
	}
	var (
		groupID    string
		urgentSent int
	)
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO notification_groups (tenant_id, integration_id, group_key, burst, opened_at, last_item_at, flush_at)
		VALUES ($1, $2, $3, $4, $5, $5, $6)
		ON CONFLICT (tenant_id, integration_id, group_key) WHERE status = 'open'
		DO UPDATE SET
			last_item_at = EXCLUDED.last_item_at,
			flush_at = CASE WHEN notification_groups.burst
				THEN LEAST(notification_groups.opened_at + $7::interval, EXCLUDED.last_item_at + $8::interval)
				ELSE notification_groups.flush_at END
		RETURNING id, urgent_sent`,
		tenant, integrationID, first.Key, burst, now, now.Add(first.Window),
		pgInterval(outbox.GroupMaxHold), pgInterval(first.Window)).Scan(&groupID, &urgentSent); err != nil {
		return fmt.Errorf("open notification group: %w", err)
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return fmt.Errorf("parse notification group id: %w", err)
	}

	// Known exploited: the tenant's findings in KEV among the items.
	kev := map[string]bool{}
	if first.UrgentAtOnce {
		var ids []string
		for _, i := range idx {
			if it := reqs[i].Item; it.AggregateType == aggregateTypeFinding && it.AggregateID != nil {
				ids = append(ids, it.AggregateID.String())
			}
		}
		if len(ids) > 0 {
			if kev, err = knownExploited(ctx, tx, tenant, ids); err != nil {
				return err
			}
		}
	}

	// One row per item: the latest event of a finding wins and counts the
	// events folded into it. The urgent budget goes to items in order.
	last := map[string]int{}
	events := map[string]int{}
	keyOf := make([]string, len(idx))
	for n, i := range idx {
		k := reqs[i].Item.ItemKey
		if k == "" {
			k = reqs[i].Item.OutboxID.String()
		}
		keyOf[n] = truncateRunes(k, 100)
		last[keyOf[n]] = n
		events[keyOf[n]]++
	}
	// Results are set only once the transaction commits: a delivery is
	// marked grouped only when its group holds it.
	sendAlone := make([]bool, len(idx))
	budget := outbox.GroupUrgentPerWindow - urgentSent
	rows := make([]groupRow, 0, len(last))
	alone := 0
	for n, i := range idx {
		if last[keyOf[n]] != n {
			continue // folded into the item's latest event
		}
		it := reqs[i].Item
		urgent := it.Urgent || (it.AggregateID != nil && kev[it.AggregateID.String()])
		goesAlone := urgent && reqs[i].UrgentAtOnce && budget > 0
		if goesAlone {
			budget--
			alone++
			sendAlone[n] = true
		}
		metadata, err := json.Marshal(it.Metadata)
		if err != nil || it.Metadata == nil {
			metadata = []byte("{}")
		}
		var aggregateID *string
		if it.AggregateID != nil {
			v := it.AggregateID.String()
			aggregateID = &v
		}
		rows = append(rows, groupRow{ItemKey: keyOf[n], OutboxID: it.OutboxID.String(), EventType: it.EventType,
			AggregateType: it.AggregateType, AggregateID: aggregateID, Title: truncateRunes(it.Title, 500), Body: it.Body,
			Severity: it.Severity, URL: truncateRunes(it.URL, 2000), Metadata: metadata, Urgent: urgent,
			SentAlone: goesAlone, EventAt: it.EventAt, Updates: events[keyOf[n]]})
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("encode notification group items: %w", err)
	}
	var inserted int
	if err := tx.QueryRowContext(ctx, `
		WITH up AS (
			INSERT INTO notification_group_items (group_id, tenant_id, item_key, outbox_id, event_type, aggregate_type,
				aggregate_id, title, body, severity, url, metadata, urgent, sent_alone, update_count, event_at, added_at, updated_at)
			SELECT $1, $2, x.item_key, x.outbox_id, x.event_type, x.aggregate_type, x.aggregate_id, x.title,
			       COALESCE(x.body, ''), x.severity, COALESCE(x.url, ''), COALESCE(x.metadata, '{}'::jsonb),
			       x.urgent, x.sent_alone, x.updates, x.event_at, $4, $4
			FROM jsonb_to_recordset($3::jsonb) AS x(item_key text, outbox_id uuid, event_type text, aggregate_type text,
				aggregate_id uuid, title text, body text, severity text, url text, metadata jsonb, urgent boolean,
				sent_alone boolean, event_at timestamptz, updates integer)
			ON CONFLICT (group_id, item_key) DO UPDATE SET
				outbox_id = EXCLUDED.outbox_id, event_type = EXCLUDED.event_type,
				title = EXCLUDED.title, body = EXCLUDED.body, severity = EXCLUDED.severity,
				url = EXCLUDED.url, metadata = EXCLUDED.metadata, urgent = EXCLUDED.urgent,
				sent_alone = EXCLUDED.sent_alone, event_at = EXCLUDED.event_at,
				update_count = notification_group_items.update_count + EXCLUDED.update_count,
				updated_at = EXCLUDED.updated_at
			RETURNING (xmax = 0) AS inserted)
		SELECT count(*) FILTER (WHERE inserted) FROM up`,
		groupID, tenant, payload, now).Scan(&inserted); err != nil {
		return fmt.Errorf("add notification group items: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE notification_groups SET item_count = item_count + $3, urgent_sent = urgent_sent + $4
		WHERE tenant_id = $1 AND id = $2`, tenant, groupID, inserted, alone); err != nil {
		return fmt.Errorf("count notification group items: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit group add: %w", err)
	}
	for n, i := range idx {
		results[i] = outbox.GroupAddResult{GroupID: gid, SendAlone: sendAlone[n]}
	}
	return nil
}

// knownExploited returns the ids among ids of the tenant's findings in KEV.
func knownExploited(ctx context.Context, q executor, tenant string, ids []string) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT f.id::text FROM unnest($2::uuid[]) AS x(id)
		JOIN findings f ON f.tenant_id = $1 AND f.id = x.id WHERE f.is_in_kev`, tenant, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read known exploited findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan known exploited finding: %w", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate known exploited findings: %w", err)
	}
	return out, nil
}

const groupColumns = `id, tenant_id, integration_id, group_key, burst, item_count, urgent_sent,
	opened_at, last_item_at, flush_at, closed_at, sent_count, outbox_id`

func scanGroup(row interface{ Scan(...any) error }) (*outbox.Group, error) {
	var (
		g                       outbox.Group
		id, tenant, integration string
		closedAt                sql.NullTime
		outboxID                sql.NullString
	)
	if err := row.Scan(&id, &tenant, &integration, &g.Key, &g.Burst, &g.ItemCount, &g.UrgentSent,
		&g.OpenedAt, &g.LastItemAt, &g.FlushAt, &closedAt, &g.SentCount, &outboxID); err != nil {
		return nil, err
	}
	var err error
	if g.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("parse group id: %w", err)
	}
	if g.TenantID, err = shared.IDFromString(tenant); err != nil {
		return nil, fmt.Errorf("parse group tenant: %w", err)
	}
	if g.IntegrationID, err = shared.IDFromString(integration); err != nil {
		return nil, fmt.Errorf("parse group integration: %w", err)
	}
	if closedAt.Valid {
		t := closedAt.Time
		g.ClosedAt = &t
	}
	if outboxID.Valid {
		if oid, err := shared.IDFromString(outboxID.String); err == nil {
			g.OutboxID = &oid
		}
	}
	return &g, nil
}

// ClaimDue implements outbox.GroupRepository: one transaction per group,
// FOR UPDATE SKIP LOCKED, so two workers never claim the same group and a
// group still receiving an item is skipped until that item is in.
func (r *NotificationGroupRepository) ClaimDue(ctx context.Context, now time.Time, limit int, fn outbox.GroupClaimFunc) (int, error) {
	closed := 0
	for closed < limit {
		done, err := r.claimOne(ctx, now, fn)
		if err != nil {
			return closed, err
		}
		if !done {
			return closed, nil
		}
		closed++
	}
	return closed, nil
}

func (r *NotificationGroupRepository) claimOne(ctx context.Context, now time.Time, fn outbox.GroupClaimFunc) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin group claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	g, err := scanGroup(tx.QueryRowContext(ctx, `
		SELECT `+groupColumns+` FROM notification_groups
		WHERE status = 'open' AND (flush_at <= $1 OR (NOT burst AND item_count >= $2))
		ORDER BY flush_at
		LIMIT 1
		FOR UPDATE SKIP LOCKED`, now, outbox.GroupEarlyFlushItems))
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim notification group: %w", err)
	}
	items, err := r.items(ctx, tx, g.TenantID, g.ID)
	if err != nil {
		return false, err
	}
	outboxID, sent, err := fn(ctx, tx, *g, items)
	if err != nil {
		return false, fmt.Errorf("send notification group: %w", err)
	}
	var oid *string
	if outboxID != nil {
		s := outboxID.String()
		oid = &s
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE notification_groups SET status = 'closed', closed_at = $3, sent_count = $4, outbox_id = $5
		WHERE tenant_id = $1 AND id = $2`, g.TenantID.String(), g.ID.String(), now, sent, oid); err != nil {
		return false, fmt.Errorf("close notification group: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit group claim: %w", err)
	}
	return true, nil
}

// Get implements outbox.GroupRepository.
func (r *NotificationGroupRepository) Get(ctx context.Context, tenantID, groupID shared.ID) (*outbox.Group, error) {
	g, err := scanGroup(r.db.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM notification_groups
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), groupID.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get notification group: %w", err)
	}
	return g, nil
}

// Items implements outbox.GroupRepository.
func (r *NotificationGroupRepository) Items(ctx context.Context, tenantID, groupID shared.ID) ([]outbox.GroupItem, error) {
	return r.items(ctx, r.db, tenantID, groupID)
}

func (r *NotificationGroupRepository) items(ctx context.Context, q executor, tenantID, groupID shared.ID) ([]outbox.GroupItem, error) {
	out, findings, err := groupItemRows(ctx, q, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return out, nil
	}
	// The findings' current state, in one lookup joined on the id list (a
	// join with the items, or id = ANY, planned before the statistics catch
	// up with a burst, compared every finding of the tenant with every item:
	// seconds for 5,000; this is a hash join, milliseconds).
	frows, err := q.QueryContext(ctx, `SELECT f.id::text, COALESCE(f.priority_class, ''), f.asset_id::text
		FROM unnest($2::uuid[]) AS x(id)
		JOIN findings f ON f.tenant_id = $1 AND f.id = x.id`, tenantID.String(), pq.Array(findings))
	if err != nil {
		return nil, fmt.Errorf("read notification group findings: %w", err)
	}
	defer func() { _ = frows.Close() }()
	type state struct{ class, asset string }
	current := make(map[string]state, len(findings))
	for frows.Next() {
		var id, class string
		var asset sql.NullString
		if err := frows.Scan(&id, &class, &asset); err != nil {
			return nil, fmt.Errorf("scan notification group finding: %w", err)
		}
		current[id] = state{class, asset.String}
	}
	if err := frows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification group findings: %w", err)
	}
	for i := range out {
		if out[i].AggregateType == aggregateTypeFinding && out[i].AggregateID != nil {
			st := current[out[i].AggregateID.String()]
			out[i].CurrentPriorityClass, out[i].AssetID = st.class, st.asset
		}
	}
	return out, nil
}

// groupItemRows reads a group's item rows and the finding ids among them.
func groupItemRows(ctx context.Context, q executor, tenantID, groupID shared.ID) ([]outbox.GroupItem, []string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT i.item_key, i.outbox_id, i.event_type, i.aggregate_type, i.aggregate_id, i.title, i.body,
		       i.severity, i.url, i.metadata, i.urgent, i.sent_alone, i.update_count, i.event_at
		FROM notification_group_items i
		WHERE i.tenant_id = $1 AND i.group_id = $2
		ORDER BY i.event_at, i.item_key`, tenantID.String(), groupID.String())
	if err != nil {
		return nil, nil, fmt.Errorf("list notification group items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		out      []outbox.GroupItem
		findings []string
	)
	for rows.Next() {
		var (
			it          outbox.GroupItem
			outboxID    string
			aggregateID sql.NullString
			metadata    []byte
		)
		if err := rows.Scan(&it.ItemKey, &outboxID, &it.EventType, &it.AggregateType, &aggregateID, &it.Title, &it.Body,
			&it.Severity, &it.URL, &metadata, &it.Urgent, &it.SentAlone, &it.UpdateCount, &it.EventAt); err != nil {
			return nil, nil, fmt.Errorf("scan notification group item: %w", err)
		}
		it.OutboxID, _ = shared.IDFromString(outboxID)
		if aggregateID.Valid {
			if u, err := uuid.Parse(aggregateID.String); err == nil {
				it.AggregateID = &u
				if it.AggregateType == aggregateTypeFinding {
					findings = append(findings, u.String())
				}
			}
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &it.Metadata)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate notification group items: %w", err)
	}
	return out, findings, nil
}

// DeleteClosedBefore implements outbox.GroupRepository (retention; its
// items go with it).
func (r *NotificationGroupRepository) DeleteClosedBefore(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM notification_groups WHERE status = 'closed' AND closed_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("delete old notification groups: %w", err)
	}
	return res.RowsAffected()
}
