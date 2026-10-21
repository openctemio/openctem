package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TicketCreatePolicyRepository stores ticket create policies, holds and the
// daily counter (docs/architecture/ticket-create-policy.md). Every query is
// tenant-scoped except DueHolds and PurgeDaily, the background job's
// system-wide reads; each row they return carries its tenant.
type TicketCreatePolicyRepository struct {
	db *DB
}

// NewTicketCreatePolicyRepository creates the repository.
func NewTicketCreatePolicyRepository(db *DB) *TicketCreatePolicyRepository {
	return &TicketCreatePolicyRepository{db: db}
}

var _ ticketpolicy.Repository = (*TicketCreatePolicyRepository)(nil)

// utcToday is today's UTC date in SQL.
const utcToday = `(now() AT TIME ZONE 'UTC')::date`

// Get returns the integration's policy, or the defaults when none is stored.
func (r *TicketCreatePolicyRepository) Get(ctx context.Context, tenantID, integrationID shared.ID) (ticketpolicy.Policy, error) {
	var (
		p   ticketpolicy.Policy
		sev string
		by  sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT min_severity, min_priority_class, always_kev, daily_cap, updated_by, updated_at
		FROM ticket_create_policies WHERE tenant_id = $1 AND integration_id = $2`,
		tenantID.String(), integrationID.String()).Scan(&sev, &p.MinPriorityClass, &p.AlwaysKEV, &p.DailyCap, &by, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ticketpolicy.Default(), nil
	}
	if err != nil {
		return ticketpolicy.Policy{}, fmt.Errorf("get ticket create policy: %w", err)
	}
	p.MinSeverity = vulnerability.Severity(sev)
	p.UpdatedBy = optID(by)
	return p, nil
}

// Save stores the integration's policy. The integration must belong to the
// tenant (composite foreign key); otherwise it is shared.ErrNotFound.
func (r *TicketCreatePolicyRepository) Save(ctx context.Context, tenantID, integrationID shared.ID, p ticketpolicy.Policy) (ticketpolicy.Policy, error) {
	var by any
	if p.UpdatedBy != nil {
		by = p.UpdatedBy.String()
	}
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO ticket_create_policies
			(tenant_id, integration_id, min_severity, min_priority_class, always_kev, daily_cap, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, integration_id) DO UPDATE SET
			min_severity = EXCLUDED.min_severity, min_priority_class = EXCLUDED.min_priority_class,
			always_kev = EXCLUDED.always_kev, daily_cap = EXCLUDED.daily_cap,
			updated_by = EXCLUDED.updated_by, updated_at = now()
		RETURNING updated_at`,
		tenantID.String(), integrationID.String(), string(p.MinSeverity), p.MinPriorityClass, p.AlwaysKEV, p.DailyCap, by,
	).Scan(&p.UpdatedAt)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return ticketpolicy.Policy{}, fmt.Errorf("%w: integration not found", shared.ErrNotFound)
		}
		return ticketpolicy.Policy{}, fmt.Errorf("save ticket create policy: %w", err)
	}
	return p, nil
}

// Stats counts the integration's holds by reason and today's creates.
func (r *TicketCreatePolicyRepository) Stats(ctx context.Context, tenantID, integrationID shared.ID) (ticketpolicy.Stats, error) {
	st := ticketpolicy.Stats{HeldByReason: map[string]int{}}
	rows, err := r.db.QueryContext(ctx, `
		SELECT reason, count(*) FROM ticket_create_holds
		WHERE tenant_id = $1 AND integration_id = $2 GROUP BY reason`, tenantID.String(), integrationID.String())
	if err != nil {
		return st, fmt.Errorf("count ticket holds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var reason string
		var n int
		if err := rows.Scan(&reason, &n); err != nil {
			return st, fmt.Errorf("scan ticket hold count: %w", err)
		}
		st.HeldByReason[reason] = n
	}
	if err := rows.Err(); err != nil {
		return st, fmt.Errorf("count ticket holds: %w", err)
	}
	err = r.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(created), 0) FROM ticket_create_daily
		WHERE tenant_id = $1 AND integration_id = $2 AND day = `+utcToday,
		tenantID.String(), integrationID.String()).Scan(&st.CreatedToday)
	if err != nil {
		return st, fmt.Errorf("count today's tickets: %w", err)
	}
	return st, nil
}

// passSQL is the policy predicate over findings alias f; $sev, $cls, $kev
// are the positions of the allowed severities, classes and the KEV switch.
// It mirrors ticketpolicy.Policy.Evaluate (without the open check).
func passSQL(sev, cls, kev int) string {
	return fmt.Sprintf(`(f.severity = ANY($%d) OR COALESCE(f.priority_class, '') = ANY($%d) OR ($%d AND f.is_in_kev))`, sev, cls, kev)
}

// Preview counts what a policy would let through: findings first seen in
// the last 30 days, and the integration's current holds.
func (r *TicketCreatePolicyRepository) Preview(ctx context.Context, tenantID, integrationID shared.ID, p ticketpolicy.Policy) (ticketpolicy.Preview, error) {
	var out ticketpolicy.Preview
	sev, cls := pq.Array(p.AllowedSeverities()), pq.Array(nonNil(p.AllowedClasses()))
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*), count(*) FILTER (WHERE `+passSQL(2, 3, 4)+`)
		FROM findings f WHERE f.tenant_id = $1 AND f.created_at >= now() - interval '30 days'`,
		tenantID.String(), sev, cls, p.AlwaysKEV).Scan(&out.Last30DaysTotal, &out.Last30DaysPass)
	if err != nil {
		return out, fmt.Errorf("preview ticket policy: %w", err)
	}
	err = r.db.QueryRowContext(ctx, `
		SELECT count(*), count(*) FILTER (WHERE `+passSQL(3, 4, 5)+` AND `+vulnerability.OpenStatusSQL("f.status")+`)
		FROM ticket_create_holds h
		JOIN findings f ON f.tenant_id = h.tenant_id AND f.id = h.finding_id
		WHERE h.tenant_id = $1 AND h.integration_id = $2`,
		tenantID.String(), integrationID.String(), sev, cls, p.AlwaysKEV).Scan(&out.HeldNow, &out.HeldWouldPass)
	if err != nil {
		return out, fmt.Errorf("preview ticket holds: %w", err)
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// PutHold records (or refreshes) a hold; held_at keeps the first hold time.
func (r *TicketCreatePolicyRepository) PutHold(ctx context.Context, h ticketpolicy.Hold) error {
	detail := h.Detail
	if len(detail) > 500 {
		detail = detail[:500]
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ticket_create_holds (tenant_id, integration_id, finding_id, reason, detail)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, integration_id, finding_id) DO UPDATE SET
			reason = EXCLUDED.reason, detail = EXCLUDED.detail, checked_at = now()`,
		h.TenantID.String(), h.IntegrationID.String(), h.FindingID.String(), h.Reason, detail)
	if err != nil {
		return fmt.Errorf("record ticket hold: %w", err)
	}
	return nil
}

// DeleteHold removes one hold.
func (r *TicketCreatePolicyRepository) DeleteHold(ctx context.Context, tenantID, integrationID, findingID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM ticket_create_holds
		WHERE tenant_id = $1 AND integration_id = $2 AND finding_id = $3`,
		tenantID.String(), integrationID.String(), findingID.String())
	if err != nil {
		return fmt.Errorf("delete ticket hold: %w", err)
	}
	return nil
}

// DeleteFindingHolds removes every hold of a finding.
func (r *TicketCreatePolicyRepository) DeleteFindingHolds(ctx context.Context, tenantID, findingID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM ticket_create_holds WHERE tenant_id = $1 AND finding_id = $2`,
		tenantID.String(), findingID.String())
	if err != nil {
		return fmt.Errorf("delete ticket holds: %w", err)
	}
	return nil
}

// ListFindingHolds lists a finding's holds (one per integration).
func (r *TicketCreatePolicyRepository) ListFindingHolds(ctx context.Context, tenantID, findingID shared.ID) ([]ticketpolicy.Hold, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT integration_id, reason, detail, held_at, checked_at FROM ticket_create_holds
		WHERE tenant_id = $1 AND finding_id = $2 ORDER BY held_at LIMIT 50`, tenantID.String(), findingID.String())
	if err != nil {
		return nil, fmt.Errorf("list ticket holds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ticketpolicy.Hold{}
	for rows.Next() {
		h := ticketpolicy.Hold{TenantID: tenantID, FindingID: findingID}
		var iid string
		if err := rows.Scan(&iid, &h.Reason, &h.Detail, &h.HeldAt, &h.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan ticket hold: %w", err)
		}
		h.IntegrationID, _ = shared.IDFromString(iid)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list ticket holds: %w", err)
	}
	return out, nil
}

// DueHolds lists holds to re-check (see ticketpolicy.Repository).
func (r *TicketCreatePolicyRepository) DueHolds(ctx context.Context, limit int, retryAfter time.Duration) ([]ticketpolicy.Candidate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT h.tenant_id, h.integration_id, h.finding_id, h.reason, h.detail, h.held_at, h.checked_at,
			f.severity, COALESCE(f.priority_class, ''), f.is_in_kev, (`+vulnerability.OpenStatusSQL("f.status")+`),
			EXISTS (SELECT 1 FROM ticket_links l WHERE l.tenant_id = h.tenant_id AND l.integration_id = h.integration_id
				AND l.finding_id = h.finding_id AND l.state = 'active'),
			p.min_severity, p.min_priority_class, p.always_kev, p.daily_cap, p.updated_at
		FROM ticket_create_holds h
		JOIN findings f ON f.tenant_id = h.tenant_id AND f.id = h.finding_id
		LEFT JOIN ticket_create_policies p ON p.tenant_id = h.tenant_id AND p.integration_id = h.integration_id
		WHERE f.updated_at > h.checked_at
			OR p.updated_at > h.checked_at
			OR (h.reason = 'daily_cap' AND (h.checked_at AT TIME ZONE 'UTC')::date < `+utcToday+`)
			OR (h.reason = 'create_failed' AND h.checked_at < now() - make_interval(secs => $2))
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			h.held_at
		LIMIT $1`, limit, retryAfter.Seconds())
	if err != nil {
		return nil, fmt.Errorf("list due ticket holds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ticketpolicy.Candidate{}
	for rows.Next() {
		var (
			c             ticketpolicy.Candidate
			tid, iid, fid string
			pSev, pCls    sql.NullString
			pKEV          sql.NullBool
			pCap          sql.NullInt64
			pAt           sql.NullTime
		)
		if err := rows.Scan(&tid, &iid, &fid, &c.Reason, &c.Detail, &c.HeldAt, &c.CheckedAt,
			&c.Signals.Severity, &c.Signals.PriorityClass, &c.Signals.InKEV, &c.Signals.Open, &c.Linked,
			&pSev, &pCls, &pKEV, &pCap, &pAt); err != nil {
			return nil, fmt.Errorf("scan due ticket hold: %w", err)
		}
		c.TenantID, _ = shared.IDFromString(tid)
		c.IntegrationID, _ = shared.IDFromString(iid)
		c.FindingID, _ = shared.IDFromString(fid)
		c.Policy = ticketpolicy.Default()
		if pSev.Valid {
			c.Policy = ticketpolicy.Policy{
				MinSeverity: vulnerability.Severity(pSev.String), MinPriorityClass: pCls.String,
				AlwaysKEV: pKEV.Bool, DailyCap: int(pCap.Int64), UpdatedAt: pAt.Time,
			}
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list due ticket holds: %w", err)
	}
	return out, nil
}

// Reserve takes one slot of today's cap (see ticketpolicy.Repository).
func (r *TicketCreatePolicyRepository) Reserve(ctx context.Context, tenantID, integrationID shared.ID, dailyCap int) (bool, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO ticket_create_daily (tenant_id, integration_id, day, created)
		VALUES ($1, $2, `+utcToday+`, 1)
		ON CONFLICT (tenant_id, integration_id, day) DO UPDATE SET created = ticket_create_daily.created + 1
			WHERE $3 = 0 OR ticket_create_daily.created < $3
		RETURNING created`, tenantID.String(), integrationID.String(), dailyCap).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reserve ticket slot: %w", err)
	}
	return true, nil
}

// Release gives one of today's slots back.
func (r *TicketCreatePolicyRepository) Release(ctx context.Context, tenantID, integrationID shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ticket_create_daily SET created = created - 1
		WHERE tenant_id = $1 AND integration_id = $2 AND day = `+utcToday+` AND created > 0`,
		tenantID.String(), integrationID.String())
	if err != nil {
		return fmt.Errorf("release ticket slot: %w", err)
	}
	return nil
}

// PurgeDaily deletes counter rows older than olderThan.
func (r *TicketCreatePolicyRepository) PurgeDaily(ctx context.Context, olderThan time.Duration) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM ticket_create_daily
		WHERE day < (now() AT TIME ZONE 'UTC')::date - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return 0, fmt.Errorf("purge ticket counters: %w", err)
	}
	return res.RowsAffected()
}

// findingLockWait bounds how long a create waits for another create of the
// same finding (a tracker call is the longest thing held under the lock).
const findingLockWait = 2 * time.Minute

// LockFinding takes a session-level advisory lock keyed on tenant, integration
// and finding, on a connection of its own (see ticketpolicy.Repository).
func (r *TicketCreatePolicyRepository) LockFinding(ctx context.Context, tenantID, integrationID, findingID shared.ID) (func(), error) {
	key := tenantID.String() + "|" + integrationID.String() + "|" + findingID.String()
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("lock finding for ticket create: %w", err)
	}
	wctx, cancel := context.WithTimeout(ctx, findingLockWait)
	defer cancel()
	if _, err := conn.ExecContext(wctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
		// A canceled wait may leave the lock request behind: drop the connection.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
		return nil, fmt.Errorf("lock finding for ticket create: %w", err)
	}
	return func() {
		uctx, ucancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ucancel()
		if _, err := conn.ExecContext(uctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key); err != nil {
			// Never hand a connection that may still hold the lock back to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = conn.Close()
	}, nil
}
