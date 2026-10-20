package postgres

// Emerging-threat alerts (docs/rfcs/RFC-117-emerging-threat-alerts.md).
// Every statement on threat_alerts, threat_alert_assets, threat_alert_queue
// and threat_alert_tenant_state carries the organization, except the
// planner's platform-wide reads of the queue and of the organizations a
// public event affects, and the resolution of a rejected CVE, which are
// named for what they do.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnevent"
)

// ThreatAlertRepository persists emerging-threat alerts.
type ThreatAlertRepository struct {
	db *DB
}

// NewThreatAlertRepository creates a ThreatAlertRepository.
func NewThreatAlertRepository(db *DB) *ThreatAlertRepository { return &ThreatAlertRepository{db: db} }

var (
	_ threatalert.PlannerStore = (*ThreatAlertRepository)(nil)
	_ threatalert.ReadStore    = (*ThreatAlertRepository)(nil)
)

const cursorPlanner = "planner"

// openAlertStates is the SQL list of open alert states.
const openAlertStates = `('new', 'acknowledged', 'remediating')`

// PlannerCursor (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) PlannerCursor(ctx context.Context) (int64, error) {
	var pos int64
	err := r.db.QueryRowContext(ctx, `SELECT position FROM vuln_event_cursors WHERE name = $1`, cursorPlanner).Scan(&pos)
	if errors.Is(err, sql.ErrNoRows) {
		// First run: start at the newest event (the baseline covers the past).
		if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(max(id), 0) FROM vuln_events`).Scan(&pos); err != nil {
			return 0, fmt.Errorf("planner cursor: %w", err)
		}
		return pos, r.SetPlannerCursor(ctx, pos)
	}
	if err != nil {
		return 0, fmt.Errorf("planner cursor: %w", err)
	}
	return pos, nil
}

// SetPlannerCursor (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) SetPlannerCursor(ctx context.Context, id int64) error {
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO vuln_event_cursors (name, position) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET position = EXCLUDED.position, updated_at = now()`, cursorPlanner, id); err != nil {
		return fmt.Errorf("set planner cursor: %w", err)
	}
	return nil
}

// EventsAfter (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) EventsAfter(ctx context.Context, id int64, limit int) ([]vulnevent.Event, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, vuln_id, kind, at, source_at, detail FROM vuln_events WHERE id > $1 ORDER BY id LIMIT $2`, id, limit)
	if err != nil {
		return nil, fmt.Errorf("events after: %w", err)
	}
	defer rows.Close()
	var out []vulnevent.Event
	for rows.Next() {
		var e vulnevent.Event
		var kind string
		var src sql.NullTime
		var detail []byte
		if err := rows.Scan(&e.ID, &e.VulnID, &kind, &e.At, &src, &detail); err != nil {
			return nil, fmt.Errorf("events after: %w", err)
		}
		e.Kind = vulnevent.Kind(kind)
		if src.Valid {
			t := src.Time
			e.SourceAt = &t
		}
		_ = json.Unmarshal(detail, &e.Detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

// TenantsAffectedBy (see threatalert.PlannerStore). Platform-wide by
// design: it answers which organizations to plan, and its result never
// leaves the planner.
func (r *ThreatAlertRepository) TenantsAffectedBy(ctx context.Context, vulnID string) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT f.tenant_id FROM findings f
		WHERE f.cve_id = $1 AND `+vulnerability.OpenStatusSQL("f.status")+`
		UNION
		SELECT DISTINCT s.tenant_id FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id
		WHERE s.superseded_at IS NULL AND (v.normalized IS NULL OR v.raw = '')
		  AND s.product_id IN (SELECT product_id FROM vulnerability_affected WHERE cve_id = $1)`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("tenants affected: %w", err)
	}
	return scanIDs(rows)
}

// Enqueue (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) Enqueue(ctx context.Context, items []threatalert.QueueItem) error {
	if len(items) == 0 {
		return nil
	}
	tenants := make([]string, 0, len(items))
	vulns := make([]string, 0, len(items))
	for _, it := range items {
		tenants, vulns = append(tenants, it.TenantID.String()), append(vulns, it.VulnID)
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO threat_alert_queue (tenant_id, vuln_id)
		SELECT t, v FROM unnest($1::uuid[], $2::text[]) AS x(t, v)
		WHERE EXISTS (SELECT 1 FROM tenants WHERE id = x.t)
		ON CONFLICT (tenant_id, vuln_id) DO NOTHING`, pq.Array(tenants), pq.Array(vulns)); err != nil {
		return fmt.Errorf("enqueue alerts: %w", err)
	}
	return nil
}

// Dequeue (see threatalert.PlannerStore). Platform-wide: the planner drains
// every organization's queue.
func (r *ThreatAlertRepository) Dequeue(ctx context.Context, limit int) ([]threatalert.QueueItem, error) {
	rows, err := r.db.QueryContext(ctx, `
		DELETE FROM threat_alert_queue q USING (
			SELECT tenant_id, vuln_id FROM threat_alert_queue ORDER BY queued_at LIMIT $1 FOR UPDATE SKIP LOCKED
		) x WHERE q.tenant_id = x.tenant_id AND q.vuln_id = x.vuln_id
		RETURNING q.tenant_id, q.vuln_id`, limit)
	if err != nil {
		return nil, fmt.Errorf("dequeue alerts: %w", err)
	}
	defer rows.Close()
	var out []threatalert.QueueItem
	for rows.Next() {
		var it threatalert.QueueItem
		if err := rows.Scan(&it.TenantID, &it.VulnID); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Vuln (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) Vuln(ctx context.Context, vulnID string, eventsSince time.Time) (*threatalert.Vuln, error) {
	v := threatalert.Vuln{ID: vulnID}
	var sev, vector, desc, status, ransomware, lastKind sql.NullString
	var score, epss sql.NullFloat64
	var published, kevAdded, lastAt, lastSource sql.NullTime
	var inKEV, known bool
	err := r.db.QueryRowContext(ctx, `
		SELECT r.cve_id IS NOT NULL OR k.cve_id IS NOT NULL OR e.cve_id IS NOT NULL OR ev.kind IS NOT NULL,
			r.severity, r.cvss_vector, r.description, r.status, r.cvss_score, r.published_at,
			k.cve_id IS NOT NULL, k.date_added::timestamptz, k.known_ransomware_campaign_use,
			e.epss_score::float8, ev.kind, ev.at, ev.source_at
		FROM (SELECT $1::text AS id) x
		LEFT JOIN cve_records r ON r.cve_id = x.id
		LEFT JOIN kev_catalog k ON k.cve_id = x.id
		LEFT JOIN epss_scores e ON e.cve_id = x.id
		LEFT JOIN LATERAL (
			SELECT kind, at, source_at FROM vuln_events WHERE vuln_id = x.id AND at >= $2 ORDER BY at DESC, id DESC LIMIT 1
		) ev ON true`, vulnID, eventsSince).
		Scan(&known, &sev, &vector, &desc, &status, &score, &published, &inKEV, &kevAdded, &ransomware, &epss, &lastKind, &lastAt, &lastSource)
	if err != nil {
		return nil, fmt.Errorf("vuln %s: %w", vulnID, err)
	}
	if !known {
		return nil, nil
	}
	v.Severity, v.CVSSVector, v.Description = sev.String, vector.String, desc.String
	v.Rejected = vulnevent.IsRejected(status.String)
	if score.Valid {
		f := score.Float64
		v.CVSSScore = &f
	}
	if published.Valid {
		t := published.Time
		v.Published = &t
	}
	v.InKEV = inKEV
	v.KEVRansomware = strings.EqualFold(ransomware.String, "Known")
	if kevAdded.Valid {
		t := kevAdded.Time
		v.KEVDateAdded = &t
	}
	if epss.Valid {
		f := epss.Float64
		v.EPSS = &f
	}
	v.LastEventKind = lastKind.String
	if lastAt.Valid {
		t := lastAt.Time
		v.LastEventAt = &t
	}
	switch {
	case lastSource.Valid:
		t := lastSource.Time
		v.SourceAt = &t
	case lastAt.Valid:
		t := lastAt.Time
		v.SourceAt = &t
	}
	return &v, nil
}

// AffectedAssets (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) AffectedAssets(ctx context.Context, tenantID shared.ID, vulnID string) ([]threatalert.Asset, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH products AS (
			SELECT DISTINCT product_id FROM vulnerability_affected WHERE cve_id = $2
		), conf AS (
			SELECT DISTINCT ON (f.asset_id) f.asset_id, f.id AS finding_id, COALESCE(f.confidence, 100) AS confidence
			FROM findings f
			WHERE f.tenant_id = $1 AND f.cve_id = $2 AND f.asset_id IS NOT NULL AND `+vulnerability.OpenStatusSQL("f.status")+`
			ORDER BY f.asset_id, COALESCE(f.confidence, 100) DESC, f.id
		), poss AS (
			SELECT DISTINCT ON (s.asset_id) s.asset_id, p.name AS product, v.raw AS version, s.confidence
			FROM asset_software s
			JOIN software_versions v ON v.id = s.software_version_id
			JOIN software_products p ON p.id = s.product_id
			WHERE s.tenant_id = $1 AND s.superseded_at IS NULL AND (v.normalized IS NULL OR v.raw = '')
			  AND s.product_id IN (SELECT product_id FROM products)
			  AND NOT EXISTS (SELECT 1 FROM conf WHERE conf.asset_id = s.asset_id)
			ORDER BY s.asset_id, s.confidence DESC, s.id
		), rows AS (
			SELECT c.asset_id, c.finding_id, c.confidence, sw.product, sw.version, false AS possible
			FROM conf c
			LEFT JOIN LATERAL (
				SELECT p.name AS product, v.raw AS version
				FROM asset_software s
				JOIN software_versions v ON v.id = s.software_version_id
				JOIN software_products p ON p.id = s.product_id
				WHERE s.tenant_id = $1 AND s.asset_id = c.asset_id AND s.superseded_at IS NULL
				  AND s.product_id IN (SELECT product_id FROM products)
				ORDER BY s.last_seen_at DESC LIMIT 1
			) sw ON true
			UNION ALL
			SELECT asset_id, NULL, confidence, product, version, true FROM poss
		)
		SELECT x.asset_id, a.name, a.asset_type, x.finding_id, x.confidence, COALESCE(x.product, ''), COALESCE(x.version, ''),
			x.possible, (a.exposure = 'public' OR COALESCE(a.is_internet_accessible, false)), COALESCE(a.criticality, '')
		FROM rows x
		JOIN assets a ON a.tenant_id = $1 AND a.id = x.asset_id AND a.status <> 'archived'
		ORDER BY x.possible, a.name
		LIMIT 5000`, tenantID.String(), vulnID)
	if err != nil {
		return nil, fmt.Errorf("affected assets: %w", err)
	}
	defer rows.Close()
	var out []threatalert.Asset
	for rows.Next() {
		var a threatalert.Asset
		var finding sql.NullString
		var possible bool
		if err := rows.Scan(&a.AssetID, &a.Name, &a.Type, &finding, &a.Confidence, &a.Product, &a.Version,
			&possible, &a.InternetFacing, &a.Criticality); err != nil {
			return nil, fmt.Errorf("affected assets: %w", err)
		}
		switch {
		case possible:
			a.Kind = threatalert.MatchPossible
		case a.Confidence < threatalert.ConfirmedConfidence:
			a.Kind = threatalert.MatchLikely
		default:
			a.Kind = threatalert.MatchConfirmed
		}
		if finding.Valid {
			if id, err := shared.IDFromString(finding.String); err == nil {
				a.FindingID = &id
			}
		}
		a.Product = clipStr(a.Product, 200)
		a.Version = clipStr(a.Version, 64)
		out = append(out, a)
	}
	return out, rows.Err()
}

// alertColumns is the column list scanAlert reads (alias a).
const alertColumns = `a.id, a.tenant_id, a.vuln_id, a.title, a.severity, a.level, a.tier, a.state, a.state_reason, a.state_note,
	a.state_changed_by, a.state_changed_at, a.suppressed_until, a.ets, a.ets_breakdown, a.in_kev, a.kev_ransomware, a.epss,
	a.confirmed_assets, a.possible_assets, a.internet_facing_assets, a.last_event_kind, a.source_at, a.event_at,
	a.notified_level, a.notified_tier, a.notified_at, a.digest_pending, a.held, a.baseline, a.planned_at,
	a.acknowledged_at, a.resolved_at, a.created_at, a.updated_at`

func scanAlert(s interface{ Scan(...any) error }, extra ...any) (*threatalert.Alert, error) {
	var a threatalert.Alert
	var level, tier, state string
	var changedBy sql.NullString
	var changedAt, suppressed, sourceAt, eventAt, notifiedAt, ackAt, resolvedAt sql.NullTime
	var breakdown []byte
	var epss sql.NullFloat64
	dest := []any{&a.ID, &a.TenantID, &a.VulnID, &a.Title, &a.Severity, &level, &tier, &state, &a.StateReason, &a.StateNote,
		&changedBy, &changedAt, &suppressed, &a.ETS, &breakdown, &a.InKEV, &a.KEVRansomware, &epss,
		&a.Confirmed, &a.Possible, &a.InternetFacing, &a.LastEventKind, &sourceAt, &eventAt,
		&a.NotifiedLevel, &a.NotifiedTier, &notifiedAt, &a.DigestPending, &a.Held, &a.Baseline, &a.PlannedAt,
		&ackAt, &resolvedAt, &a.CreatedAt, &a.UpdatedAt}
	if err := s.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	a.Level, a.Tier, a.State = threatalert.Level(level), threatalert.Tier(tier), threatalert.State(state)
	if changedBy.Valid {
		if id, err := shared.IDFromString(changedBy.String); err == nil {
			a.StateChangedBy = &id
		}
	}
	a.StateChangedAt, a.SuppressedUntil = timePtr(changedAt), timePtr(suppressed)
	a.SourceAt, a.EventAt, a.NotifiedAt = timePtr(sourceAt), timePtr(eventAt), timePtr(notifiedAt)
	a.AcknowledgedAt, a.ResolvedAt = timePtr(ackAt), timePtr(resolvedAt)
	_ = json.Unmarshal(breakdown, &a.Breakdown)
	if epss.Valid {
		f := epss.Float64
		a.EPSS = &f
	}
	return &a, nil
}

// AlertByVuln (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) AlertByVuln(ctx context.Context, tenantID shared.ID, vulnID string) (*threatalert.Alert, error) {
	a, err := scanAlert(r.db.QueryRowContext(ctx, `SELECT `+alertColumns+` FROM threat_alerts a WHERE a.tenant_id = $1 AND a.vuln_id = $2`,
		tenantID.String(), vulnID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("alert by vuln: %w", err)
	}
	return a, nil
}

// SaveAlert (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) SaveAlert(ctx context.Context, a *threatalert.Alert, assets []threatalert.Asset) error {
	breakdown, err := json.Marshal(a.Breakdown)
	if err != nil {
		return fmt.Errorf("alert breakdown: %w", err)
	}
	var epss sql.NullFloat64
	if a.EPSS != nil {
		epss = sql.NullFloat64{Float64: *a.EPSS, Valid: true}
	}
	notified := a.NotifiedLevel
	if notified == "" {
		notified = threatalert.NotifiedNone
	}
	// The version the planner read: an update applies only to that version.
	var readAt sql.NullTime
	if !a.ID.IsZero() {
		readAt = sql.NullTime{Time: a.UpdatedAt, Valid: true}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	err = tx.QueryRowContext(ctx, `
		INSERT INTO threat_alerts (tenant_id, vuln_id, title, severity, level, tier, state, state_reason, state_note,
			state_changed_at, suppressed_until, ets, ets_breakdown, in_kev, kev_ransomware, epss,
			confirmed_assets, possible_assets, internet_facing_assets, last_event_kind, source_at, event_at,
			notified_level, notified_tier, digest_pending, baseline, planned_at, resolved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
			$23, $24, $25, $26, now(), $27)
		ON CONFLICT (tenant_id, vuln_id) DO UPDATE SET title = EXCLUDED.title, severity = EXCLUDED.severity,
			level = EXCLUDED.level, tier = EXCLUDED.tier, state = EXCLUDED.state, state_reason = EXCLUDED.state_reason,
			state_note = EXCLUDED.state_note, state_changed_at = EXCLUDED.state_changed_at,
			suppressed_until = EXCLUDED.suppressed_until, ets = EXCLUDED.ets, ets_breakdown = EXCLUDED.ets_breakdown,
			in_kev = EXCLUDED.in_kev, kev_ransomware = EXCLUDED.kev_ransomware, epss = EXCLUDED.epss,
			confirmed_assets = EXCLUDED.confirmed_assets, possible_assets = EXCLUDED.possible_assets,
			internet_facing_assets = EXCLUDED.internet_facing_assets, last_event_kind = EXCLUDED.last_event_kind,
			source_at = EXCLUDED.source_at, event_at = EXCLUDED.event_at, notified_level = EXCLUDED.notified_level,
			notified_tier = EXCLUDED.notified_tier, digest_pending = EXCLUDED.digest_pending,
			planned_at = now(), resolved_at = EXCLUDED.resolved_at, updated_at = now()
		WHERE $28::timestamptz IS NULL OR threat_alerts.updated_at = $28::timestamptz
		RETURNING id, created_at, updated_at`,
		a.TenantID.String(), a.VulnID, clipStr(a.Title, 200), a.Severity, string(a.Level), string(a.Tier), string(a.State),
		a.StateReason, a.StateNote, nullTime(a.StateChangedAt), nullTime(a.SuppressedUntil), a.ETS, breakdown,
		a.InKEV, a.KEVRansomware, epss, a.Confirmed, a.Possible, a.InternetFacing, a.LastEventKind,
		nullTime(a.SourceAt), nullTime(a.EventAt), notified, a.NotifiedTier, a.DigestPending, a.Baseline,
		nullTime(a.ResolvedAt), readAt).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return threatalert.ErrStale
	}
	if err != nil {
		return fmt.Errorf("save alert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM threat_alert_assets WHERE tenant_id = $1 AND alert_id = $2`,
		a.TenantID.String(), a.ID.String()); err != nil {
		return fmt.Errorf("replace alert assets: %w", err)
	}
	if len(assets) > 0 {
		n := len(assets)
		ids, kinds, crit, prods, vers := make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n), make([]string, 0, n)
		confs := make([]int64, 0, n)
		inet := make([]bool, 0, n)
		finds := make([]sql.NullString, 0, n)
		for _, x := range assets {
			ids, kinds = append(ids, x.AssetID.String()), append(kinds, string(x.Kind))
			crit, prods, vers = append(crit, clipStr(x.Criticality, 32)), append(prods, clipStr(x.Product, 200)), append(vers, clipStr(x.Version, 64))
			confs, inet, finds = append(confs, int64(max(0, min(100, x.Confidence)))), append(inet, x.InternetFacing), append(finds, nullIDPtr(x.FindingID))
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO threat_alert_assets (tenant_id, alert_id, asset_id, match_kind, confidence, internet_facing,
				criticality, product, version_seen, finding_id)
			SELECT $1, $2, x.asset, x.kind, x.conf, x.inet, x.crit, x.prod, x.ver, x.finding
			FROM unnest($3::uuid[], $4::text[], $5::int[], $6::bool[], $7::text[], $8::text[], $9::text[], $10::uuid[])
				AS x(asset, kind, conf, inet, crit, prod, ver, finding)
			ON CONFLICT (alert_id, asset_id) DO NOTHING`,
			a.TenantID.String(), a.ID.String(), pq.Array(ids), pq.Array(kinds), pq.Array(confs), pq.Array(inet),
			pq.Array(crit), pq.Array(prods), pq.Array(vers), pq.Array(finds)); err != nil {
			return fmt.Errorf("save alert assets: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ResolveVuln (see threatalert.PlannerStore). Platform-wide by design: a
// CVE rejected upstream resolves it everywhere.
func (r *ThreatAlertRepository) ResolveVuln(ctx context.Context, vulnID, reason string, at time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE threat_alerts SET state = 'resolved', state_reason = $2, resolved_at = $3, state_changed_at = $3,
			state_changed_by = NULL, digest_pending = true, updated_at = now()
		WHERE vuln_id = $1 AND state IN `+openAlertStates, vulnID, reason, at)
	if err != nil {
		return 0, fmt.Errorf("resolve alerts: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// PendingImmediate (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) PendingImmediate(ctx context.Context, tenantID shared.ID) ([]*threatalert.Alert, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+alertColumns+` FROM threat_alerts a
		WHERE a.tenant_id = $1 AND a.level = 'immediate' AND a.notified_level <> 'immediate' AND a.state IN `+openAlertStates+`
		ORDER BY a.ets DESC, a.created_at LIMIT 200`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("pending immediate: %w", err)
	}
	defer rows.Close()
	var out []*threatalert.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, fmt.Errorf("pending immediate: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TenantsWithPendingImmediate (see threatalert.PlannerStore). Platform-wide:
// the planner's sweep for held and capped alerts.
func (r *ThreatAlertRepository) TenantsWithPendingImmediate(ctx context.Context, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM threat_alerts
		WHERE level = 'immediate' AND notified_level <> 'immediate' AND state IN `+openAlertStates+` LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("tenants pending: %w", err)
	}
	return scanIDs(rows)
}

func alertIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// MarkNotified (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) MarkNotified(ctx context.Context, tenantID shared.ID, ids []shared.ID, level threatalert.Level, counted bool, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, `
		UPDATE threat_alerts SET notified_level = $3, notified_tier = tier, notified_at = $4, held = false,
			immediate_sent_at = CASE WHEN $5 THEN $4 ELSE immediate_sent_at END, updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(alertIDStrings(ids)), string(level), at, counted); err != nil {
		return fmt.Errorf("mark notified: %w", err)
	}
	return nil
}

// SetHeld (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) SetHeld(ctx context.Context, tenantID shared.ID, ids []shared.ID) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE threat_alerts SET held = true WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND NOT held`,
		tenantID.String(), pq.Array(alertIDStrings(ids))); err != nil {
		return fmt.Errorf("hold alerts: %w", err)
	}
	return nil
}

// ImmediateSentSince (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) ImmediateSentSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM threat_alerts WHERE tenant_id = $1 AND immediate_sent_at >= $2`,
		tenantID.String(), since).Scan(&n); err != nil {
		return 0, fmt.Errorf("immediate sent: %w", err)
	}
	return n, nil
}

// TenantState (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) TenantState(ctx context.Context, tenantID shared.ID) (threatalert.TenantState, error) {
	st := threatalert.TenantState{TenantID: tenantID}
	var baseline, lastAt, fold sql.NullTime
	var lastOn sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT baseline_at, baseline_digest_due, to_char(last_digest_on, 'YYYY-MM-DD'), last_digest_at, last_fold_at
		FROM threat_alert_tenant_state WHERE tenant_id = $1`, tenantID.String()).
		Scan(&baseline, &st.BaselineDigestDue, &lastOn, &lastAt, &fold)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("tenant alert state: %w", err)
	}
	st.Exists = true
	st.BaselineAt, st.LastDigestAt, st.LastFoldAt = timePtr(baseline), timePtr(lastAt), timePtr(fold)
	st.LastDigestOn = lastOn.String
	return st, nil
}

// SaveTenantState (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) SaveTenantState(ctx context.Context, st threatalert.TenantState) error {
	var lastOn sql.NullString
	if st.LastDigestOn != "" {
		lastOn = sql.NullString{String: st.LastDigestOn, Valid: true}
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO threat_alert_tenant_state (tenant_id, baseline_at, baseline_digest_due, last_digest_on, last_digest_at, last_fold_at)
		SELECT $1, $2, $3, $4::date, $5, $6 WHERE EXISTS (SELECT 1 FROM tenants WHERE id = $1)
		ON CONFLICT (tenant_id) DO UPDATE SET baseline_at = EXCLUDED.baseline_at,
			baseline_digest_due = EXCLUDED.baseline_digest_due, last_digest_on = EXCLUDED.last_digest_on,
			last_digest_at = EXCLUDED.last_digest_at, last_fold_at = EXCLUDED.last_fold_at, updated_at = now()`,
		st.TenantID.String(), nullTime(st.BaselineAt), st.BaselineDigestDue, lastOn, nullTime(st.LastDigestAt), nullTime(st.LastFoldAt)); err != nil {
		return fmt.Errorf("save tenant alert state: %w", err)
	}
	return nil
}

// TenantsWithoutBaseline (see threatalert.PlannerStore). Platform-wide: the
// planner's sweep of organizations to baseline.
func (r *ThreatAlertRepository) TenantsWithoutBaseline(ctx context.Context, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id FROM tenants t
		LEFT JOIN threat_alert_tenant_state s ON s.tenant_id = t.id
		WHERE s.tenant_id IS NULL OR (s.baseline_at IS NULL AND s.updated_at < now() - interval '1 hour')
		ORDER BY s.updated_at NULLS FIRST, t.id
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("tenants without baseline: %w", err)
	}
	return scanIDs(rows)
}

// ActiveWindowVulns (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) ActiveWindowVulns(ctx context.Context, tenantID shared.ID, eventsSince, kevSince time.Time) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		WITH win AS (
			SELECT DISTINCT vuln_id FROM vuln_events WHERE at >= $2 AND kind <> 'rejected'
			UNION
			SELECT cve_id FROM kev_catalog WHERE date_added >= $3::date
		)
		SELECT DISTINCT f.cve_id FROM findings f JOIN win ON win.vuln_id = f.cve_id
		WHERE f.tenant_id = $1 AND `+vulnerability.OpenStatusSQL("f.status")+`
		UNION
		SELECT DISTINCT va.cve_id FROM asset_software s
		JOIN software_versions v ON v.id = s.software_version_id
		JOIN vulnerability_affected va ON va.product_id = s.product_id
		JOIN win ON win.vuln_id = va.cve_id
		WHERE s.tenant_id = $1 AND s.superseded_at IS NULL AND (v.normalized IS NULL OR v.raw = '')
		LIMIT 5000`, tenantID.String(), eventsSince, kevSince)
	if err != nil {
		return nil, fmt.Errorf("active window vulns: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DigestTenants (see threatalert.PlannerStore). Platform-wide: the
// planner's digest sweep.
func (r *ThreatAlertRepository) DigestTenants(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id FROM threat_alerts WHERE digest_pending
		UNION
		SELECT tenant_id FROM threat_alert_tenant_state WHERE baseline_digest_due`)
	if err != nil {
		return nil, fmt.Errorf("digest tenants: %w", err)
	}
	return scanIDs(rows)
}

// inScopeAsset is the predicate "the alert asset taa is in scope" plus its
// arguments, numbered from first. A nil scope (an owner, the system) is
// unrestricted.
func inScopeAsset(scope *shared.DataScope, first int) (string, []any) {
	if scope == nil {
		return sqlTrue, nil
	}
	return dataScopeCondAt("taa.asset_id", scope, first)
}

// DigestSummary (see threatalert.PlannerStore). Counts and names only the
// alerts with at least one asset in scope.
func (r *ThreatAlertRepository) DigestSummary(ctx context.Context, tenantID shared.ID, since time.Time, scope *shared.DataScope) (threatalert.Digest, error) {
	var d threatalert.Digest
	cond, args := inScopeAsset(scope, 3)
	visible := `EXISTS (SELECT 1 FROM threat_alert_assets taa WHERE taa.tenant_id = a.tenant_id AND taa.alert_id = a.id AND ` + cond + `)`
	base := append([]any{tenantID.String(), since}, args...)
	err := r.db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.level = 'immediate' AND (a.digest_pending OR a.notified_at >= $2)),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.level = 'digest' AND (a.digest_pending OR a.notified_at >= $2)),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.level = 'listed' AND a.created_at >= $2),
			count(*) FILTER (WHERE a.state = 'resolved' AND a.resolved_at >= $2),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.in_kev AND (a.digest_pending OR a.notified_at >= $2)),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.in_kev)
		FROM threat_alerts a WHERE a.tenant_id = $1 AND `+visible, base...).
		Scan(&d.Immediate, &d.Digest, &d.Listed, &d.Resolved, &d.KEV, &d.Exploited)
	if err != nil {
		return d, fmt.Errorf("digest summary: %w", err)
	}
	// The counts of each listed alert are those in scope (a scoped member's
	// e-mail never counts assets they cannot see).
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.id, a.vuln_id, a.title, a.level, a.ets, a.in_kev, vc.c, vc.p, vc.i
		FROM threat_alerts a `+viewerCountsSQL(cond)+`
		WHERE a.tenant_id = $1 AND a.state IN `+openAlertStates+` AND a.level IN ('immediate', 'digest')
		  AND (a.digest_pending OR a.notified_at >= $2) AND `+visible+`
		ORDER BY a.ets DESC, a.vuln_id LIMIT 5`, base...)
	if err != nil {
		return d, fmt.Errorf("digest top: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var it threatalert.DigestItem
		var level string
		if err := rows.Scan(&it.ID, &it.VulnID, &it.Title, &level, &it.ETS, &it.InKEV, &it.Confirmed, &it.Possible, &it.InternetFacing); err != nil {
			return d, fmt.Errorf("digest top: %w", err)
		}
		it.Level = threatalert.Level(level)
		d.Top = append(d.Top, it)
	}
	return d, rows.Err()
}

// ClearDigest (see threatalert.PlannerStore).
func (r *ThreatAlertRepository) ClearDigest(ctx context.Context, tenantID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE threat_alerts SET digest_pending = false,
			notified_level = CASE WHEN notified_level = 'none' AND level = 'digest' THEN 'digest' ELSE notified_level END,
			notified_tier = CASE WHEN notified_level = 'none' AND level = 'digest' THEN tier ELSE notified_tier END,
			notified_at = CASE WHEN notified_level = 'none' AND level = 'digest' THEN now() ELSE notified_at END
		WHERE tenant_id = $1 AND digest_pending`, tenantID.String()); err != nil {
		return fmt.Errorf("clear digest: %w", err)
	}
	return nil
}

// DigestRecipients (see threatalert.PlannerStore): active people whose
// e-mail digest preference is daily or weekly and who are owners,
// administrators or hold findings:vulnerabilities:read through a role.
func (r *ThreatAlertRepository) DigestRecipients(ctx context.Context, tenantID shared.ID) ([]threatalert.Recipient, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id, u.email, p.email_digest,
			COALESCE(p.muted_types, '[]'::jsonb) ? 'emerging_threat_digest'
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id AND u.status = 'active' AND u.kind = 'person'
		JOIN notification_preferences p ON p.tenant_id = m.tenant_id AND p.user_id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.status = 'active'
		  AND (m.expires_at IS NULL OR m.expires_at > now())
		  AND p.email_digest IN ('daily', 'weekly') AND u.email <> ''
		  AND (ver.role IN ('owner', 'admin') OR EXISTS (
		        SELECT 1 FROM user_roles ur
		        JOIN role_permissions rp ON rp.role_id = ur.role_id
		        JOIN permissions pe ON pe.id = rp.permission_id AND pe.is_active = TRUE
		        WHERE ur.tenant_id = m.tenant_id AND ur.user_id = m.user_id AND rp.permission_id = 'findings:vulnerabilities:read'))
		ORDER BY u.id LIMIT 1000`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("digest recipients: %w", err)
	}
	defer rows.Close()
	var out []threatalert.Recipient
	for rows.Next() {
		var rc threatalert.Recipient
		if err := rows.Scan(&rc.UserID, &rc.Email, &rc.Frequency, &rc.Muted); err != nil {
			return nil, fmt.Errorf("digest recipients: %w", err)
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

// CoveredByAlert reports whether an open, announced alert of a CVE in KEV
// covers the finding, so the per-finding KEV escalation message is not
// sent (the alert is the one message).
func (r *ThreatAlertRepository) CoveredByAlert(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM findings f
			JOIN threat_alerts a ON a.tenant_id = f.tenant_id AND a.vuln_id = f.cve_id
			WHERE f.tenant_id = $1 AND f.id = $2 AND a.in_kev
			  AND a.state IN `+openAlertStates+` AND a.level IN ('immediate', 'digest'))`,
		tenantID.String(), findingID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("alert coverage: %w", err)
	}
	return ok, nil
}

// QueueVulns queues an organization's vulnerabilities for planning (the
// matcher created findings for them).
func (r *ThreatAlertRepository) QueueVulns(ctx context.Context, tenantID shared.ID, vulnIDs []string) error {
	items := make([]threatalert.QueueItem, 0, len(vulnIDs))
	for _, v := range vulnIDs {
		items = append(items, threatalert.QueueItem{TenantID: tenantID, VulnID: v})
	}
	return r.Enqueue(ctx, items)
}
