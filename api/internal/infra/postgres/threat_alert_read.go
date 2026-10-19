package postgres

// Reads and triage writes of emerging-threat alerts for the API
// (docs/rfcs/RFC-117-emerging-threat-alerts.md §4). A viewer sees an alert
// only when at least one of its assets is in their data scope, and only the
// assets, counts and findings in scope.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
)

// viewerCountsSQL counts the alert's assets in scope (alias vc); cond is
// the scope predicate on taa.asset_id.
func viewerCountsSQL(cond string) string {
	return `LEFT JOIN LATERAL (
		SELECT count(*) FILTER (WHERE taa.match_kind <> 'possible') AS c,
			count(*) FILTER (WHERE taa.match_kind = 'possible') AS p,
			count(*) FILTER (WHERE taa.internet_facing) AS i
		FROM threat_alert_assets taa
		WHERE taa.tenant_id = a.tenant_id AND taa.alert_id = a.id AND ` + cond + `
	) vc ON true`
}

// List (see threatalert.ReadStore).
func (r *ThreatAlertRepository) List(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, f threatalert.ListFilter) ([]threatalert.Alert, int, threatalert.Summary, error) {
	var sum threatalert.Summary
	cond, args := inScopeAsset(scope, 2)
	args = append([]any{tenantID.String()}, args...)
	from := ` FROM threat_alerts a ` + viewerCountsSQL(cond) + ` WHERE a.tenant_id = $1 AND (vc.c + vc.p) > 0`

	if err := r.db.QueryRowContext(ctx, `SELECT
			count(*) FILTER (WHERE a.state IN `+openAlertStates+`),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.level = 'immediate'),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.level = 'digest'),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.level = 'listed'),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND a.in_kev),
			count(*) FILTER (WHERE a.state IN `+openAlertStates+` AND vc.i > 0)`+from, args...).
		Scan(&sum.Open, &sum.Immediate, &sum.Digest, &sum.Listed, &sum.KEV, &sum.InternetFacing); err != nil {
		return nil, 0, sum, fmt.Errorf("alert summary: %w", err)
	}

	where := ""
	add := func(clause string, v any) {
		args = append(args, v)
		where += " AND " + strings.ReplaceAll(clause, "?", "$"+strconv.Itoa(len(args)))
	}
	if f.Level != "" {
		add("a.level = ?", string(f.Level))
	}
	if len(f.States) > 0 {
		states := make([]string, 0, len(f.States))
		for _, s := range f.States {
			states = append(states, string(s))
		}
		add("a.state = ANY(?::text[])", pq.Array(states))
	}
	if f.Tier != "" {
		add("a.tier = ?", string(f.Tier))
	}
	if f.InternetOnly {
		where += " AND vc.i > 0"
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		// Both placeholders take the same argument.
		add("(a.vuln_id ILIKE ? OR a.title ILIKE ?)", "%"+escapeLikePattern(s)+"%")
	}
	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*)`+from+where, args...).Scan(&total); err != nil {
		return nil, 0, sum, fmt.Errorf("count alerts: %w", err)
	}
	per := max(1, min(f.PerPage, 200))
	page := max(1, f.Page)
	args = append(args, per, (page-1)*per)
	q := `SELECT ` + alertColumns + `, vc.c, vc.p, vc.i` + from + where + `
		ORDER BY CASE a.level WHEN 'immediate' THEN 0 WHEN 'digest' THEN 1 ELSE 2 END, a.ets DESC, a.updated_at DESC, a.id
		LIMIT $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args))
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, sum, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	out := make([]threatalert.Alert, 0)
	for rows.Next() {
		var c, p, i int
		a, err := scanAlert(rows, &c, &p, &i)
		if err != nil {
			return nil, 0, sum, fmt.Errorf("list alerts: %w", err)
		}
		a.Confirmed, a.Possible, a.InternetFacing = c, p, i
		out = append(out, *a)
	}
	return out, total, sum, rows.Err()
}

// Get (see threatalert.ReadStore). An alert with no asset in scope is not
// found.
func (r *ThreatAlertRepository) Get(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, id shared.ID) (*threatalert.Detail, error) {
	cond, sargs := inScopeAsset(scope, 3)
	args := append([]any{tenantID.String(), id.String()}, sargs...)
	var c, p, i, total int
	a, err := scanAlert(r.db.QueryRowContext(ctx, `SELECT `+alertColumns+`, vc.c, vc.p, vc.i,
			(SELECT count(*) FROM threat_alert_assets t WHERE t.tenant_id = a.tenant_id AND t.alert_id = a.id)
		FROM threat_alerts a `+viewerCountsSQL(cond)+`
		WHERE a.tenant_id = $1 AND a.id = $2 AND (vc.c + vc.p) > 0`, args...), &c, &p, &i, &total)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, threatalert.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get alert: %w", err)
	}
	a.Confirmed, a.Possible, a.InternetFacing = c, p, i
	d := &threatalert.Detail{Alert: *a, AllInScope: c+p == total}

	rows, err := r.db.QueryContext(ctx, `
		SELECT taa.asset_id, a.name, a.asset_type, taa.match_kind, taa.confidence, taa.internet_facing, taa.criticality,
			taa.product, taa.version_seen, taa.finding_id, COALESCE(f.status, ''), tm.task_id
		FROM threat_alert_assets taa
		JOIN assets a ON a.tenant_id = taa.tenant_id AND a.id = taa.asset_id
		LEFT JOIN findings f ON f.tenant_id = taa.tenant_id AND f.id = taa.finding_id
		LEFT JOIN remediation_task_members tm ON tm.tenant_id = taa.tenant_id AND tm.finding_id = taa.finding_id
			AND tm.left_at IS NULL AND tm.role = 'primary'
		WHERE taa.tenant_id = $1 AND taa.alert_id = $2 AND `+cond+`
		ORDER BY CASE taa.match_kind WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END, taa.internet_facing DESC, a.name
		LIMIT 1000`, args...)
	if err != nil {
		return nil, fmt.Errorf("alert assets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v threatalert.AssetView
		var kind string
		var finding, task sql.NullString
		if err := rows.Scan(&v.AssetID, &v.Name, &v.Type, &kind, &v.Confidence, &v.InternetFacing, &v.Criticality,
			&v.Product, &v.Version, &finding, &v.FindingStatus, &task); err != nil {
			return nil, fmt.Errorf("alert assets: %w", err)
		}
		v.Kind = threatalert.MatchKind(kind)
		if finding.Valid {
			if fid, err := shared.IDFromString(finding.String); err == nil {
				v.FindingID = &fid
			}
		}
		if task.Valid {
			if tid, err := shared.IDFromString(task.String); err == nil {
				v.TaskID = &tid
			}
		}
		d.Assets = append(d.Assets, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	vuln, err := r.Vuln(ctx, a.VulnID, time.Time{})
	if err != nil {
		return nil, err
	}
	if vuln != nil {
		d.Vuln = *vuln
	}
	trows, err := r.db.QueryContext(ctx, `
		SELECT kind, at, source_at, detail FROM vuln_events WHERE vuln_id = $1 ORDER BY at DESC, id DESC LIMIT 50`, a.VulnID)
	if err != nil {
		return nil, fmt.Errorf("alert timeline: %w", err)
	}
	defer trows.Close()
	for trows.Next() {
		var e threatalert.TimelineEntry
		var src sql.NullTime
		var detail []byte
		if err := trows.Scan(&e.Kind, &e.At, &src, &detail); err != nil {
			return nil, fmt.Errorf("alert timeline: %w", err)
		}
		e.SourceAt = timePtr(src)
		_ = json.Unmarshal(detail, &e.Detail)
		d.Timeline = append(d.Timeline, e)
	}
	return d, trows.Err()
}

// SetState (see threatalert.ReadStore).
func (r *ThreatAlertRepository) SetState(ctx context.Context, tenantID, id shared.ID, to threatalert.State, reason, note string, by shared.ID, at time.Time, suppressedUntil *time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE threat_alerts SET state = $3, state_reason = $4, state_note = $5, state_changed_by = $6, state_changed_at = $7,
			suppressed_until = $8,
			acknowledged_at = CASE WHEN $3 IN ('acknowledged', 'remediating') THEN COALESCE(acknowledged_at, $7) ELSE acknowledged_at END,
			resolved_at = CASE WHEN $3 = 'new' THEN NULL ELSE resolved_at END,
			updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), string(to), reason, note, nullIDPtr(&by), at, nullTime(suppressedUntil))
	if err != nil {
		return fmt.Errorf("set alert state: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return threatalert.ErrNotFound
	}
	return nil
}
