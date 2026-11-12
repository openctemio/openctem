package postgres

// Asset liveness (docs/architecture/asset-liveness.md): the evidence the
// coverage loop records per asset, the state decided from it, and what a
// gone asset does to its findings. Every statement is pinned to one tenant;
// the finding moves lock with SKIP LOCKED (a person editing a finding is
// never overwritten mid-edit) and are recorded on each finding's timeline by
// the transition trigger, with a finding.status_changed audit row each.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/exposure"
	"github.com/openctemio/openctem/server/pkg/domain/liveness"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// Names the liveness pass writes on timeline entries, audit rows and state
// history.
const (
	livenessSource  = "asset_liveness"
	livenessActor   = "system: asset liveness"
	livenessField   = "liveness"
	livenessHistSrc = "system"
	auditKeyActor   = "actor"
)

// AssetLivenessRepository stores asset liveness and applies its effects.
type AssetLivenessRepository struct {
	db *DB
}

// NewAssetLivenessRepository creates an AssetLivenessRepository.
func NewAssetLivenessRepository(db *DB) *AssetLivenessRepository {
	return &AssetLivenessRepository{db: db}
}

const livenessCols = `l.asset_id::text, l.state, l.reason, l.state_since, l.last_checked_at, l.last_checked_by,
	l.last_kind, l.last_capability, l.last_outcome, l.last_alive_at, l.last_resolved_at,
	l.reach_fails, l.reach_fail_since, l.reach_fail_last, l.reach_observers,
	l.dns_fails, l.dns_fail_since, l.dns_fail_last, l.nx_count, l.nx_since, l.nx_last, l.nx_observers`

func scanLivenessEvidence(rs rowScanner, extra ...any) (shared.ID, liveness.Evidence, error) {
	var (
		id, state, kind string
		e               liveness.Evidence
		since, checked  sql.NullTime
		alive, resolved sql.NullTime
		rfs, rfl        sql.NullTime
		dfs, dfl        sql.NullTime
		nxs, nxl        sql.NullTime
		reachObs, nxObs []string
	)
	dest := make([]any, 0, 22+len(extra))
	dest = append(dest, &id, &state, &e.Reason, &since, &checked, &e.LastCheckedBy,
		&kind, &e.LastCapability, &e.LastOutcome, &alive, &resolved,
		&e.ReachFails, &rfs, &rfl, pq.Array(&reachObs),
		&e.DNSFails, &dfs, &dfl, &e.NXCount, &nxs, &nxl, pq.Array(&nxObs))
	if err := rs.Scan(append(dest, extra...)...); err != nil {
		return shared.ID{}, e, err
	}
	aid, err := shared.IDFromString(id)
	if err != nil {
		return shared.ID{}, e, err
	}
	e.State, e.LastKind = liveness.State(state), liveness.Kind(kind)
	e.Since, e.LastCheckedAt = timePtr(since), timePtr(checked)
	e.LastAliveAt, e.LastResolvedAt = timePtr(alive), timePtr(resolved)
	e.ReachFailSince, e.ReachFailLast = timePtr(rfs), timePtr(rfl)
	e.DNSFailSince, e.DNSFailLast = timePtr(dfs), timePtr(dfl)
	e.NXSince, e.NXLast = timePtr(nxs), timePtr(nxl)
	e.ReachObservers, e.NXObservers = reachObs, nxObs
	return aid, e, nil
}

const upsertLivenessSQL = `
	INSERT INTO asset_liveness (tenant_id, asset_id, state, reason, state_since, last_checked_at, last_checked_by,
		last_kind, last_capability, last_outcome, last_alive_at, last_resolved_at,
		reach_fails, reach_fail_since, reach_fail_last, reach_observers,
		dns_fails, dns_fail_since, dns_fail_last, nx_count, nx_since, nx_last, nx_observers, updated_at)
	SELECT $1, a.id, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, now()
	FROM assets a WHERE a.tenant_id = $1 AND a.id = $2
	ON CONFLICT (tenant_id, asset_id) DO UPDATE SET
		state = EXCLUDED.state, reason = EXCLUDED.reason, state_since = EXCLUDED.state_since,
		last_checked_at = EXCLUDED.last_checked_at, last_checked_by = EXCLUDED.last_checked_by,
		last_kind = EXCLUDED.last_kind, last_capability = EXCLUDED.last_capability, last_outcome = EXCLUDED.last_outcome,
		last_alive_at = EXCLUDED.last_alive_at, last_resolved_at = EXCLUDED.last_resolved_at,
		reach_fails = EXCLUDED.reach_fails, reach_fail_since = EXCLUDED.reach_fail_since,
		reach_fail_last = EXCLUDED.reach_fail_last, reach_observers = EXCLUDED.reach_observers,
		dns_fails = EXCLUDED.dns_fails, dns_fail_since = EXCLUDED.dns_fail_since, dns_fail_last = EXCLUDED.dns_fail_last,
		nx_count = EXCLUDED.nx_count, nx_since = EXCLUDED.nx_since, nx_last = EXCLUDED.nx_last,
		nx_observers = EXCLUDED.nx_observers, updated_at = now()`

func writeEvidence(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, e liveness.Evidence) error {
	_, err := tx.ExecContext(ctx, upsertLivenessSQL, tenantID.String(), assetID.String(),
		string(e.State), e.Reason, nullTime(e.Since), nullTime(e.LastCheckedAt), clipText(e.LastCheckedBy, 80),
		string(e.LastKind), clipText(e.LastCapability, 64), clipText(e.LastOutcome, 64),
		nullTime(e.LastAliveAt), nullTime(e.LastResolvedAt),
		e.ReachFails, nullTime(e.ReachFailSince), nullTime(e.ReachFailLast), pq.Array(nonNil(e.ReachObservers)),
		e.DNSFails, nullTime(e.DNSFailSince), nullTime(e.DNSFailLast),
		e.NXCount, nullTime(e.NXSince), nullTime(e.NXLast), pq.Array(nonNil(e.NXObservers)))
	if err != nil {
		return fmt.Errorf("write asset liveness: %w", err)
	}
	return nil
}

func clipText(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// recordLivenessHistory appends one state-history row per state change.
func recordLivenessHistory(ctx context.Context, tx *sql.Tx, tenantID, assetID shared.ID, from, to liveness.State, reason string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO asset_state_history (tenant_id, asset_id, change_type, field, old_value, new_value, reason, source, metadata, changed_at)
		SELECT $1, a.id, 'status_changed', '`+livenessField+`', $3, $4, $5, '`+livenessHistSrc+`',
		       jsonb_build_object('open_findings', (SELECT count(*) FROM findings f
		           WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND f.status IN `+livenessOpenStatuses+`)),
		       now()
		FROM assets a WHERE a.tenant_id = $1 AND a.id = $2`,
		tenantID.String(), assetID.String(), string(from), string(to), "liveness: "+reason)
	if err != nil {
		return fmt.Errorf("record liveness history: %w", err)
	}
	return nil
}

// Observe records observations of the tenant's assets made at now and
// settles each asset's state without the guards (gone is never entered
// here, only kept while its evidence holds). An asset that is not the
// tenant's is skipped. It returns the state changes.
func (r *AssetLivenessRepository) Observe(ctx context.Context, tenantID shared.ID, obs []liveness.AssetObservation, th liveness.Thresholds, now time.Time) (map[shared.ID]liveness.Transition, error) {
	if len(obs) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(obs))
	for _, o := range obs {
		ids = append(ids, o.AssetID.String())
	}
	out := map[shared.ID]liveness.Transition{}
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		current, err := lockEvidence(ctx, tx, tenantID, ids)
		if err != nil {
			return err
		}
		touched := map[shared.ID]liveness.Evidence{}
		for _, o := range obs {
			e, ok := touched[o.AssetID]
			if !ok {
				e = current[o.AssetID]
				if e.State == "" {
					e.State = liveness.StateUnknown
				}
			}
			touched[o.AssetID] = e.Observe(o.Observation, now)
		}
		for id, e := range touched {
			from := e.State
			e, changed := e.Settle(liveness.Guards{}, th, now)
			if err := writeEvidence(ctx, tx, tenantID, id, e); err != nil {
				return err
			}
			if changed {
				out[id] = liveness.Transition{From: from, To: e.State, Reason: e.Reason}
				if err := recordLivenessHistory(ctx, tx, tenantID, id, from, e.State, e.Reason); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// lockEvidence reads and locks the stored evidence of the tenant's assets.
func lockEvidence(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []string) (map[shared.ID]liveness.Evidence, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+livenessCols+` FROM asset_liveness l
		WHERE l.tenant_id = $1 AND l.asset_id = ANY($2::uuid[]) ORDER BY l.asset_id FOR UPDATE`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read asset liveness: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[shared.ID]liveness.Evidence{}
	for rows.Next() {
		id, e, err := scanLivenessEvidence(rows)
		if err != nil {
			return nil, err
		}
		out[id] = e
	}
	return out, rows.Err()
}

// livenessGuardsSQL reads, beside each row (alias l, asset a, host name
// asset h, host liveness hl), whether a person pinned the asset, whether the
// name (or the service's host name) is dangling, whether the dangling DNS
// check ran since the NXDOMAIN streak began and found nothing, and whether
// the service's host name is gone.
var livenessGuardsSQL = `
	a.asset_type,
	(a.manual_status_override OR COALESCE(a.lifecycle_paused_until > now(), false)) AS pinned,
	(EXISTS (SELECT 1 FROM exposure_events ee
	         WHERE ee.tenant_id = l.tenant_id AND ee.asset_id IN (a.id, COALESCE(h.id, a.id))
	           AND ee.event_type IN ('dangling_cname', 'dangling_ns', 'subdomain_takeover')
	           AND ee.state IN ` + exposure.OpenStatesSQL + `)
	 OR 'dangling_cname' = ANY(COALESCE(a.tags, '{}')) OR 'dangling_cname' = ANY(COALESCE(h.tags, '{}'))) AS dangling,
	(l.nx_since IS NOT NULL AND EXISTS (SELECT 1 FROM asset_coverage dc
	         WHERE dc.tenant_id = l.tenant_id AND dc.asset_id = COALESCE(h.id, a.id)
	           AND dc.capability = 'dns.dangling' AND dc.vantage = '' AND dc.last_outcome = 'ok'
	           AND dc.last_success_at >= l.nx_since)) AS dangling_checked,
	(a.asset_type = 'service' AND COALESCE(hl.state, '') = 'gone') AS host_gone,
	CASE WHEN h.id <> a.id THEN h.id::text ELSE '' END AS host_id,
	(SELECT count(*) FROM findings f WHERE f.tenant_id = l.tenant_id AND f.asset_id = a.id
	   AND f.status IN ` + livenessOpenStatuses + `) AS open_findings`

var livenessFromSQL = `
	FROM asset_liveness l
	JOIN assets a ON a.tenant_id = l.tenant_id AND a.id = l.asset_id AND a.deleted_at IS NULL
	LEFT JOIN LATERAL (
		SELECT h.id, h.tags FROM assets h
		WHERE h.tenant_id = l.tenant_id AND h.deleted_at IS NULL AND h.asset_type IN ('domain', 'subdomain')
		  AND lower(h.name) = ` + assetHostSQL("a") + `
		ORDER BY (h.id = a.id) DESC, h.id
		LIMIT 1) h ON true
	LEFT JOIN asset_liveness hl ON hl.tenant_id = l.tenant_id AND hl.asset_id = h.id AND h.id <> a.id`

// Rows returns up to limit rows of the tenant a pass re-decides (every row
// not plainly alive), services or the other assets, with their guards.
func (r *AssetLivenessRepository) Rows(ctx context.Context, tenantID shared.ID, services bool, limit int) ([]liveness.Row, error) {
	//nolint:gosec // G202: fixed SQL fragments with numbered placeholders
	rows, err := r.db.QueryContext(ctx, `SELECT `+livenessCols+`, `+livenessGuardsSQL+livenessFromSQL+`
		WHERE l.tenant_id = $1 AND (a.asset_type = 'service') = $2
		  AND (l.state <> 'alive' OR l.reach_fails > 0 OR l.dns_fails > 0)
		ORDER BY l.asset_id
		LIMIT $3`, tenantID.String(), services, limit)
	if err != nil {
		return nil, fmt.Errorf("list asset liveness: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []liveness.Row
	for rows.Next() {
		var row liveness.Row
		var hostID string
		id, e, err := scanLivenessEvidence(rows, &row.AssetType, &row.Guards.Pinned, &row.Guards.Dangling,
			&row.Guards.DanglingChecked, &row.Guards.HostGone, &hostID, &row.OpenFindings)
		if err != nil {
			return nil, err
		}
		if hostID != "" {
			row.HostID, _ = shared.IDFromString(hostID)
		}
		row.AssetID, row.Evidence, row.Guards.Known = id, e, true
		out = append(out, row)
	}
	return out, rows.Err()
}

// AddServicesOfGoneHosts gives every service of the tenant whose host name
// asset is gone, and that has no liveness row yet (nothing checked the
// service itself), a row for the pass to decide (it then follows its host).
func (r *AssetLivenessRepository) AddServicesOfGoneHosts(ctx context.Context, tenantID shared.ID) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO asset_liveness (tenant_id, asset_id)
		SELECT a.tenant_id, a.id FROM assets a
		WHERE a.tenant_id = $1 AND a.asset_type = 'service' AND a.deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM asset_liveness x WHERE x.tenant_id = a.tenant_id AND x.asset_id = a.id)
		  AND EXISTS (SELECT 1 FROM assets h JOIN asset_liveness hl ON hl.tenant_id = h.tenant_id AND hl.asset_id = h.id
		              WHERE h.tenant_id = a.tenant_id AND h.deleted_at IS NULL AND h.asset_type IN ('domain', 'subdomain')
		                AND hl.state = 'gone' AND lower(h.name) = `+assetHostSQL("a")+`)
		ON CONFLICT DO NOTHING`, tenantID.String())
	if err != nil {
		return 0, fmt.Errorf("add services of gone hosts: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GoneSince counts the tenant's assets with open findings that became gone
// after since (the daily bound counts only what can close findings).
func (r *AssetLivenessRepository) GoneSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_state_history
		WHERE tenant_id = $1 AND field = '`+livenessField+`' AND new_value = 'gone' AND changed_at > $2
		  AND COALESCE((metadata->>'open_findings')::int, 0) > 0`,
		tenantID.String(), since).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count gone assets: %w", err)
	}
	return n, nil
}

// SetState stores a state a pass decided for one of the tenant's assets,
// with its history row, unless the row changed since it was read (the
// evidence's state and reason are the expected current values).
func (r *AssetLivenessRepository) SetState(ctx context.Context, tenantID, assetID shared.ID, before, after liveness.Evidence) (bool, error) {
	var moved bool
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE asset_liveness SET state = $3, reason = $4, state_since = $5, updated_at = now()
			WHERE tenant_id = $1 AND asset_id = $2 AND state = $6 AND reason = $7`,
			tenantID.String(), assetID.String(), string(after.State), after.Reason, nullTime(after.Since),
			string(before.State), before.Reason)
		if err != nil {
			return fmt.Errorf("set asset liveness: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		moved = true
		if before.State == after.State {
			return nil
		}
		return recordLivenessHistory(ctx, tx, tenantID, assetID, before.State, after.State, after.Reason)
	})
	return moved, err
}

// TenantsWithLiveness lists the tenants that have liveness rows a pass may
// change, or findings closed by it.
func (r *AssetLivenessRepository) TenantsWithLiveness(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT tenant_id::text FROM asset_liveness WHERE state <> 'alive' OR reach_fails > 0 OR dns_fails > 0
		UNION
		SELECT DISTINCT tenant_id::text FROM findings WHERE status = 'resolved' AND closure_reason = 'obsolete_asset'`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with liveness: %w", err)
	}
	return scanIDs(rows)
}

// livenessOpenStatuses are the statuses a gone close moves (as scope
// effects: published and still needing action; pentest drafts are left to
// their author).
const livenessOpenStatuses = scopeEffectsOpenStatuses

// livenessClosedByUsSQL is "the finding (alias f) was moved to resolved
// last by the liveness pass": a close by anyone else (a person, a scan) is
// never reopened by it.
const livenessClosedByUsSQL = `(SELECT fa.source FROM finding_activities fa
	WHERE fa.tenant_id = f.tenant_id AND fa.finding_id = f.id AND fa.changes->>'new_status' = 'resolved'
	ORDER BY fa.created_at DESC, fa.id DESC LIMIT 1) = '` + livenessSource + `'`

// livenessMove is one finding a pass moved.
type livenessMove struct {
	id                      shared.ID
	from, to                string
	severity, priorityClass string
	kev, linked             bool
	assetState, assetRsn    string
}

func scanLivenessMoves(rows *sql.Rows) ([]livenessMove, error) {
	defer func() { _ = rows.Close() }()
	var out []livenessMove
	for rows.Next() {
		var m livenessMove
		var id, assetID string
		if err := rows.Scan(&id, &m.from, &m.to, &m.severity, &m.priorityClass, &m.kev, &m.linked,
			&assetID, &m.assetState, &m.assetRsn); err != nil {
			return nil, err
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		m.id = fid
		out = append(out, m)
	}
	return out, rows.Err()
}

// auditLivenessMoves writes, in tx, the finding.status_changed audit row of
// every move. Closing a finding of the critical tier is high, any other
// move medium.
func auditLivenessMoves(ctx context.Context, tx *sql.Tx, tenantID shared.ID, trigger string, moves []livenessMove) error {
	for _, m := range moves {
		level := audit.SeverityMedium
		next := vulnerability.FindingStatus(m.to)
		if !vulnerability.IsOpenStatus(next) &&
			vulnerability.FindingRiskTier(vulnerability.Severity(m.severity), m.priorityClass, m.kev) == vulnerability.RiskTierCritical {
			level = audit.SeverityHigh
		}
		meta := map[string]any{
			auditKeyOldStatus: m.from, auditKeyNewStatus: m.to, auditKeySeverity: m.severity,
			auditKeyActor: livenessActor, auditKeyActorKind: string(vulnerability.ActorTypeSystem),
			auditKeySource: livenessSource, auditKeyTrigger: trigger,
			"asset_liveness": m.assetState, "asset_liveness_reason": m.assetRsn,
		}
		if next == vulnerability.FindingStatusResolved {
			meta["closure_reason"] = string(vulnerability.ClosureReasonObsoleteAsset)
			meta["verification"] = string(vulnerability.VerificationNone)
		}
		if err := insertDecisionAudit(ctx, tx, tenantID, m.id, string(audit.ActionFindingStatusChanged), string(level),
			fmt.Sprintf("Finding status changed from %s to %s", m.from, m.to), meta); err != nil {
			return err
		}
	}
	return nil
}

func livenessTicketSync(ctx context.Context, tx *sql.Tx, tenantID shared.ID, moves []livenessMove) error {
	sm := make([]scopeMove, 0, len(moves))
	for _, m := range moves {
		sm = append(sm, scopeMove{id: m.id, linked: m.linked})
	}
	return queueScopeTicketSync(ctx, tx, tenantID, sm)
}

// CloseGone closes up to limit open findings of the tenant whose asset is
// gone, as resolved / obsolete_asset (never counted as fixed), and returns
// them. Every close has its timeline entry and its audit row, in the same
// transaction.
func (r *AssetLivenessRepository) CloseGone(ctx context.Context, tenantID shared.ID, limit int) (liveness.CloseResult, error) {
	var out liveness.CloseResult
	if limit <= 0 {
		return out, nil
	}
	t := vulnerability.StatusTransition{
		ActivityType: string(vulnerability.ActivityAutoResolved), Source: livenessSource, Reason: "asset_gone",
		ActorType: string(vulnerability.ActorTypeSystem), ActorName: livenessActor,
		Message: "Its asset is gone: the name has had no address long enough (not a fix)",
	}
	var moves []livenessMove
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		//nolint:gosec // G202: fixed SQL fragments with numbered placeholders
		rows, err := tx.QueryContext(ctx, `
			WITH cand AS (
				SELECT f.id, f.status AS old_status, f.severity, COALESCE(f.priority_class, '') AS priority_class,
					COALESCE(f.is_in_kev, false) AS kev, a.id AS asset_id, gl.state, gl.reason
				FROM findings f
				JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
				JOIN asset_liveness gl ON gl.tenant_id = a.tenant_id AND gl.asset_id = a.id AND gl.state = 'gone'
				WHERE f.tenant_id = $1 AND f.status IN `+livenessOpenStatuses+`
				ORDER BY f.id
				LIMIT $2
				FOR UPDATE OF f SKIP LOCKED
			)
			UPDATE findings f SET status = 'resolved', resolution = 'obsolete_asset',
				closure_reason = 'obsolete_asset', verification = 'none',
				resolved_at = NOW(), resolved_by = NULL, updated_at = NOW()
			FROM cand
			WHERE f.id = cand.id AND f.tenant_id = $1
			RETURNING f.id::text, cand.old_status, f.status, cand.severity, cand.priority_class, cand.kev,
				COALESCE(cardinality(f.work_item_uris), 0) > 0, cand.asset_id::text, cand.state, cand.reason`,
			tenantID.String(), limit)
		if err != nil {
			return err
		}
		if moves, err = scanLivenessMoves(rows); err != nil {
			return err
		}
		if err := auditLivenessMoves(ctx, tx, tenantID, "asset_gone", moves); err != nil {
			return err
		}
		return livenessTicketSync(ctx, tx, tenantID, moves)
	})
	if err != nil {
		return out, fmt.Errorf("close findings of gone assets: %w", err)
	}
	for _, m := range moves {
		out.IDs = append(out.IDs, m.id)
		if vulnerability.FindingRiskTier(vulnerability.Severity(m.severity), m.priorityClass, m.kev) == vulnerability.RiskTierCritical {
			out.Critical++
		}
	}
	return out, nil
}

// ReopenNotGone reopens up to limit findings of the tenant that the
// liveness pass closed and whose asset is no longer gone, to the status the
// close moved them from (confirmed when the timeline does not say). Not a
// regression: nothing failed a fix. The SLA deadline is kept. A finding a
// person or a scan closed (or moved) after the liveness close is not the
// pass's to reopen.
func (r *AssetLivenessRepository) ReopenNotGone(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		return nil, nil
	}
	t := vulnerability.StatusTransition{
		ActivityType: string(vulnerability.ActivityAutoReopened), Source: livenessSource, Reason: "asset_back",
		ActorType: string(vulnerability.ActorTypeSystem), ActorName: livenessActor,
		Message: "Its asset is no longer gone",
	}
	var moves []livenessMove
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
			return fmt.Errorf("mark reopen as not a regression: %w", err)
		}
		//nolint:gosec // G202: fixed SQL fragments with numbered placeholders
		rows, err := tx.QueryContext(ctx, `
			WITH cand AS (
				SELECT f.id, f.severity, COALESCE(f.priority_class, '') AS priority_class,
					COALESCE(f.is_in_kev, false) AS kev, a.id AS asset_id,
					l.state, l.reason
				FROM findings f
				-- Only a live asset with stored evidence that it is no
				-- longer gone: no liveness row (pruned, merged away) or a
				-- deleted asset is not a sign that it came back.
				JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.deleted_at IS NULL
				JOIN asset_liveness l ON l.tenant_id = a.tenant_id AND l.asset_id = a.id AND l.state <> 'gone'
				WHERE f.tenant_id = $1 AND f.status = 'resolved' AND f.closure_reason = 'obsolete_asset'
				  AND `+livenessClosedByUsSQL+`
				ORDER BY f.id
				LIMIT $2
				FOR UPDATE OF f SKIP LOCKED
			), back AS (
				SELECT c.*, COALESCE((
					SELECT fa.changes->>'old_status' FROM finding_activities fa
					WHERE fa.tenant_id = $1 AND fa.finding_id = c.id AND fa.source = '`+livenessSource+`'
					  AND fa.changes->>'new_status' = 'resolved'
					  AND fa.changes->>'old_status' IN `+livenessOpenStatuses+`
					ORDER BY fa.created_at DESC
					LIMIT 1), 'confirmed') AS to_status
				FROM cand c
			)
			UPDATE findings f SET status = back.to_status, resolution = NULL,
				closure_reason = NULL, verification = NULL,
				resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
			FROM back
			WHERE f.id = back.id AND f.tenant_id = $1
			RETURNING f.id::text, 'resolved', f.status, back.severity, back.priority_class, back.kev,
				COALESCE(cardinality(f.work_item_uris), 0) > 0, back.asset_id::text, back.state, back.reason`,
			tenantID.String(), limit)
		if err != nil {
			return err
		}
		if moves, err = scanLivenessMoves(rows); err != nil {
			return err
		}
		if err := auditLivenessMoves(ctx, tx, tenantID, "asset_back", moves); err != nil {
			return err
		}
		return livenessTicketSync(ctx, tx, tenantID, moves)
	})
	if err != nil {
		return nil, fmt.Errorf("reopen findings of assets back: %w", err)
	}
	ids := make([]shared.ID, 0, len(moves))
	for _, m := range moves {
		ids = append(ids, m.id)
	}
	return ids, nil
}

// StateCounts counts the tenant's assets per stored liveness state.
func (r *AssetLivenessRepository) StateCounts(ctx context.Context, tenantID shared.ID) (map[string]int, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT l.state, count(*) FROM asset_liveness l
		JOIN assets a ON a.tenant_id = l.tenant_id AND a.id = l.asset_id AND a.deleted_at IS NULL
		WHERE l.tenant_id = $1 GROUP BY l.state`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("count liveness states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// CountOpenFindings counts the open findings (the statuses a gone close
// moves) of the tenant's assets, and those of the critical tier.
func (r *AssetLivenessRepository) CountOpenFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (open, critical int, err error) {
	if len(assetIDs) == 0 {
		return 0, 0, nil
	}
	//nolint:gosec // G202: fixed SQL fragments with numbered placeholders
	err = r.db.QueryRowContext(ctx, `SELECT count(*),
			count(*) FILTER (WHERE f.severity = 'critical' OR f.priority_class = 'P0' OR COALESCE(f.is_in_kev, false))
		FROM findings f
		WHERE f.tenant_id = $1 AND f.asset_id = ANY($2::uuid[]) AND f.status IN `+livenessOpenStatuses,
		tenantID.String(), pq.Array(coverageIDStrings(assetIDs))).Scan(&open, &critical)
	if err != nil {
		return 0, 0, fmt.Errorf("count open findings: %w", err)
	}
	return open, critical, nil
}

// CountReopenable counts the findings the liveness pass closed whose asset
// is not among stillGone.
func (r *AssetLivenessRepository) CountReopenable(ctx context.Context, tenantID shared.ID, stillGone []shared.ID) (int, error) {
	var n int
	//nolint:gosec // G202: fixed SQL fragments with numbered placeholders
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings f
		WHERE f.tenant_id = $1 AND f.status = 'resolved' AND f.closure_reason = 'obsolete_asset'
		  AND NOT (f.asset_id = ANY($2::uuid[])) AND `+livenessClosedByUsSQL,
		tenantID.String(), pq.Array(coverageIDStrings(stillGone))).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count findings to reopen: %w", err)
	}
	return n, nil
}

// ForAssets returns the stored liveness of the tenant's assets, with the
// name of the zone or sensor of the last check (the tenant's own only).
func (r *AssetLivenessRepository) ForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]liveness.View, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT l.asset_id::text, l.state, l.reason, l.state_since, l.last_checked_at, l.last_capability, l.last_outcome,
		       l.last_alive_at,
		       COALESCE(CASE
		           WHEN l.last_checked_by LIKE 'zone:%' THEN (SELECT z.name FROM scan_zones z
		               WHERE z.tenant_id = l.tenant_id AND z.id::text = substr(l.last_checked_by, 6))
		           WHEN l.last_checked_by LIKE 'sensor:%' THEN (SELECT s.name FROM sensors s
		               WHERE s.tenant_id = l.tenant_id AND s.id::text = substr(l.last_checked_by, 8))
		       END, '')
		FROM asset_liveness l
		WHERE l.tenant_id = $1 AND l.asset_id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read asset liveness: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[shared.ID]liveness.View, len(ids))
	for rows.Next() {
		var (
			id                   string
			v                    liveness.View
			since, checked, live sql.NullTime
		)
		if err := rows.Scan(&id, &v.State, &v.Reason, &since, &checked, &v.LastCapability, &v.LastOutcome, &live, &v.LastCheckedBy); err != nil {
			return nil, err
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		v.Since, v.LastCheckedAt, v.LastAliveAt = timePtr(since), timePtr(checked), timePtr(live)
		out[aid] = v
	}
	return out, rows.Err()
}
