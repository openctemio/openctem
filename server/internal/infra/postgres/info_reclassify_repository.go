package postgres

// Stored informational template-scan findings moved to exposures
// (docs/architecture/exposure-taxonomy.md, "Template scanner info matches",
// "Findings filed before"). Since info matches of a template scanner become
// exposures at ingest, the ones filed as findings before stay open forever:
// no scan reports them as findings again. The refingerprint command's
// -info-exposures mode moves them the way ingest moves a new match: the
// asset gets the same exposure event (same fingerprint, so the next scan
// bumps it instead of filing a second one), and the finding is resolved
// with the closure reason reclassified_exposure (never counted as fixed),
// its severity none becoming info. The finding row, its timeline, comments
// and evidence stay; the move writes one timeline entry per finding.
//
// A finding a person or an integration still works on is left as it is and
// counted: one with an active ticket link (a move must never close or
// change a ticket), in an open remediation task, with a pending status
// approval or a pending closure proposal.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/exposure"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// InfoFinding is one stored informational finding of a template scanner.
type InfoFinding struct {
	ID, AssetID             shared.ID
	Tool, RuleID, Title     string
	Matcher, URL, Severity  string
	Tags                    []string
	FirstSeenAt, LastSeenAt time.Time
	// Held: a person or an integration works on it (see the file comment);
	// it is never moved.
	Held bool
}

// InfoReclassification is one move: the finding and the exposure event it
// becomes.
type InfoReclassification struct {
	Finding InfoFinding
	Event   *exposure.ExposureEvent
}

// InfoReclassifyRepository reads and moves stored informational findings.
type InfoReclassifyRepository struct{ db *DB }

// NewInfoReclassifyRepository creates the repository.
func NewInfoReclassifyRepository(db *DB) *InfoReclassifyRepository {
	return &InfoReclassifyRepository{db: db}
}

// infoFindingSQL selects the open informational findings of a tenant on a
// live asset of the same tenant, outside branches and pentests.
var infoFindingSQL = `
	FROM findings f
	JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.deleted_at IS NULL
	WHERE f.tenant_id = $1
		AND f.severity IN ('info', 'none')
		AND f.status IN ` + autoResolveFromSQL + `
		AND f.branch_id IS NULL
		AND f.pentest_campaign_id IS NULL
		AND f.tool_name = ANY($2)`

// TenantsWithInfoFindings lists the tenants with an open informational
// finding of one of tools.
func (r *InfoReclassifyRepository) TenantsWithInfoFindings(ctx context.Context, tools []string) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT f.tenant_id::text FROM findings f
		WHERE f.severity IN ('info', 'none') AND f.status IN `+autoResolveFromSQL+`
			AND f.branch_id IS NULL AND f.pentest_campaign_id IS NULL AND f.tool_name = ANY($1)
		ORDER BY 1`, pq.Array(tools))
	if err != nil {
		return nil, fmt.Errorf("list tenants with info findings: %w", err)
	}
	return scanIDs(rows)
}

// InfoFindings returns up to limit open informational findings of tools in
// the tenant with an id above after (keyset order), held ones included and
// marked.
func (r *InfoReclassifyRepository) InfoFindings(ctx context.Context, tenantID shared.ID, tools []string, after string, limit int) ([]InfoFinding, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, f.asset_id::text, f.tool_name, COALESCE(f.rule_id, ''), COALESCE(f.title, ''),
			COALESCE(f.source_extra->>'matcher_name', ''), COALESCE(f.file_path, ''), f.severity,
			COALESCE(f.tags, '{}'), f.first_detected_at, f.last_seen_at,
			(EXISTS (SELECT 1 FROM ticket_links t WHERE t.tenant_id = f.tenant_id AND t.finding_id = f.id AND t.state = 'active')
			 OR EXISTS (SELECT 1 FROM remediation_task_members m JOIN remediation_tasks rt ON rt.id = m.task_id AND rt.tenant_id = m.tenant_id
				WHERE m.tenant_id = f.tenant_id AND m.finding_id = f.id AND m.left_at IS NULL)
			 OR EXISTS (SELECT 1 FROM finding_status_approvals p WHERE p.tenant_id = f.tenant_id AND p.finding_id = f.id AND p.status = 'pending')
			 OR EXISTS (SELECT 1 FROM finding_closure_proposals c WHERE c.tenant_id = f.tenant_id AND c.finding_id = f.id AND c.state = 'pending')
			 OR COALESCE(cardinality(f.work_item_uris), 0) > 0) AS held
		`+infoFindingSQL+`
			AND f.id::text > $3
		ORDER BY f.id::text
		LIMIT $4`, tenantID.String(), pq.Array(tools), after, limit)
	if err != nil {
		return nil, fmt.Errorf("list info findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []InfoFinding
	for rows.Next() {
		var (
			f           InfoFinding
			id, asset   string
			first, last sql.NullTime
			tags        pq.StringArray
		)
		if err := rows.Scan(&id, &asset, &f.Tool, &f.RuleID, &f.Title, &f.Matcher, &f.URL, &f.Severity,
			&tags, &first, &last, &f.Held); err != nil {
			return nil, fmt.Errorf("scan info finding: %w", err)
		}
		if f.ID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		if f.AssetID, err = shared.IDFromString(asset); err != nil {
			return nil, err
		}
		f.Tags = tags
		f.FirstSeenAt, f.LastSeenAt = first.Time, last.Time
		out = append(out, f)
	}
	return out, rows.Err()
}

// infoReclassifyReason is the timeline reason of a move.
const infoReclassifyReason = "reclassified_exposure"

// Reclassify moves the findings of one batch in one transaction: each gets
// its exposure event (inserted with the finding's first and last sighting;
// an event already there keeps its state and widens its seen window), and
// is resolved as reclassified_exposure with its timeline entry, which names
// the exposure event and the severity it had. A finding that is no longer
// an open informational one (a person moved it meanwhile) is skipped.
// Returns the ids moved.
func (r *InfoReclassifyRepository) Reclassify(ctx context.Context, tenantID shared.ID, moves []InfoReclassification) ([]shared.ID, error) {
	if len(moves) == 0 {
		return nil, nil
	}
	var moved []shared.ID
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
			return err
		}
		for _, m := range moves {
			if m.Event == nil || m.Event.TenantID() != tenantID || m.Finding.Held {
				continue
			}
			eventID, err := upsertReclassifiedEvent(ctx, tx, m)
			if err != nil {
				return err
			}
			if err := setFindingTransition(ctx, tx, findingTransition{
				Source: "info_reclassify", Reason: infoReclassifyReason, ActorName: "system: info match moved to exposures",
				Message: "An informational template match: moved to the asset's exposures, not fixed",
				Changes: map[string]any{"exposure_event_id": eventID, "previous_severity": m.Finding.Severity},
			}); err != nil {
				return err
			}
			var id string
			err = tx.QueryRowContext(ctx, `UPDATE findings f SET status = 'resolved', resolution = 'reclassified_exposure',
				closure_reason = 'reclassified_exposure', verification = 'none', resolved_at = NOW(), resolved_by = NULL,
				severity = CASE WHEN f.severity = 'none' THEN 'info' ELSE f.severity END, updated_at = NOW()
				WHERE f.tenant_id = $1 AND f.id = $2 AND f.severity IN ('info', 'none') AND f.status IN `+autoResolveFromSQL+`
				RETURNING f.id::text`, tenantID.String(), m.Finding.ID.String()).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				// Moved by someone meanwhile: the event stays (the match is real).
				continue
			}
			if err != nil {
				return fmt.Errorf("resolve reclassified finding: %w", err)
			}
			moved = append(moved, m.Finding.ID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return moved, nil
}

// upsertReclassifiedEvent stores the event of a move and returns its id.
// A new event carries the finding's sighting window and names the finding
// it came from (details.reclassified_from_finding, the down move's
// marker); an existing one (the same match a later scan filed) keeps its
// state and details, its window widened to the finding's.
func upsertReclassifiedEvent(ctx context.Context, tx *sql.Tx, m InfoReclassification) (string, error) {
	ev := m.Event
	details := ev.Details()
	details["reclassified_from_finding"] = m.Finding.ID.String()
	raw, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("marshal details: %w", err)
	}
	first, last := m.Finding.FirstSeenAt, m.Finding.LastSeenAt
	if first.IsZero() {
		first = ev.FirstSeenAt()
	}
	if last.IsZero() || last.Before(first) {
		last = first
	}
	var id string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, severity, state, title, description,
			details, fingerprint, source, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8, $9, $10, $11, $12, NOW(), NOW())
		ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
			first_seen_at = LEAST(exposure_events.first_seen_at, EXCLUDED.first_seen_at),
			last_seen_at = GREATEST(exposure_events.last_seen_at, EXCLUDED.last_seen_at)
		RETURNING id::text`,
		ev.ID().String(), ev.TenantID().String(), nullIDPtr(ev.AssetID()), ev.EventType().String(), ev.Severity().String(),
		ev.State().String(), ev.Title(), raw, ev.Fingerprint(), ev.Source(), first, last).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("store exposure event: %w", err)
	}
	return id, nil
}

// CountReclassified counts the tenant's findings resolved as
// reclassified_exposure (what -down would reopen).
func (r *InfoReclassifyRepository) CountReclassified(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings
		WHERE tenant_id = $1 AND status = 'resolved' AND closure_reason = 'reclassified_exposure'`, tenantID.String()).Scan(&n)
	return n, err
}

// ReclassifiedRestore is what the down move did in one tenant.
type ReclassifiedRestore struct {
	Reopened      int `json:"reopened"`
	EventsRemoved int `json:"events_removed"`
	EventsKept    int `json:"events_kept"`
}

// RestoreReclassified undoes the moves of the tenant (the recovery of
// -info-exposures): each finding resolved as reclassified_exposure returns
// to the status and severity its move recorded on its timeline, with a
// timeline entry; an event the move created and nothing touched since is
// removed, one a later scan saw again is kept (the match is real). Batched;
// returns what it did.
func (r *InfoReclassifyRepository) RestoreReclassified(ctx context.Context, tenantID shared.ID, limit int) (ReclassifiedRestore, error) {
	var out ReclassifiedRestore
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
			return err
		}
		todo, err := reclassifiedToRestore(ctx, tx, tenantID, limit)
		if err != nil {
			return err
		}
		for _, x := range todo {
			st := vulnerability.FindingStatus(x.status)
			if st.IsClosed() || !st.IsValid() {
				st = vulnerability.FindingStatusConfirmed
			}
			if err := setFindingTransition(ctx, tx, findingTransition{
				Source: "info_reclassify", Reason: "reclassification_undone", ActorName: "system: info match moved back",
				Message: "The move to exposures was undone",
			}); err != nil {
				return err
			}
			res, err := tx.ExecContext(ctx, `UPDATE findings SET status = $3, resolution = NULL, closure_reason = NULL,
				verification = NULL, resolved_at = NULL, resolved_by = NULL,
				severity = CASE WHEN $4 IN ('info', 'none') THEN $4 ELSE severity END, updated_at = NOW()
				WHERE tenant_id = $1 AND id = $2 AND status = 'resolved' AND closure_reason = 'reclassified_exposure'`,
				tenantID.String(), x.id, string(st), x.severity)
			if err != nil {
				return fmt.Errorf("reopen reclassified finding: %w", err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			out.Reopened++
			if x.event == "" {
				continue
			}
			// Created by this move and untouched since: removed.
			del, err := tx.ExecContext(ctx, `DELETE FROM exposure_events
				WHERE tenant_id = $1 AND id::text = $2 AND details->>'reclassified_from_finding' = $3
					AND ($4::timestamptz IS NULL OR updated_at <= $4::timestamptz + interval '1 minute')`,
				tenantID.String(), x.event, x.id, x.resolvedAt)
			if err != nil {
				return fmt.Errorf("remove reclassified exposure: %w", err)
			}
			if n, _ := del.RowsAffected(); n > 0 {
				out.EventsRemoved++
			} else {
				out.EventsKept++
			}
		}
		return nil
	})
	return out, err
}

// reclassifiedRestore is one moved finding and what its move recorded.
type reclassifiedRestore struct {
	id, status, severity, event string
	resolvedAt                  sql.NullTime
}

// reclassifiedToRestore locks up to limit moved findings of the tenant and
// reads the status, severity and exposure event their move recorded.
func reclassifiedToRestore(ctx context.Context, tx *sql.Tx, tenantID shared.ID, limit int) ([]reclassifiedRestore, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT f.id::text, COALESCE(a.changes->>'old_status', 'confirmed'), COALESCE(a.changes->>'previous_severity', f.severity),
			COALESCE(a.changes->>'exposure_event_id', ''), f.resolved_at
		FROM findings f
		LEFT JOIN LATERAL (
			SELECT fa.changes FROM finding_activities fa
			WHERE fa.tenant_id = f.tenant_id AND fa.finding_id = f.id AND fa.source = 'info_reclassify'
				AND fa.changes->>'new_status' = 'resolved'
			ORDER BY fa.created_at DESC LIMIT 1
		) a ON true
		WHERE f.tenant_id = $1 AND f.status = 'resolved' AND f.closure_reason = 'reclassified_exposure'
		ORDER BY f.id LIMIT $2
		FOR UPDATE OF f`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list reclassified findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []reclassifiedRestore
	for rows.Next() {
		var x reclassifiedRestore
		if err := rows.Scan(&x.id, &x.status, &x.severity, &x.event, &x.resolvedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
