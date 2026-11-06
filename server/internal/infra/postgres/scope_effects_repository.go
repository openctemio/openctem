package postgres

// Scope effects (research/320, RFC-054 §20): what marking something out of
// scope does to its findings. The open findings of an asset that is out of
// scope for good (a permanent, approved, active exclusion of kind not_ours
// or retired matches it, or the organization marked it not its own) are
// closed as resolved with the closure reason out_of_scope; a finding closed
// that way whose asset is no longer out of scope for good is reopened to the
// status it had. Tasks, tickets and SLA clocks follow the findings through
// their own reconcilers.
//
// Every statement is pinned to one tenant (findings, assets, attributions,
// exclusions and timeline rows of that tenant only), locks the rows it
// moves with SKIP LOCKED (a person editing a finding is never overwritten
// mid-edit; the next pass picks it up), and records each move on the
// finding's timeline through the transition trigger.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/durablejob"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// ScopeEffectsRepository closes and reopens findings as their assets go out
// of scope and come back.
type ScopeEffectsRepository struct {
	db *DB
}

// NewScopeEffectsRepository creates a ScopeEffectsRepository.
func NewScopeEffectsRepository(db *DB) *ScopeEffectsRepository {
	return &ScopeEffectsRepository{db: db}
}

// scopeEffectsOpenStatuses are the statuses an out-of-scope close moves:
// published, still needing action. Pentest drafts are left to their author.
// Names the scope effects pass writes on timeline entries and audit rows.
const (
	scopeEffectsSource = "scope_effects"
	scopeEffectsActor  = "system: out of scope"
	auditKeyKind       = "kind"
	auditKeyActorKind  = "actor_kind"
	scopeHostCol       = "sh.host"
	scopeIPCol         = "sh.ip"
	auditKeySource     = "source"
)

const scopeEffectsOpenStatuses = `('new', 'confirmed', 'in_progress', 'fix_applied')`

// scopeEffectsCutoverSQL is when out-of-scope decisions started to close
// findings (migration scope_effects_cutover). Decisions older than it only
// stop scanning, as before the feature; a missing row closes nothing.
const scopeEffectsCutoverSQL = `(SELECT effective_at FROM scope_effects_cutover)`

// scopeRejectedDecisionSQL is "the organization marked the asset (alias a)
// not its own" at or after the cut-over.
func scopeRejectedDecisionSQL(a string) string {
	return `EXISTS (SELECT 1 FROM asset_attributions srj
		             WHERE srj.asset_id = ` + a + `.id AND srj.tenant_id = ` + a + `.tenant_id AND srj.state = 'rejected'
		               AND COALESCE(srj.decided_at, srj.updated_at) >= ` + scopeEffectsCutoverSQL + `)`
}

// scopeClosingExclusionsSQL is the FROM/WHERE of the permanent, approved,
// active exclusions of a closing kind that match the asset (alias a), with
// its host in sh.host / sh.ip (see assetScopeSQL).
func scopeClosingExclusionsSQL(a string) string {
	h, i, n := scopeHostCol, scopeIPCol, "lower("+a+".name)"
	return `scope_exclusions se
		             WHERE se.tenant_id = ` + a + `.tenant_id AND se.status = 'active' AND se.approved_at IS NOT NULL
		               AND se.expires_at IS NULL AND se.kind IN ('not_ours', 'retired')
		               AND se.updated_at >= ` + scopeEffectsCutoverSQL + `
		               AND se.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
		               AND ` + scopePatternMatchSQL("se.exclusion_type", "se.pattern", h, i, n)
}

// assetScopeSQL evaluates expr for the asset (alias a) with its host bound
// as sh.host and sh.ip.
func assetScopeSQL(a, expr string) string {
	return `(SELECT ` + expr + `
	FROM (SELECT hh.host, CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip
	      FROM (SELECT ` + assetHostSQL(a) + ` AS host) hh) sh)`
}

// assetOutOfScopeForGoodSQL is "the asset (alias a) is out of scope for
// good": marked not ours, or matched by a permanent, approved, active
// exclusion of a closing kind. The match is the inventory scope filter's
// (asset_scope_status.go), so the list, the preview and this agree.
func assetOutOfScopeForGoodSQL(a string) string {
	return assetScopeSQL(a, scopeRejectedDecisionSQL(a)+`
		  OR EXISTS (SELECT 1 FROM `+scopeClosingExclusionsSQL(a)+`)`)
}

// assetScopeCauseSQL is why the asset (alias a) is out of scope for good:
// the matching closing exclusions as "id:kind" text, in id order (empty when
// none matches).
func assetScopeCauseSQL(a string) string {
	return assetScopeSQL(a, `COALESCE((SELECT array_agg(se.id::text || ':' || se.kind ORDER BY se.id) FROM `+
		scopeClosingExclusionsSQL(a)+`), '{}')`)
}

// TenantsWithScopeEffects lists the tenants that may have findings to close
// or reopen: a closing exclusion or a "not ours" decision exists, or a
// finding is closed as out of scope.
func (r *ScopeEffectsRepository) TenantsWithScopeEffects(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id::text FROM scope_exclusions
		WHERE kind IN ('not_ours', 'retired') AND status = 'active' AND expires_at IS NULL
		  AND updated_at >= `+scopeEffectsCutoverSQL+`
		UNION
		SELECT tenant_id::text FROM asset_attributions WHERE state = 'rejected'
		  AND COALESCE(decided_at, updated_at) >= `+scopeEffectsCutoverSQL+`
		UNION
		SELECT tenant_id::text FROM findings WHERE closure_reason = 'out_of_scope' AND status = 'resolved'`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with scope effects: %w", err)
	}
	return scanIDs(rows)
}

// scopeMove is one finding a scope effects pass moved, with what the audit
// row needs.
type scopeMove struct {
	id            shared.ID
	from, to      string
	severity      string
	priorityClass string
	kev           bool
	exclusions    []string // "id:kind" of the closing exclusions that matched
	notOurs       bool     // the organization marked the asset not its own
	linked        bool     // the finding has a ticket (work item) linked
}

// scanScopeMoves reads the moved rows (id, from, to, severity, priority
// class, kev, exclusions, not ours, linked) and closes rows.
func scanScopeMoves(rows *sql.Rows) ([]scopeMove, error) {
	defer rows.Close()
	var out []scopeMove
	for rows.Next() {
		var m scopeMove
		var id string
		if err := rows.Scan(&id, &m.from, &m.to, &m.severity, &m.priorityClass, &m.kev,
			pq.Array(&m.exclusions), &m.notOurs, &m.linked); err != nil {
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

// auditScopeMoves writes, in tx, the finding.status_changed audit row of
// every move: the same action a person's status change writes, so a close
// or reopen by scope effects is accountable finding by finding (the
// timeline goes with the finding; audit_logs stay). It names what caused it
// (the exclusions with their kind, or the "not ours" decision). Closing a
// finding of the critical tier (critical, P0 or KEV) is high, any other
// move medium.
func auditScopeMoves(ctx context.Context, tx *sql.Tx, tenantID shared.ID, trigger string, moves []scopeMove) error {
	for _, m := range moves {
		level := audit.SeverityMedium
		next := vulnerability.FindingStatus(m.to)
		if !vulnerability.IsOpenStatus(next) &&
			vulnerability.FindingRiskTier(vulnerability.Severity(m.severity), m.priorityClass, m.kev) == vulnerability.RiskTierCritical {
			level = audit.SeverityHigh
		}
		excl := make([]map[string]string, 0, len(m.exclusions))
		for _, e := range m.exclusions {
			id, kind, _ := strings.Cut(e, ":")
			excl = append(excl, map[string]string{"id": id, auditKeyKind: kind})
		}
		meta := map[string]any{
			auditKeyOldStatus: m.from, auditKeyNewStatus: m.to, auditKeySeverity: m.severity,
			"actor": scopeEffectsActor, auditKeyActorKind: string(vulnerability.ActorTypeSystem),
			auditKeySource: scopeEffectsSource, auditKeyTrigger: trigger,
			"exclusions": excl, "not_ours_decision": m.notOurs,
		}
		if next == vulnerability.FindingStatusResolved {
			meta["closure_reason"] = string(vulnerability.ClosureReasonOutOfScope)
			meta["verification"] = string(vulnerability.VerificationNone)
		}
		if err := insertDecisionAudit(ctx, tx, tenantID, m.id, string(audit.ActionFindingStatusChanged), string(level),
			fmt.Sprintf("Finding status changed from %s to %s", m.from, m.to), meta); err != nil {
			return err
		}
	}
	return nil
}

// queueScopeTicketSync queues, in tx, the outbound ticket status push of
// every moved finding that has a ticket, the same durable jobs a person's
// status change queues. The workers do nothing unless the organization
// opted in; a finding closed as out of scope gets a comment on its ticket
// instead of a close, since nothing was fixed (jira.SyncService,
// ticketing.GitHubTicketService).
func queueScopeTicketSync(ctx context.Context, tx *sql.Tx, tenantID shared.ID, moves []scopeMove) error {
	var jobs []durablejob.Job
	for _, m := range moves {
		if m.linked {
			jobs = append(jobs, durablejob.StatusSyncJobs(tenantID, m.id)...)
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	return insertDurableJobsTx(ctx, tx, jobs)
}

// CloseOutOfScope closes up to limit open findings of the tenant whose asset
// is out of scope for good, as resolved / out_of_scope, and returns their
// ids. Every close has its timeline entry and its audit row, in the same
// transaction.
func (r *ScopeEffectsRepository) CloseOutOfScope(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		return nil, nil
	}
	t := vulnerability.StatusTransition{
		ActivityType: string(vulnerability.ActivityAutoResolved), Source: scopeEffectsSource, Reason: "out_of_scope",
		ActorType: string(vulnerability.ActorTypeSystem), ActorName: scopeEffectsActor,
		Message: "Its asset was marked out of scope (not ours or retired)",
	}
	var moves []scopeMove
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		//nolint:gosec // G202: the predicate and status list are fixed SQL with numbered placeholders
		rows, err := tx.QueryContext(ctx, `
			WITH cand AS (
				SELECT f.id, f.status AS old_status, f.severity, COALESCE(f.priority_class, '') AS priority_class,
					COALESCE(f.is_in_kev, false) AS kev,
					`+assetScopeCauseSQL("a")+` AS exclusions,
					`+scopeRejectedDecisionSQL("a")+` AS not_ours
				FROM findings f
				JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
				WHERE f.tenant_id = $1 AND f.status IN `+scopeEffectsOpenStatuses+`
				  AND `+assetOutOfScopeForGoodSQL("a")+`
				ORDER BY f.id
				LIMIT $2
				FOR UPDATE OF f SKIP LOCKED
			)
			UPDATE findings f SET status = 'resolved', resolution = 'out_of_scope',
				closure_reason = 'out_of_scope', verification = 'none',
				resolved_at = NOW(), resolved_by = NULL, updated_at = NOW()
			FROM cand
			WHERE f.id = cand.id AND f.tenant_id = $1
			RETURNING f.id::text, cand.old_status, f.status, cand.severity, cand.priority_class, cand.kev,
				cand.exclusions, cand.not_ours, COALESCE(cardinality(f.work_item_uris), 0) > 0`, tenantID.String(), limit)
		if err != nil {
			return err
		}
		if moves, err = scanScopeMoves(rows); err != nil {
			return err
		}
		if err := auditScopeMoves(ctx, tx, tenantID, "out_of_scope", moves); err != nil {
			return err
		}
		return queueScopeTicketSync(ctx, tx, tenantID, moves)
	})
	if err != nil {
		return nil, fmt.Errorf("close out-of-scope findings: %w", err)
	}
	return moveIDs(moves), nil
}

// moveIDs is the finding ids of moves.
func moveIDs(moves []scopeMove) []shared.ID {
	out := make([]shared.ID, 0, len(moves))
	for _, m := range moves {
		out = append(out, m.id)
	}
	return out
}

// ReopenBackInScope reopens up to limit findings of the tenant closed as out
// of scope whose asset is no longer out of scope for good, to the status the
// close moved them from (confirmed when the timeline does not say), and
// returns their ids. A reopen is not a regression: nothing failed a fix.
// The SLA deadline is kept, so excluding and re-including never resets a
// clock. Every reopen has its timeline entry and its audit row.
func (r *ScopeEffectsRepository) ReopenBackInScope(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		return nil, nil
	}
	t := vulnerability.StatusTransition{
		ActivityType: string(vulnerability.ActivityAutoReopened), Source: scopeEffectsSource, Reason: "back_in_scope",
		ActorType: string(vulnerability.ActorTypeSystem), ActorName: scopeEffectsActor,
		Message: "Its asset is no longer marked out of scope",
	}
	var moves []scopeMove
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		// The regression trigger counts a reopen of a resolved finding as a
		// failed fix unless a person's move says otherwise; this one never is.
		if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
			return fmt.Errorf("mark reopen as not a regression: %w", err)
		}
		//nolint:gosec // G202: the predicate and status list are fixed SQL with numbered placeholders
		rows, err := tx.QueryContext(ctx, `
			WITH cand AS (
				SELECT f.id, f.severity, COALESCE(f.priority_class, '') AS priority_class,
					COALESCE(f.is_in_kev, false) AS kev
				FROM findings f
				JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
				WHERE f.tenant_id = $1 AND f.status = 'resolved' AND f.closure_reason = 'out_of_scope'
				  AND NOT `+assetOutOfScopeForGoodSQL("a")+`
				ORDER BY f.id
				LIMIT $2
				FOR UPDATE OF f SKIP LOCKED
			), back AS (
				SELECT c.*, COALESCE((
					SELECT fa.changes->>'old_status' FROM finding_activities fa
					WHERE fa.tenant_id = $1 AND fa.finding_id = c.id
					  AND fa.changes->>'new_status' = 'resolved'
					  AND fa.changes->>'closure_reason' = 'out_of_scope'
					  AND fa.changes->>'old_status' IN `+scopeEffectsOpenStatuses+`
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
				'{}'::text[], false, COALESCE(cardinality(f.work_item_uris), 0) > 0`, tenantID.String(), limit)
		if err != nil {
			return err
		}
		if moves, err = scanScopeMoves(rows); err != nil {
			return err
		}
		if err := auditScopeMoves(ctx, tx, tenantID, "back_in_scope", moves); err != nil {
			return err
		}
		return queueScopeTicketSync(ctx, tx, tenantID, moves)
	})
	if err != nil {
		return nil, fmt.Errorf("reopen findings back in scope: %w", err)
	}
	return moveIDs(moves), nil
}
