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

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
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
const scopeEffectsOpenStatuses = `('new', 'confirmed', 'in_progress', 'fix_applied')`

// assetOutOfScopeForGoodSQL is "the asset (alias a) is out of scope for
// good": marked not ours, or matched by a permanent, approved, active
// exclusion of a closing kind. The match is the inventory scope filter's
// (asset_scope_status.go), so the list, the preview and this agree.
func assetOutOfScopeForGoodSQL(a string) string {
	h, i, n := "sh.host", "sh.ip", "lower("+a+".name)"
	return `(SELECT EXISTS (SELECT 1 FROM asset_attributions srj
		             WHERE srj.asset_id = ` + a + `.id AND srj.tenant_id = ` + a + `.tenant_id AND srj.state = 'rejected')
		  OR EXISTS (SELECT 1 FROM scope_exclusions se
		             WHERE se.tenant_id = ` + a + `.tenant_id AND se.status = 'active' AND se.approved_at IS NOT NULL
		               AND se.expires_at IS NULL AND se.kind IN ('not_ours', 'retired')
		               AND se.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
		               AND ` + scopePatternMatchSQL("se.exclusion_type", "se.pattern", h, i, n) + `)
	FROM (SELECT hh.host, CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip
	      FROM (SELECT ` + assetHostSQL(a) + ` AS host) hh) sh)`
}

// TenantsWithScopeEffects lists the tenants that may have findings to close
// or reopen: a closing exclusion or a "not ours" decision exists, or a
// finding is closed as out of scope.
func (r *ScopeEffectsRepository) TenantsWithScopeEffects(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id::text FROM scope_exclusions
		WHERE kind IN ('not_ours', 'retired') AND status = 'active' AND expires_at IS NULL
		UNION
		SELECT tenant_id::text FROM asset_attributions WHERE state = 'rejected'
		UNION
		SELECT tenant_id::text FROM findings WHERE closure_reason = 'out_of_scope' AND status = 'resolved'`)
	if err != nil {
		return nil, fmt.Errorf("list tenants with scope effects: %w", err)
	}
	return scanIDs(rows)
}

// CloseOutOfScope closes up to limit open findings of the tenant whose asset
// is out of scope for good, as resolved / out_of_scope, and returns their
// ids.
func (r *ScopeEffectsRepository) CloseOutOfScope(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		return nil, nil
	}
	t := vulnerability.StatusTransition{
		ActivityType: "auto_resolved", Source: "scope_effects", Reason: "out_of_scope",
		ActorType: "system", ActorName: "system: out of scope",
		Message: "Its asset was marked out of scope (not ours or retired)",
	}
	ids, err := r.db.queryIDsWithTransition(ctx, t, `
		WITH cand AS (
			SELECT f.id FROM findings f
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
		RETURNING f.id::text`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("close out-of-scope findings: %w", err)
	}
	return ids, nil
}

// ReopenBackInScope reopens up to limit findings of the tenant closed as out
// of scope whose asset is no longer out of scope for good, to the status the
// close moved them from (confirmed when the timeline does not say), and
// returns their ids. A reopen is not a regression: nothing failed a fix.
func (r *ScopeEffectsRepository) ReopenBackInScope(ctx context.Context, tenantID shared.ID, limit int) ([]shared.ID, error) {
	if limit <= 0 {
		return nil, nil
	}
	t := vulnerability.StatusTransition{
		ActivityType: "auto_reopened", Source: "scope_effects", Reason: "back_in_scope",
		ActorType: "system", ActorName: "system: out of scope",
		Message: "Its asset is no longer marked out of scope",
	}
	var out []shared.ID
	err := r.db.withFindingTransition(ctx, t, func(tx *sql.Tx) error {
		// The regression trigger counts a reopen of a resolved finding as a
		// failed fix unless a person's move says otherwise; this one never is.
		if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.person_move', 'on', true)`); err != nil {
			return fmt.Errorf("mark reopen as not a regression: %w", err)
		}
		//nolint:gosec // G202: the predicate and status list are fixed SQL with numbered placeholders
		rows, err := tx.QueryContext(ctx, `
			WITH cand AS (
				SELECT f.id FROM findings f
				JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
				WHERE f.tenant_id = $1 AND f.status = 'resolved' AND f.closure_reason = 'out_of_scope'
				  AND NOT `+assetOutOfScopeForGoodSQL("a")+`
				ORDER BY f.id
				LIMIT $2
				FOR UPDATE OF f SKIP LOCKED
			), back AS (
				SELECT c.id, COALESCE((
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
			RETURNING f.id::text`, tenantID.String(), limit)
		if err != nil {
			return err
		}
		out, err = scanIDs(rows)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("reopen findings back in scope: %w", err)
	}
	return out, nil
}
