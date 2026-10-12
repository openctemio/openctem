package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// terminalStatusFilter excludes every closed/terminal status (matches
// FindingStatus.IsClosed). 'closed' is not a real status value; an earlier
// list also missed accepted/duplicate, so a
// risk-accepted CVE got force-escalated to critical on every KEV sync,
// overriding a deliberate human decision.
const terminalStatusFilter = `status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate')`

// KEVEscalator auto-escalates findings whose CVEs are in the CISA KEV catalog.
type KEVEscalator struct {
	db *DB
}

// NewKEVEscalator creates a new KEVEscalator.
func NewKEVEscalator(db *DB) *KEVEscalator {
	return &KEVEscalator{db: db}
}

// EscalateKEVFindings reconciles findings against the CISA KEV catalog.
//
// Runs across ALL tenants — this is intentional: KEV is a global catalog from
// CISA, and any finding with a KEV CVE should be reconciled regardless of
// tenant. It performs two independent, non-terminal-scoped updates:
//
//  1. Severity escalation — non-critical findings whose CVE is in KEV are
//     raised to 'critical'.
//  2. is_in_kev reconciliation — is_in_kev is set true for EVERY finding whose
//     CVE is in KEV, independent of severity. This is a fact about the CVE, not
//     a workflow decision, so an already-critical KEV finding (which the
//     escalation update skips) still gets flagged.
//  3. Unflagging — a finding whose CVE is no longer in KEV (CISA removed it;
//     the sync prunes kev_catalog) gets is_in_kev=false and kev_due_date
//     cleared. This runs on every status: a resolved finding must not keep
//     claiming a fact that stopped being true. Severity is NOT lowered: the
//     escalation did not record the severity it replaced, and a human may have
//     confirmed critical since.
//
// Updates 1 and 2 skip terminal/closed statuses. Returns what changed plus the
// distinct set of tenants touched, so the caller can enqueue a priority
// reclassify per tenant (severity=critical + is_in_kev=true should drive those
// findings toward P0 via the classifier's KEV/severity ladder).
func (e *KEVEscalator) EscalateKEVFindings(ctx context.Context) (threat.KEVEscalationResult, error) {
	result := threat.KEVEscalationResult{}
	tenantSet := make(map[shared.ID]struct{})

	// 1. Severity escalation — non-critical KEV findings become critical.
	escQuery := `
		UPDATE findings
		SET severity = 'critical', updated_at = NOW()
		WHERE cve_id IN (SELECT cve_id FROM kev_catalog)
		  AND severity != 'critical'
		  AND ` + terminalStatusFilter + `
		  AND cve_id IS NOT NULL
		  AND cve_id != ''
		RETURNING tenant_id
	`
	escalated, err := e.runReturningTenants(ctx, escQuery, tenantSet)
	if err != nil {
		return result, fmt.Errorf("failed to escalate KEV findings: %w", err)
	}
	result.Escalated = escalated

	// 2. is_in_kev reconciliation — set the flag for every KEV finding whose
	// flag is still false, REGARDLESS of severity (so an already-critical KEV
	// finding, which update 1 skips, is still flagged). Only false→true here.
	flagQuery := `
		UPDATE findings
		SET is_in_kev = true, updated_at = NOW()
		WHERE cve_id IN (SELECT cve_id FROM kev_catalog)
		  AND is_in_kev = false
		  AND ` + terminalStatusFilter + `
		  AND cve_id IS NOT NULL
		  AND cve_id != ''
		RETURNING tenant_id
	`
	flagged, err := e.runReturningTenants(ctx, flagQuery, tenantSet)
	if err != nil {
		return result, fmt.Errorf("failed to reconcile is_in_kev: %w", err)
	}
	result.Flagged = flagged

	// 3. Unflag findings whose CVE left KEV.
	unflagQuery := `
		UPDATE findings
		SET is_in_kev = false, kev_due_date = NULL, updated_at = NOW()
		WHERE is_in_kev = true
		  AND (cve_id IS NULL OR cve_id NOT IN (SELECT cve_id FROM kev_catalog))
		RETURNING tenant_id
	`
	unflagged, err := e.runReturningTenants(ctx, unflagQuery, tenantSet)
	if err != nil {
		return result, fmt.Errorf("failed to clear is_in_kev: %w", err)
	}
	result.Unflagged = unflagged

	result.Tenants = make([]shared.ID, 0, len(tenantSet))
	for t := range tenantSet {
		result.Tenants = append(result.Tenants, t)
	}
	return result, nil
}

// runReturningTenants executes an UPDATE ... RETURNING tenant_id, adds each
// distinct tenant to the set, and returns the number of rows affected.
func (e *KEVEscalator) runReturningTenants(ctx context.Context, query string, tenantSet map[shared.ID]struct{}) (int, error) {
	rows, err := e.db.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	count := 0
	for rows.Next() {
		var tenantID shared.ID
		if err := rows.Scan(&tenantID); err != nil {
			return count, fmt.Errorf("scan tenant_id: %w", err)
		}
		tenantSet[tenantID] = struct{}{}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("iterate rows: %w", err)
	}
	return count, nil
}
