package postgres

import (
	"context"
	"fmt"
)

// KEVEscalator auto-escalates findings whose CVEs are in the CISA KEV catalog.
type KEVEscalator struct {
	db *DB
}

// NewKEVEscalator creates a new KEVEscalator.
func NewKEVEscalator(db *DB) *KEVEscalator {
	return &KEVEscalator{db: db}
}

// EscalateKEVFindings updates open findings with CVEs in KEV to critical severity.
// Runs across ALL tenants — this is intentional: KEV is a global catalog from CISA,
// and any finding with a KEV CVE should be escalated regardless of tenant.
// Only escalates findings that are not already critical and not in a terminal status.
// Returns the number of escalated findings.
func (e *KEVEscalator) EscalateKEVFindings(ctx context.Context) (int, error) {
	query := `
		UPDATE findings
		SET severity = 'critical', updated_at = NOW()
		WHERE cve_id IN (SELECT cve_id FROM kev_catalog)
		  AND severity != 'critical'
		  AND status NOT IN ('resolved', 'closed', 'false_positive')
		  AND cve_id IS NOT NULL
		  AND cve_id != ''
	`

	result, err := e.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to escalate KEV findings: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}
