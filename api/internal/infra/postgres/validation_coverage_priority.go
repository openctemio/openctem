package postgres

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/openctemio/openctem/api/internal/app/validation"
)

// Querier is the part of *sql.DB the coverage query needs.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ValidationCoverageByPriority counts, per priority class (P0..P3), the
// findings that reached a terminal state (resolved | verified | accepted |
// false_positive) and how many of them have a validation_evidence record
// (RFC-011: pentest, scripted and sensor evidence all land there).
//
// It is the one definition of "validation coverage": the CTEM cycle's
// close-time gate (window = the cycle's dates) and the tenant-wide
// Validation overview (no window, everything to date) both call it. An empty
// startDate / endDate leaves that side of the window open.
func ValidationCoverageByPriority(
	ctx context.Context, db Querier, tenantID, startDate, endDate string,
) (validation.ValidationCoverage, error) {
	var c validation.ValidationCoverage
	windowSQL := ""
	args := []any{tenantID}
	argN := 2
	if startDate != "" {
		windowSQL += " AND f.updated_at >= $" + strconv.Itoa(argN)
		args = append(args, startDate)
		argN++
	}
	if endDate != "" {
		windowSQL += " AND f.updated_at < ($" + strconv.Itoa(argN) + "::date + INTERVAL '1 day')"
		args = append(args, endDate)
	}
	q := `
		SELECT
		  COALESCE(f.priority_class, '') AS pc,
		  COUNT(*) AS total,
		  COUNT(*) FILTER (
		    WHERE EXISTS (
		      SELECT 1 FROM validation_evidence v
		       WHERE v.tenant_id = f.tenant_id AND v.finding_id = f.id
		    )
		  ) AS with_ev
		FROM findings f
		WHERE f.tenant_id = $1 AND NOT f.branch_only
		  AND f.status IN ('resolved','accepted','false_positive')` + windowSQL + `
		GROUP BY COALESCE(f.priority_class, '')
	`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return c, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var pc string
		var total, withEv int
		if err := rows.Scan(&pc, &total, &withEv); err != nil {
			return c, err
		}
		switch pc {
		case "P0":
			c.P0Total, c.P0WithEvidence = total, withEv
		case "P1":
			c.P1Total, c.P1WithEvidence = total, withEv
		case "P2":
			c.P2Total, c.P2WithEvidence = total, withEv
		case "P3":
			c.P3Total, c.P3WithEvidence = total, withEv
		}
	}
	return c, rows.Err()
}

// CoverageByPriority is ValidationCoverageByPriority for the whole tenant
// history (the Validation overview).
func (r *ValidationEvidenceRepository) CoverageByPriority(ctx context.Context, tenantID string) (validation.ValidationCoverage, error) {
	return ValidationCoverageByPriority(ctx, r.db, tenantID, "", "")
}
