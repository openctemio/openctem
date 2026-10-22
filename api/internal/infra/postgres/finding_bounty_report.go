package postgres

// Bug-bounty report identity on findings (RFC-121).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"context"
	"errors"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// bountyReportIndex keeps (tenant, intake, ref) unique among bug_bounty
// findings (migration findings_bounty_report_ref_unique).
const bountyReportIndex = "idx_findings_bounty_report_ref"

// isBountyReportViolation reports whether err is a write refused because
// another finding of the tenant already holds the same report.
func isBountyReportViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == bountyReportIndex
}

// FindByBountyReport returns the tenant's bug_bounty finding that holds the
// report (intake, ref), or a not-found error. The predicate matches the
// partial unique index.
func (r *FindingRepository) FindByBountyReport(ctx context.Context, tenantID shared.ID, intake, ref string) (*vulnerability.Finding, error) {
	query := r.selectQuery() + ` WHERE tenant_id = $1 AND source = 'bug_bounty'
		AND (metadata->'bounty_report'->>'intake') = $2 AND (metadata->'bounty_report'->>'ref') = $3`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), intake, ref)
	return r.scanFinding(row, shared.NewDomainError("NOT_FOUND", "bounty report not found", shared.ErrNotFound))
}
