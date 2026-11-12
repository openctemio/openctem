package postgres

// EPSS score history (api/docs/architecture/vulnerability-page.md, "EPSS
// trend"). The sync records one point per CVE per feed day for the CVEs that
// findings carry; the scoped vulnerability reads return the points of CVEs
// the caller already sees. The history is never read by CVE id alone: a
// point exists only when some organization has a finding of the CVE, so an
// unscoped read would tell one organization what another one has.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// EPSSHistoryRetentionDays is how many feed days of EPSS points are kept.
const EPSSHistoryRetentionDays = vulnerability.EPSSTrendDays

// recordEPSSHistory writes today's points from the sync's temp_epss_scores
// for the CVEs some finding carries (idx_findings_cve_tenant answers each
// EXISTS), and deletes points older than the retention, counted from the
// feed's own date so a stale feed never empties the history. Running twice
// on one feed day rewrites the same points.
func recordEPSSHistory(ctx context.Context, tx *sql.Tx) error {
	// sqlgate:optional — temp_epss_scores is the sync's session TEMP table.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO epss_score_history (cve_id, score_date, epss_score, percentile)
		SELECT s.cve_id, s.score_date, s.epss_score, s.percentile
		FROM (
			SELECT DISTINCT ON (cve_id) cve_id, score_date, epss_score, percentile
			FROM temp_epss_scores
			WHERE score_date IS NOT NULL
			ORDER BY cve_id, score_date DESC
		) s
		WHERE EXISTS (SELECT 1 FROM findings f WHERE f.cve_id = s.cve_id)
		ON CONFLICT (cve_id, score_date) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			percentile = EXCLUDED.percentile
		WHERE (epss_score_history.epss_score, epss_score_history.percentile)
			IS DISTINCT FROM (EXCLUDED.epss_score, EXCLUDED.percentile)
	`); err != nil {
		return fmt.Errorf("failed to record EPSS history: %w", err)
	}
	// sqlgate:optional — same TEMP table.
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM epss_score_history
		WHERE score_date <= (SELECT MAX(score_date) FROM temp_epss_scores) - $1::int
	`, EPSSHistoryRetentionDays); err != nil {
		return fmt.Errorf("failed to trim EPSS history: %w", err)
	}
	return nil
}

// trendQuerier runs the trend statement inside or outside a transaction.
type trendQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// epssTrends returns the last EPSSTrendDays points of each CVE, oldest
// first. Callers pass only CVEs the caller has a finding of in scope.
func epssTrends(ctx context.Context, q trendQuerier, cves []string) (map[string][]vulnerability.EPSSPoint, error) {
	out := make(map[string][]vulnerability.EPSSPoint, len(cves))
	if len(cves) == 0 {
		return out, nil
	}
	rows, err := q.QueryContext(ctx, `
		SELECT cve_id, score_date, epss_score::float8
		FROM epss_score_history
		WHERE cve_id = ANY($1::text[])
		  AND score_date > (SELECT COALESCE(MAX(score_date), CURRENT_DATE) FROM epss_score_history) - $2::int
		ORDER BY cve_id, score_date`, pq.Array(cves), vulnerability.EPSSTrendDays)
	if err != nil {
		return nil, fmt.Errorf("epss trend: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cve string
		var day time.Time
		var score float64
		if err := rows.Scan(&cve, &day, &score); err != nil {
			return nil, fmt.Errorf("scan epss trend: %w", err)
		}
		out[cve] = append(out[cve], vulnerability.EPSSPoint{Date: day.Format(time.DateOnly), Score: score})
	}
	return out, rows.Err()
}

// EPSSTrend returns the EPSS points of one CVE. The service calls it only
// when the caller has a finding of the CVE in scope.
func (r *FindingRepository) EPSSTrend(ctx context.Context, cveID string) ([]vulnerability.EPSSPoint, error) {
	m, err := epssTrends(ctx, r.db, []string{cveID})
	if err != nil {
		return nil, err
	}
	return m[cveID], nil
}
