package postgres

import "github.com/openctemio/openctem/api/pkg/domain/vulnerability"

// The SLA reason column of the findings table: whether the stored deadline
// came from the SLA policy's known exploited (CISA KEV) deadline cap. See
// docs/architecture/scoring-versions.md, "Known exploited deadline cap".
const findingSLAKEVColumnsSQL = `sla_kev_capped`

// findingSLAKEVColumnCount is the number of columns in findingSLAKEVColumnsSQL.
const findingSLAKEVColumnCount = 1

func findingSLAKEVArgs(f *vulnerability.Finding) []any {
	return []any{f.SLAKEVCapped()}
}

// findingSLAKEVConflictSQL is the ON CONFLICT ... DO UPDATE part: the flag
// follows the deadline the upsert keeps (the same choice as sla_deadline in
// findingUpsertConflictSQL), so it is the incoming one only when the incoming
// deadline is the one stored.
func findingSLAKEVConflictSQL() string {
	return `,
			sla_kev_capped = CASE
				WHEN EXCLUDED.sla_deadline IS NULL THEN findings.sla_kev_capped
				WHEN findings.sla_deadline IS NULL THEN EXCLUDED.sla_kev_capped
				WHEN NOT is_open_finding_status(findings.status) THEN findings.sla_kev_capped
				WHEN EXCLUDED.sla_deadline < findings.sla_deadline THEN EXCLUDED.sla_kev_capped
				ELSE findings.sla_kev_capped END`
}

// findingSLAKEVPlaceholders is ", $first, …" for the SLA reason columns of a
// hand-numbered single-row INSERT.
func findingSLAKEVPlaceholders(first int) string {
	out := ""
	for i := 0; i < findingSLAKEVColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}
