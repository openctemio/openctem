package postgres

import (
	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// The verification columns of the findings table (migration
// finding_verification_state, docs/architecture/held-findings.md): whether a
// match was checked, and why a held one is held.
const findingVerificationColumnsSQL = `verification_state, hold_reasons`

// findingVerificationColumnCount is the number of columns in
// findingVerificationColumnsSQL.
const findingVerificationColumnCount = 2

func findingVerificationArgs(f *vulnerability.Finding) []any {
	reasons := f.HoldReasons()
	if reasons == nil {
		reasons = []string{}
	}
	return []any{f.VerificationState().String(), pq.Array(reasons)}
}

// findingVerificationConflictSQL is the ON CONFLICT ... DO UPDATE part. A
// sighting changes the state only of a held finding: a clean sighting
// releases it (the incoming state, unchecked), a held one keeps it held with
// the incoming reasons. A finding that was not held keeps its state: a held
// sighting never downgrades an unchecked, verified or not reproduced
// finding (its earlier evidence stands; the hold reasons of the sighting are
// in its sighting record).
func findingVerificationConflictSQL() string {
	return `,
			verification_state = CASE WHEN findings.verification_state = 'held'
				THEN EXCLUDED.verification_state ELSE findings.verification_state END,
			hold_reasons = CASE WHEN findings.verification_state = 'held'
				THEN EXCLUDED.hold_reasons ELSE findings.hold_reasons END`
}

// findingVerificationPlaceholders is ", $first, …" for the verification
// columns of a hand-numbered single-row INSERT.
func findingVerificationPlaceholders(first int) string {
	out := ""
	for i := 0; i < findingVerificationColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}
