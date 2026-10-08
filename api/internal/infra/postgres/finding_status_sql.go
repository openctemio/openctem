package postgres

import (
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The from-state lists of every SQL statement that moves findings.status in
// bulk. Each is built from the domain lifecycle (pkg/domain/vulnerability
// status_lifecycle.go) and checked against it when the package loads, so a
// statement can never move a finding along an edge the lifecycle does not
// have: a list that drifts makes the binary and every test of this package
// panic at start.
//
// The values are FindingStatus constants, never input, so they are safe to
// splice into a statement.
var (
	// Open work an automated close acts on, per target.
	autoResolveFromSQL      = platformFromSQL(vulnerability.FindingStatusResolved, vulnerability.AutoCloseFromStatuses()...)
	vexFalsePositiveFromSQL = platformFromSQL(vulnerability.FindingStatusFalsePositive, vulnerability.AutoCloseFromStatuses()...)
	staleFromSQL            = platformFromSQL(vulnerability.FindingStatusNotObserved, vulnerability.AutoCloseFromStatuses()...)

	// A retired CI source also closes the findings it had already marked stale.
	sourceRetiredFromSQL = platformFromSQL(vulnerability.FindingStatusResolved,
		append(vulnerability.AutoCloseFromStatuses(), vulnerability.FindingStatusNotObserved)...)

	// A feature branch that expires marks its untriaged findings stale; a
	// branch-only finding also when it was confirmed.
	branchExpiryFromSQL     = platformFromSQL(vulnerability.FindingStatusNotObserved, vulnerability.FindingStatusNew)
	branchOnlyExpiryFromSQL = platformFromSQL(vulnerability.FindingStatusNotObserved,
		vulnerability.FindingStatusNew, vulnerability.FindingStatusConfirmed)

	// A scan that reports a finding again.
	regressionReopenFromSQL = platformFromSQL(vulnerability.FindingStatusConfirmed, vulnerability.RegressionReopenFromStatuses()...)
	// AutoReopenByFingerprint reopens only findings closed as fixed.
	fixedReopenFromSQL = platformFromSQL(vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusResolved)

	// A suppression rule lifted (the finding returns to new) or re-linked to
	// another rule (the finding takes that rule's disposition).
	suppressionLiftFromSQL   = platformFromSQL(vulnerability.FindingStatusNew, vulnerability.SuppressedStatuses()...)
	suppressionRelinkFromSQL = platformFromSQLEach(vulnerability.SuppressedStatuses(), vulnerability.SuppressedStatuses()...)
)

// platformFromSQL renders from as a SQL list, ('a', 'b'), after checking that
// the platform may move each of them to target. It panics otherwise: the lists
// are package variables, so a wrong one stops the program at start.
func platformFromSQL(target vulnerability.FindingStatus, from ...vulnerability.FindingStatus) string {
	if err := vulnerability.CheckPlatformTransitions(target, from...); err != nil {
		panic(err)
	}
	return sqlStatusList(from)
}

// platformFromSQLEach is platformFromSQL for a statement whose target is one
// of targets (chosen per row).
func platformFromSQLEach(targets []vulnerability.FindingStatus, from ...vulnerability.FindingStatus) string {
	for _, t := range targets {
		platformFromSQL(t, from...)
	}
	return sqlStatusList(from)
}

// sqlStatusList renders statuses as a SQL list: ('a', 'b').
func sqlStatusList(statuses []vulnerability.FindingStatus) string {
	quoted := make([]string, len(statuses))
	for i, s := range statuses {
		quoted[i] = "'" + strings.ReplaceAll(string(s), "'", "''") + "'"
	}
	return "(" + strings.Join(quoted, ", ") + ")"
}

// statusStrings is statuses as strings, for a pq.Array parameter.
func statusStrings(statuses []vulnerability.FindingStatus) []string {
	out := make([]string, len(statuses))
	for i, s := range statuses {
		out[i] = string(s)
	}
	return out
}
