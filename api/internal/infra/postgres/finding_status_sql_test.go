package postgres

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The SQL from-state lists are the domain's lists, rendered.
func TestFindingStatusSQL_ListsComeFromTheLifecycle(t *testing.T) {
	cases := map[string]struct {
		got  string
		want []vulnerability.FindingStatus
	}{
		"autoResolve":   {autoResolveFromSQL, vulnerability.AutoCloseFromStatuses()},
		"vex":           {vexFalsePositiveFromSQL, vulnerability.AutoCloseFromStatuses()},
		"stale":         {staleFromSQL, vulnerability.AutoCloseFromStatuses()},
		"sourceRetired": {sourceRetiredFromSQL, append(vulnerability.AutoCloseFromStatuses(), vulnerability.FindingStatusNotObserved)},
		"regression":    {regressionReopenFromSQL, vulnerability.RegressionReopenFromStatuses()},
		"suppression":   {suppressionLiftFromSQL, vulnerability.SuppressedStatuses()},
		"relink":        {suppressionRelinkFromSQL, vulnerability.SuppressedStatuses()},
	}
	for name, c := range cases {
		if c.got != sqlStatusList(c.want) {
			t.Errorf("%s = %s, want %s", name, c.got, sqlStatusList(c.want))
		}
		if strings.Contains(c.got, "'open'") {
			t.Errorf("%s lists open, which is not a finding status", name)
		}
	}
	if got := sqlStatusList([]vulnerability.FindingStatus{"new", "fix_applied"}); got != "('new', 'fix_applied')" {
		t.Errorf("sqlStatusList = %s", got)
	}
}

// A from-state list with a move the lifecycle does not have stops the program.
func TestFindingStatusSQL_IllegalListPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("platformFromSQL accepted false_positive -> resolved")
		}
	}()
	platformFromSQL(vulnerability.FindingStatusResolved, vulnerability.FindingStatusNew, vulnerability.FindingStatusFalsePositive)
}

// findingStatusWriters counts, per file, the SQL statements that set
// findings.status. Each takes its from-states from finding_status_sql.go (or
// a lifecycle check in Go), except the identity merge in
// asset_merge_findings.go, which is not a lifecycle move. A new statement
// that writes findings.status fails this test: give it a lifecycle guard and
// add it here.
var findingStatusWriters = map[string]int{
	"asset_merge_findings.go":              2, // identity merge: survivor inherits, tombstone -> duplicate
	"ci_coverage_repository.go":            2, // staleFromSQL, sourceRetiredFromSQL
	"finding_branch_only.go":               1, // branchOnlyExpiryFromSQL
	"finding_coverage_autoresolve.go":      2, // autoResolveFromSQL
	"finding_group_repository.go":          1, // UserFromStatuses($6)
	"finding_interop.go":                   1, // vexFalsePositiveFromSQL
	"finding_repo_coverage_autoresolve.go": 1, // autoResolveFromSQL
	"finding_repository.go":                9, // entity Update; UpdateStatusBatch ($6); auto-resolve x4; reopen x2; branch expiry
	"finding_retest_repository.go":         2, // moveFindingInTx checks the lifecycle
	"finding_template_provenance.go":       1, // staleFromSQL
	"finding_vex_document.go":              1, // vexFalsePositiveFromSQL
	"softwarematch_repository.go":          1, // regressionReopenFromSQL (reopen); the matcher close builds its SET from autoResolveFromSQL, staleFromSQL, vexFalsePositiveFromSQL
	"suppression_repository.go":            2, // suppressionRelinkFromSQL, suppressionLiftFromSQL
	"license_policy_repository.go":         2, // autoResolveFromSQL (policy no longer flags), fixedReopenFromSQL (flags again)
	"vex_statement_repository.go":          1, // per-row move decided by vex.Decide (lifecycle edges, TestDecideFollowsLifecycle), guarded by the old status
}

var (
	updateFindingsRe = regexp.MustCompile(`(?is)UPDATE\s+findings\b[^` + "`" + `]*`)
	setStatusRe      = regexp.MustCompile(`(?is)\bSET\b(.*?)(\bWHERE\b|\bFROM\b|$)`)
	statusAssignRe   = regexp.MustCompile(`(?i)(^|[\s,(])status\s*=`)
	openStatusRe     = regexp.MustCompile(`(?i)\b(f\.)?status\s+(NOT\s+)?IN\s*\([^)]*'open'`)
)

func TestFindingStatusSQL_EveryStatusWriteIsKnown(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range updateFindingsRe.FindAllString(string(src), -1) {
			m := setStatusRe.FindStringSubmatch(stmt)
			if m != nil && statusAssignRe.MatchString(m[1]) {
				got[f]++
			}
		}
		if loc := openStatusRe.FindIndex(src); loc != nil {
			t.Errorf("%s filters findings on status 'open', which is not a status: %q", f, src[loc[0]:loc[1]])
		}
	}
	names := map[string]bool{}
	for f := range got {
		names[f] = true
	}
	for f := range findingStatusWriters {
		names[f] = true
	}
	sorted := make([]string, 0, len(names))
	for f := range names {
		sorted = append(sorted, f)
	}
	sort.Strings(sorted)
	for _, f := range sorted {
		if got[f] != findingStatusWriters[f] {
			t.Errorf("%s: %d statements write findings.status, %d known; check the new one follows the lifecycle and update findingStatusWriters",
				f, got[f], findingStatusWriters[f])
		}
	}
}
