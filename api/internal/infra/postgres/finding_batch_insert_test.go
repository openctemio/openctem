package postgres

import (
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// The multi-row batch insert builds a flat argument slice and a generated
// VALUES placeholder list. If the column header SQL, the findingInsertArgs
// order, and findingInsertColumnCount ever drift apart, Postgres rejects the
// statement at runtime ("INSERT has more expressions than target columns").
// These no-DB tests pin all three together so the drift is caught at build
// time instead of in production ingest.

func newTestFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(),
		shared.NewID(),
		vulnerability.FindingSourceManual,
		"trivy",
		vulnerability.SeverityHigh,
		"test finding",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func TestFindingInsertArgs_MatchesColumnCount(t *testing.T) {
	args, err := findingInsertArgs(newTestFinding(t))
	if err != nil {
		t.Fatalf("findingInsertArgs: %v", err)
	}
	if len(args) != findingInsertColumnCount {
		t.Fatalf("arg count %d != findingInsertColumnCount %d", len(args), findingInsertColumnCount)
	}
}

func TestFindingInsertColumnsSQL_MatchesColumnCount(t *testing.T) {
	sql := findingInsertColumnsSQL()
	open := strings.Index(sql, "(")
	closeIdx := strings.LastIndex(sql, ")")
	if open < 0 || closeIdx < 0 || closeIdx < open {
		t.Fatalf("could not locate column list parens in: %q", sql)
	}
	cols := strings.Split(sql[open+1:closeIdx], ",")
	count := 0
	for _, c := range cols {
		if strings.TrimSpace(c) != "" {
			count++
		}
	}
	if count != findingInsertColumnCount {
		t.Fatalf("column header lists %d columns, findingInsertColumnCount is %d", count, findingInsertColumnCount)
	}
}

func TestFindingValuesPlaceholders(t *testing.T) {
	const rows = 3
	out := findingValuesPlaceholders(rows)

	// Contiguous numbering: the last placeholder must be rows*columns.
	last := "$" + strconv.Itoa(rows*findingInsertColumnCount)
	if !strings.HasSuffix(out, last+")") {
		t.Fatalf("expected placeholders to end with %s), got tail %q", last, out[len(out)-12:])
	}
	// One group per row.
	if got := strings.Count(out, "("); got != rows {
		t.Fatalf("expected %d value groups, got %d", rows, got)
	}
	// Total placeholders == rows*columns.
	if got := strings.Count(out, "$"); got != rows*findingInsertColumnCount {
		t.Fatalf("expected %d placeholders, got %d", rows*findingInsertColumnCount, got)
	}
}

// The single-row upsert query must use exactly findingInsertColumnCount
// placeholders so the per-row fallback path stays consistent with the header.
func TestUpsertQuery_PlaceholderCount(t *testing.T) {
	r := &FindingRepository{}
	q := r.upsertQuery()
	// Count distinct $N tokens up to the ON CONFLICT clause (EXCLUDED has none).
	valuesPart := q
	if idx := strings.Index(q, "ON CONFLICT"); idx >= 0 {
		valuesPart = q[:idx]
	}
	max := 0
	for i := 1; i <= findingInsertColumnCount+5; i++ {
		if strings.Contains(valuesPart, "$"+strconv.Itoa(i)) {
			max = i
		}
	}
	if max != findingInsertColumnCount {
		t.Fatalf("upsertQuery highest placeholder $%d, expected $%d", max, findingInsertColumnCount)
	}
}
