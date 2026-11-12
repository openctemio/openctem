package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestRowsPerStatement_NeverExceedsTheBindLimit(t *testing.T) {
	cases := []struct{ perRow, fixed, limit, want int }{
		{75, 0, 1000, 873}, // the enrich UPDATE: a 1000-row constant is lowered
		{37, 0, 0, 1771},   // the asset upsert
		{9, 0, 5000, 5000}, // a limit that fits is kept
		{1, 1, 0, 65534},   // IN list next to one shared parameter
		{70000, 0, 0, 1},   // never zero rows
	}
	for _, c := range cases {
		got := rowsPerStatement(c.perRow, c.fixed, c.limit)
		if got != c.want {
			t.Errorf("rowsPerStatement(%d,%d,%d) = %d, want %d", c.perRow, c.fixed, c.limit, got, c.want)
		}
		if c.perRow < maxBindParams && got*c.perRow+c.fixed > maxBindParams {
			t.Errorf("rowsPerStatement(%d,%d,%d) = %d binds %d parameters", c.perRow, c.fixed, c.limit, got, got*c.perRow+c.fixed)
		}
	}
}

func TestForEachStatementChunk_CoversEveryRowAndStopsOnError(t *testing.T) {
	var seen int
	if err := forEachStatementChunk(2000, 75, 0, 0, func(s, e int) error {
		if s != seen || e-s > 873 {
			t.Fatalf("chunk [%d,%d) after %d", s, e, seen)
		}
		seen = e
		return nil
	}); err != nil || seen != 2000 {
		t.Fatalf("seen %d rows (%v)", seen, err)
	}

	boom := errors.New("boom")
	calls := 0
	err := forEachStatementChunk(2000, 75, 0, 0, func(int, int) error { calls++; return boom })
	if !errors.Is(err, boom) || calls != 1 || !strings.Contains(err.Error(), "rows 0-873 of 2000") {
		t.Fatalf("err = %v after %d calls", err, calls)
	}
}
