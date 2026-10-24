package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/lib/pq"
)

// The insert of new findings sorts in Go and every other writer sorts in SQL
// (findingLockOrderSQL): both must give one order, or the writers deadlock
// again. Fingerprints of every shape (hex, upper case, punctuation, a
// version prefix, non-ASCII) sort the same both ways.
func TestFindingLockOrder_GoAndSQLAgree(t *testing.T) {
	db := openSLADB(t)
	fps := []string{
		"b1d3", "B1d3", "a_b", "a-b", "a.b", "v2:ff00", "v2:00ff", "ab", "a", "Z", "z", "é1", "e1",
		"0f", "f0", "v10:aa", "v9:aa", "a b", "aB", "Ab",
	}
	rows, err := db.QueryContext(context.Background(),
		`SELECT fingerprint FROM unnest($1::text[]) AS t(fingerprint) ORDER BY `+findingLockOrderSQL, pq.Array(fps))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var fromSQL []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			t.Fatal(err)
		}
		fromSQL = append(fromSQL, fp)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	fromGo := slices.Clone(fps)
	sortByFingerprint(fromGo, func(s string) string { return s })
	if !slices.Equal(fromGo, fromSQL) {
		t.Fatalf("lock orders differ:\nGo  %q\nSQL %q", fromGo, fromSQL)
	}
}
