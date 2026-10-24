package postgres

// One lock order for findings rows (docs/architecture/deduplication.md,
// "Concurrent uploads").
//
// A statement that writes many findings rows takes their row locks one by
// one and holds them until it ends. Two such statements that meet the same
// rows in different orders can each hold a row the other waits for, and
// Postgres aborts one of them (40P01). Every batched writer of findings
// therefore locks its rows in one global order: fingerprint, compared byte
// by byte (Go's string <, SQL COLLATE "C"; the two agree).
//
// Fingerprint, not id, because the upsert of new findings
// (CreateBatchWithResult) can only order by what it has before the rows
// exist: its ON CONFLICT DO UPDATE branch locks the rows another upload
// inserted first in the order of its VALUES list, which it sorts by
// fingerprint. A writer that locked the same rows by id (enrichment, the
// sighting update, the priority stamp) deadlocked with it.
//
// A writer that is not a single INSERT sorted in Go takes its locks in a
// CTE first (findingLockCTE): SELECT ... ORDER BY fingerprint COLLATE "C"
// FOR NO KEY UPDATE locks in the sorted order, and the UPDATE then touches
// only rows it already holds. Each such statement runs under
// retryWriteConflict, so a conflict with a writer outside this rule (a
// trigger, another table) runs it again instead of dropping the write.

import "sort"

// findingLockOrderSQL is the ORDER BY of findings rows in the global lock
// order. The column is qualified by the caller's alias when needed.
const findingLockOrderSQL = `fingerprint COLLATE "C"`

// findingLockCTE is a CTE named locked that locks, in the global order, the
// findings rows (alias f) that from and where select, and returns their id as
// locked_id. from is the FROM list, whose findings table must be aliased f;
// where must scope by tenant.
func findingLockCTE(from, where string) string {
	return `locked AS (
			SELECT f.id AS locked_id FROM ` + from + `
			WHERE ` + where + `
			ORDER BY f.` + findingLockOrderSQL + `
			FOR NO KEY UPDATE OF f
		)`
}

// sortByFingerprint sorts items in the global lock order (stable, so equal
// fingerprints keep their input order).
func sortByFingerprint[T any](items []T, fingerprint func(T) string) {
	sort.SliceStable(items, func(a, b int) bool { return fingerprint(items[a]) < fingerprint(items[b]) })
}
