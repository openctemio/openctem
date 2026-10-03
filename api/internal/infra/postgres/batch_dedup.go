package postgres

// One INSERT ... ON CONFLICT DO UPDATE statement cannot update the same row
// twice: a batch that carries one conflict key twice fails as a whole with
// "ON CONFLICT DO UPDATE command cannot affect row a second time", and every
// row in it is lost. Every multi-row upsert built from a Go slice folds such
// duplicates before it builds the statement. RFC-043 P0
// (docs/rfcs/RFC-043-deduplication-and-identity.md).

// dedupeLastWins returns items with one entry per key. An entry keeps the
// position of the key's first occurrence and the value of its last one, which
// is what applying the items one by one as upserts would leave behind.
func dedupeLastWins[T any](items []T, key func(T) string) []T {
	if len(items) < 2 {
		return items
	}
	index := make(map[string]int, len(items))
	out := make([]T, 0, len(items))
	for _, it := range items {
		k := key(it)
		if i, ok := index[k]; ok {
			out[i] = it
			continue
		}
		index[k] = len(out)
		out = append(out, it)
	}
	return out
}
