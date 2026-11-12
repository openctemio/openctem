package postgres

import (
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// The sighting times of a new finding: when it was first detected and last
// seen. A finding first stored from a scan file carries the file's own time
// (vulnerability.Finding.ObservedAt), not the import's. See
// docs/architecture/finding-import.md, "What a Nessus import closes".
const findingObservedColumnsSQL = `first_detected_at, last_seen_at`

// findingObservedColumnCount is the number of columns in findingObservedColumnsSQL.
const findingObservedColumnCount = 2

func findingObservedArgs(f *vulnerability.Finding) []any {
	now := time.Now().UTC()
	first, last := f.FirstDetectedAt(), f.LastSeenAt()
	if first.IsZero() {
		first = now
	}
	if last.IsZero() {
		last = now
	}
	return []any{first, last}
}

// findingObservedPlaceholders is ", $first, …" for the sighting time
// columns of a hand-numbered single-row INSERT. A conflict keeps the stored
// times (the re-sighting path moves last seen).
func findingObservedPlaceholders(first int) string {
	out := ""
	for i := 0; i < findingObservedColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}
