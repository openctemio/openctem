package crypto

import (
	"testing"
	"time"
)

// pgStore models what PostgreSQL does to a timestamptz on the way in: it reduces
// to microsecond resolution by ROUNDING (verified on the live DB —
// '...00.123456789+00'::timestamptz reads back as .123457, not .123456).
func pgStore(ts time.Time) time.Time { return ts.UTC().Round(time.Microsecond) }

// The chain is hashed at write time from an in-memory timestamp and re-hashed at
// verify time from the value read back out of Postgres. If those two reductions
// disagree, the entry reports as tampered even though nothing was touched.
//
// This is the regression test for a live bug: the hash used Truncate while
// Postgres rounds, so every timestamp with a nanosecond remainder >= 500ns —
// about half of them — self-corrupted. Recomputing the real chain showed 50 of
// 93 recent entries breaking, all off by exactly one microsecond.
func TestComputeAuditChainHash_SurvivesPostgresRoundTrip(t *testing.T) {
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		ns   int
	}{
		{"no sub-microsecond remainder", 0},
		{"remainder just below the rounding point", 499},
		{"remainder exactly at the rounding point", 500}, // this is the one that broke
		{"remainder just above", 501},
		{"remainder near the next microsecond", 999},
		{"realistic wall-clock value", 123456789},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			atWrite := base.Add(time.Duration(tc.ns))
			atVerify := pgStore(atWrite) // what a later read actually sees

			want := ComputeAuditChainHash("prev", "log-id", "payload", atWrite)
			got := ComputeAuditChainHash("prev", "log-id", "payload", atVerify)

			if got != want {
				t.Fatalf("hash changed across the Postgres round-trip (ns=%d):\n  write:  %s\n  verify: %s\nan untouched entry would be reported as tampered",
					tc.ns, want, got)
			}
		})
	}
}

// Sanity: the hash must still actually depend on the timestamp, i.e. the fix
// must not have flattened it into "ignore time" (which would let a chain row be
// reordered undetected).
func TestComputeAuditChainHash_StillBindsTheTimestamp(t *testing.T) {
	t1 := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Second)

	if ComputeAuditChainHash("p", "id", "pay", t1) == ComputeAuditChainHash("p", "id", "pay", t2) {
		t.Fatal("hash ignores the timestamp — reordering chain rows would be undetectable")
	}
	// A difference below storage resolution must NOT change the hash, though:
	// it cannot survive the round-trip and would be a false tamper signal.
	if ComputeAuditChainHash("p", "id", "pay", t1) != ComputeAuditChainHash("p", "id", "pay", t1.Add(100*time.Nanosecond)) {
		t.Fatal("sub-microsecond difference changed the hash; it cannot survive storage")
	}
}
