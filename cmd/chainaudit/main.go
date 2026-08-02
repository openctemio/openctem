// Command chainaudit recomputes every audit_log_chain row against live data and
// classifies why it does or does not verify.
//
// It exists because "the chain reports 80 breaks" is not actionable on its own.
// Rebaselining a tamper-evident chain re-signs whatever is there, so it erases
// evidence as readily as it clears noise. Before doing that we have to show that
// every break is explained by a known defect and none is an unexplained
// mismatch.
//
// The known defect: ComputeAuditChainHash used to reduce the timestamp with
// Truncate(time.Microsecond) while PostgreSQL ROUNDS timestamptz to microseconds.
// Any timestamp whose nanosecond remainder was >= 500ns therefore hashed one
// value at write time and a different one at verify time. Fixed in api#361;
// this tool measures the wreckage that fix left behind.
//
// Classification per row:
//
//	verifies        - recomputes to the stored hash with the current (Round) code
//	legacy truncate - matches at stored_ts-1us => the #79..#361 truncate/round bug
//	pre-#79         - matches once the lost sub-microsecond remainder is brute
//	                  forced back => the original nanosecond-precision hash
//	UNEXPLAINED     - matches under none of the above. This is the one that matters:
//	                  a row here is either a defect nobody has characterized yet or
//	                  an actual tamper, and rebaselining would erase the difference.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"

	cryptopkg "github.com/openctemio/api/pkg/crypto"
)

// legacyMatch reports whether the stored hash is reproducible by the pre-#361
// code path.
//
// It cannot be reproduced by simply truncating the stored timestamp: PostgreSQL
// already rounded it to microsecond resolution on write, so the nanosecond
// remainder that caused the defect is gone from the database. Truncating a value
// that is already microsecond-exact is a no-op, and a check written that way
// silently reports "not explained" for every row — which is exactly the wrong
// answer to get when the next step is rebaselining a tamper-evident chain.
//
// What the defect actually did: the write hashed Truncate(t) while the database
// stored Round(t). When t rounded UP, the hashed value is one microsecond BELOW
// the stored timestamp. So the candidate to test is stored_ts - 1µs. stored_ts
// itself is covered by the caller's "verifies now" branch; both are tried here
// for completeness.
func legacyMatch(prevHash, auditLogID, payload, storedHash string, ts time.Time) bool {
	for _, cand := range []time.Time{
		ts.Add(-time.Microsecond),
		ts,
	} {
		if cryptopkg.ComputeAuditChainHash(prevHash, auditLogID, payload, cand) == storedHash {
			return true
		}
	}
	return false
}

// preHashReductionMatch reports whether the stored hash is reproducible by the
// ORIGINAL implementation, which predates any timestamp reduction at all.
//
// Before #79 the hash was taken over ts.UTC().Format(RFC3339Nano) with full
// nanosecond precision. PostgreSQL then stored the value rounded to microseconds,
// so the sub-microsecond remainder that went into the hash exists nowhere any
// more. Those rows are unverifiable by construction — but that is a claim worth
// proving rather than asserting, because "unverifiable" and "tampered" look
// identical from the outside.
//
// The proof: the lost remainder is bounded. A stored value rounded to the
// microsecond came from an original within [-500ns, +500ns) of it, so brute
// forcing that 1000-nanosecond window either recovers the exact original — which
// demonstrates the row is intact and merely un-reproducible from stored data — or
// finds nothing, which would be a genuine tamper signal.
//
// Returns the recovered offset in nanoseconds and whether a match was found.
func preHashReductionMatch(prevHash, auditLogID, payload, storedHash string, ts time.Time) (int, bool) {
	base := ts.UTC()
	for off := -500; off < 500; off++ {
		cand := base.Add(time.Duration(off) * time.Nanosecond)
		// Reproduce the pre-#79 hash: no Truncate, no Round, straight format.
		if rawNanoHash(prevHash, auditLogID, payload, cand) == storedHash {
			return off, true
		}
	}
	return 0, false
}

// rawNanoHash reimplements the pre-#79 hash exactly: the same length-prefixed
// field framing the production function still uses, but the timestamp formatted
// at full nanosecond precision with no reduction step.
//
// It is duplicated here rather than exposed from pkg/crypto on purpose — the
// production package should not carry a second, weaker hash for a diagnostic to
// call. If this drifts from history the tool reports fewer matches, which fails
// safe: it would block a rebaseline rather than wave one through.
func rawNanoHash(prevHash, auditLogID, payload string, ts time.Time) string {
	h := sha256.New()
	for _, f := range []string{prevHash, auditLogID, payload, ts.UTC().Format(time.RFC3339Nano)} {
		_, _ = fmt.Fprintf(h, "%d:", len(f))
		_, _ = h.Write([]byte(f))
		_, _ = h.Write([]byte{'|'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type row struct {
	auditLogID string
	position   int
	prevHash   string
	hash       string
	tenantID   string
	action     string
	resType    string
	resID      sql.NullString
	result     string
	loggedAt   time.Time
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL required")
		os.Exit(2)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// Order by tenant then position: the chain is per-tenant, and prev_hash only
	// means anything within one tenant's sequence.
	rows, err := db.Query(`
		SELECT c.audit_log_id, c.chain_position, c.prev_hash, c.hash,
		       l.tenant_id, l.action, l.resource_type, l.resource_id, l.result, l.logged_at
		FROM audit_log_chain c
		JOIN audit_logs l ON l.id = c.audit_log_id
		ORDER BY l.tenant_id, c.chain_position`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query:", err)
		os.Exit(1)
	}
	defer func() { _ = rows.Close() }()

	var (
		total, verifies, legacy, preReduction, unexplained int
		unexplainedRows                                    []row
		recovered                                          []string
		perTenant                                          = map[string][4]int{}
	)

	for rows.Next() {
		var r row
		if err := rows.Scan(&r.auditLogID, &r.position, &r.prevHash, &r.hash,
			&r.tenantID, &r.action, &r.resType, &r.resID, &r.result, &r.loggedAt); err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		total++

		payload := fmt.Sprintf("%s|%s|%s|%s", r.action, r.resType, r.resID.String, r.result)
		now := cryptopkg.ComputeAuditChainHash(r.prevHash, r.auditLogID, payload, r.loggedAt)

		c := perTenant[r.tenantID]

		switch {
		case now == r.hash:
			verifies++
			c[0]++
		case legacyMatch(r.prevHash, r.auditLogID, payload, r.hash, r.loggedAt):
			legacy++
			c[1]++
		default:
			if off, ok := preHashReductionMatch(r.prevHash, r.auditLogID, payload, r.hash, r.loggedAt); ok {
				preReduction++
				c[2]++
				recovered = append(recovered, fmt.Sprintf("pos=%d offset=%+dns", r.position, off))
				perTenant[r.tenantID] = c
				continue
			}
			unexplained++
			c[3]++
			unexplainedRows = append(unexplainedRows, r)
		}
		perTenant[r.tenantID] = c
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "rows:", err)
		os.Exit(1)
	}

	fmt.Printf("chain rows            : %d\n", total)
	fmt.Printf("  verifies now        : %d\n", verifies)
	fmt.Printf("  legacy truncate bug : %d\n", legacy)
	fmt.Printf("  pre-#79 nanosecond  : %d  (exact original recovered by brute force)\n", preReduction)
	fmt.Printf("  UNEXPLAINED         : %d\n", unexplained)
	fmt.Println()
	fmt.Println("per tenant  (verifies / legacy / pre-79 / unexplained)")
	for t, c := range perTenant {
		fmt.Printf("  %s   %3d / %3d / %3d / %3d\n", t, c[0], c[1], c[2], c[3])
	}

	if unexplained > 0 {
		fmt.Println("\nUNEXPLAINED ROWS — these are NOT accounted for by the known defect:")
		for _, r := range unexplainedRows {
			fmt.Printf("  tenant=%s pos=%d audit_log=%s action=%s logged_at=%s\n",
				r.tenantID, r.position, r.auditLogID, r.action, r.loggedAt.Format(time.RFC3339Nano))
		}
		fmt.Println("\nDo NOT rebaseline until each of these is explained.")
		os.Exit(1)
	}
	fmt.Printf("\nrecovered nanosecond offsets: %v\n", recovered)
	fmt.Println("Every break is explained. None is an unexplained mismatch.")
}
