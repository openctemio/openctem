package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ComputeAuditChainHash returns the SHA-256 hex digest that pins a
// single audit_log row into the tamper-evident chain for its tenant.
//
// The hash covers four pieces of data in a fixed order:
//
//	prevHash | auditLogID | payload | timestamp (RFC3339Nano, UTC)
//
// Why each part matters:
//
//   - prevHash links this entry to the previous one; any mutation of an
//     earlier row invalidates every subsequent hash.
//   - auditLogID ties the chain row to a specific audit_logs PK, so
//     reinserting an audit log with a new id cannot slot in silently.
//   - payload should be a deterministic serialisation of the audit_log
//     row contents (actor, action, resource, changes, etc.). Callers
//     normally pass a canonical JSON of the log or a concatenation of
//     the scalar columns.
//   - timestamp binds the hash to real time so reordering chain rows
//     is detectable. It is truncated to microseconds before hashing
//     because PostgreSQL timestamptz only stores microsecond resolution:
//     hashing the in-memory nanosecond time at write but the
//     microsecond-truncated value read back at verify would make EVERY
//     row mismatch on the round-trip.
//
// An empty prevHash is valid — it marks the first entry per tenant.
// The returned string is lower-case hex, 64 characters. The function is
// pure (no I/O, no time.Now) so it is trivially unit-testable.
func ComputeAuditChainHash(prevHash, auditLogID, payload string, ts time.Time) string {
	h := sha256.New()
	// Length-prefix each field so concatenation collisions are impossible.
	// Example attack we block: payload="foo|2026-01-01" vs payload="foo"
	// with timestamp split differently.
	writeField(h, prevHash)
	writeField(h, auditLogID)
	writeField(h, payload)
	// Reduce to microseconds the way PostgreSQL does — it ROUNDS timestamptz to
	// microsecond resolution, it does not truncate. Truncating here meant that any
	// timestamp whose nanosecond remainder was >= 500ns hashed one value at write
	// time and a different one (stored_ts, rounded up) at verify time, so the entry
	// reported as tampered. That silently broke ~54% of new chain entries and
	// buried real tamper signals in the noise.
	writeField(h, ts.UTC().Round(time.Microsecond).Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

// writeField writes a length-prefixed string so concatenation of fields
// cannot overlap. Format: "<n>:<bytes>|" where n is decimal byte count.
func writeField(h interface {
	Write(p []byte) (int, error)
}, s string) {
	_, _ = fmt.Fprintf(h, "%d:", len(s))
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{'|'})
}
