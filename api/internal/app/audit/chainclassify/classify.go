// Package chainclassify explains why each audit_log_chain row does or does not
// verify. It is shared by cmd/chainaudit (the operator CLI) and the platform
// admin's "rebaseline audit chain" action, so the server refuses exactly what
// the CLI would flag.
//
// "The chain reports 80 breaks" is not actionable on its own. Rebaselining a
// tamper-evident chain re-signs whatever is there, so it erases evidence as
// readily as it clears noise. Before doing that every break has to be explained
// by a known defect, and none may be an unexplained mismatch.
//
// The known defect: ComputeAuditChainHash used to reduce the timestamp with
// Truncate(time.Microsecond) while PostgreSQL ROUNDS timestamptz to
// microseconds. Any timestamp whose nanosecond remainder was >= 500ns therefore
// hashed one value at write time and a different one at verify time. Fixed in
// api#361; this package measures the wreckage that fix left behind.
//
// Classification per row:
//
//	verifies          - recomputes to the stored hash with the current (Round) code
//	legacy truncate   - matches at stored_ts-1us => the #79..#361 truncate/round bug
//	pre-#79           - matches once the lost sub-microsecond remainder is brute
//	                    forced back => the original nanosecond-precision hash
//	UNEXPLAINED       - matches under none of the above. This is the one that
//	                    matters: a row here is either a defect nobody has
//	                    characterized yet or an actual tamper, and rebaselining
//	                    would erase the difference.
//
// The server walk (Builder) adds two more blocking classes the CLI's JOIN
// cannot produce: a chain row whose audit_logs row is gone, and a row whose
// prev_hash does not link to the previous row's stored hash.
package chainclassify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	cryptopkg "github.com/openctemio/openctem/api/pkg/crypto"
)

// Class is why a chain row does or does not verify.
type Class string

const (
	// Verifies: the stored hash recomputes with the current code.
	Verifies Class = "verifies"
	// LegacyTruncate: the #79..#361 truncate/round defect.
	LegacyTruncate Class = "legacy_truncate"
	// PreHashReduction: the pre-#79 nanosecond-precision hash, with the lost
	// sub-microsecond remainder recovered by brute force.
	PreHashReduction Class = "pre_79_nanosecond"
	// Unexplained: matches no known defect. Blocks a rebaseline.
	Unexplained Class = "unexplained"
	// SourceMissing: the audit_logs row behind the chain row is gone. Blocks a
	// rebaseline (server walk only).
	SourceMissing Class = "source_missing"
	// LinkBroken: the row's prev_hash is not the previous row's stored hash (a
	// chain row was removed or re-ordered). Blocks a rebaseline (server walk
	// only).
	LinkBroken Class = "link_broken"
)

// Blocking reports whether a row of this class must stop a rebaseline.
func (c Class) Blocking() bool {
	switch c {
	case Unexplained, SourceMissing, LinkBroken:
		return true
	}
	return false
}

// Row is one audit_log_chain row joined with the audit_logs fields the chain
// hash covers.
type Row struct {
	AuditLogID   string
	Position     int64
	PrevHash     string
	Hash         string
	Action       string
	ResourceType string
	ResourceID   string
	Result       string
	LoggedAt     time.Time
}

// Payload is the chain hash's payload field for an audit log; it must match
// what AuditService writes.
func Payload(action, resourceType, resourceID, result string) string {
	return fmt.Sprintf("%s|%s|%s|%s", action, resourceType, resourceID, result)
}

// Result is the classification of one row. OffsetNS is the recovered
// nanosecond offset for PreHashReduction rows.
type Result struct {
	Class    Class
	OffsetNS int
}

// Classify explains one row's stored hash against its own stored prev_hash.
// It never returns SourceMissing or LinkBroken; those need the walk.
func Classify(r Row) Result {
	payload := Payload(r.Action, r.ResourceType, r.ResourceID, r.Result)
	if cryptopkg.ComputeAuditChainHash(r.PrevHash, r.AuditLogID, payload, r.LoggedAt) == r.Hash {
		return Result{Class: Verifies}
	}
	if LegacyMatch(r.PrevHash, r.AuditLogID, payload, r.Hash, r.LoggedAt) {
		return Result{Class: LegacyTruncate}
	}
	if off, ok := PreHashReductionMatch(r.PrevHash, r.AuditLogID, payload, r.Hash, r.LoggedAt); ok {
		return Result{Class: PreHashReduction, OffsetNS: off}
	}
	return Result{Class: Unexplained}
}

// LegacyMatch reports whether the stored hash is reproducible by the pre-#361
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
func LegacyMatch(prevHash, auditLogID, payload, storedHash string, ts time.Time) bool {
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

// PreHashReductionMatch reports whether the stored hash is reproducible by the
// ORIGINAL implementation, which predates any timestamp reduction at all.
//
// Before #79 the hash was taken over ts.UTC().Format(RFC3339Nano) with full
// nanosecond precision. PostgreSQL then stored the value rounded to
// microseconds, so the sub-microsecond remainder that went into the hash exists
// nowhere any more. Those rows are unverifiable by construction — but that is a
// claim worth proving rather than asserting, because "unverifiable" and
// "tampered" look identical from the outside.
//
// The proof: the lost remainder is bounded. A stored value rounded to the
// microsecond came from an original within [-500ns, +500ns) of it, so brute
// forcing that 1000-nanosecond window either recovers the exact original —
// which demonstrates the row is intact and merely un-reproducible from stored
// data — or finds nothing, which would be a genuine tamper signal.
//
// Returns the recovered offset in nanoseconds and whether a match was found.
func PreHashReductionMatch(prevHash, auditLogID, payload, storedHash string, ts time.Time) (int, bool) {
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
// field framing the production function still uses, but the timestamp
// formatted at full nanosecond precision with no reduction step.
//
// It is kept here rather than exposed from pkg/crypto on purpose — the
// production package should not carry a second, weaker hash for a diagnostic
// to call. If this drifts from history the classifier reports fewer matches,
// which fails safe: it blocks a rebaseline rather than waving one through.
func rawNanoHash(prevHash, auditLogID, payload string, ts time.Time) string {
	h := sha256.New()
	for _, f := range []string{prevHash, auditLogID, payload, ts.UTC().Format(time.RFC3339Nano)} {
		_, _ = fmt.Fprintf(h, "%d:", len(f))
		_, _ = h.Write([]byte(f))
		_, _ = h.Write([]byte{'|'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Sample is one non-verifying row in a Report.
type Sample struct {
	Position   int64     `json:"position"`
	AuditLogID string    `json:"audit_log_id"`
	Action     string    `json:"action,omitempty"`
	LoggedAt   time.Time `json:"logged_at,omitzero"`
	Class      Class     `json:"class"`
	OffsetNS   int       `json:"offset_ns,omitempty"`
}

// Counts is the number of rows per class.
type Counts struct {
	Verifies         int `json:"verifies"`
	LegacyTruncate   int `json:"legacy_truncate"`
	PreHashReduction int `json:"pre_79_nanosecond"`
	Unexplained      int `json:"unexplained"`
	SourceMissing    int `json:"source_missing"`
	LinkBroken       int `json:"link_broken"`
}

func (c *Counts) add(class Class) {
	switch class {
	case Verifies:
		c.Verifies++
	case LegacyTruncate:
		c.LegacyTruncate++
	case PreHashReduction:
		c.PreHashReduction++
	case Unexplained:
		c.Unexplained++
	case SourceMissing:
		c.SourceMissing++
	case LinkBroken:
		c.LinkBroken++
	}
}

// Blocking is the number of rows that must stop a rebaseline.
func (c Counts) Blocking() int { return c.Unexplained + c.SourceMissing + c.LinkBroken }

// Breaks is the number of rows that do not verify as they stand.
func (c Counts) Breaks() int {
	return c.LegacyTruncate + c.PreHashReduction + c.Blocking()
}

// Report is the classification of one tenant's whole chain.
type Report struct {
	Total        int    `json:"total"`
	Counts       Counts `json:"counts"`
	Breaks       int    `json:"breaks"`
	Blocking     int    `json:"blocking"`
	LastPosition int64  `json:"last_position"`
	// Fingerprint identifies the exact chain that was classified (every row's
	// position, ids, hashes, hashed fields and class). A rebaseline is refused
	// when the chain it is about to re-sign has a different fingerprint from
	// the one the administrator reviewed.
	Fingerprint string   `json:"fingerprint"`
	Samples     []Sample `json:"samples"`
}

// RebaselineAllowed reports whether every break is explained.
func (r *Report) RebaselineAllowed() bool { return r.Blocking == 0 }

// Sample limits: every blocking row (up to maxBlockingSamples) is listed so an
// operator can investigate it; explained breaks are illustrated, not listed.
const (
	maxBlockingSamples  = 100
	maxExplainedSamples = 5
)

// Builder classifies a chain row by row, in chain_position order, and also
// checks that each row links to the previous one.
type Builder struct {
	report     Report
	fp         hash.Hash
	prevStored string
	sampled    map[Class]int
}

// NewBuilder starts the classification of one tenant's chain.
func NewBuilder() *Builder {
	return NewBuilderFrom("")
}

// NewBuilderFrom starts the classification of a chain whose oldest remaining
// row must link to prevHash: the retention anchor of a pruned chain ("" for a
// chain that was never pruned).
func NewBuilderFrom(prevHash string) *Builder {
	return &Builder{fp: sha256.New(), sampled: map[Class]int{}, report: Report{Samples: []Sample{}}, prevStored: prevHash}
}

// Add classifies the next row of the chain.
func (b *Builder) Add(r Row) Result {
	res := Classify(r)
	// A row whose own hash is explained but which does not link to the row
	// before it means a chain row was removed or re-ordered: the hash check
	// alone cannot see that, because it recomputes against the row's OWN
	// stored prev_hash. The first row links to "", or to the retention anchor.
	if !res.Class.Blocking() && r.PrevHash != b.prevStored {
		res = Result{Class: LinkBroken}
	}
	b.record(r.Position, r.AuditLogID, r.PrevHash, r.Hash, res, r.Action, r.ResourceType, r.ResourceID, r.Result, r.LoggedAt)
	return res
}

// AddMissing records a chain row whose audit_logs row could not be found.
func (b *Builder) AddMissing(position int64, auditLogID, prevHash, storedHash string) {
	b.record(position, auditLogID, prevHash, storedHash, Result{Class: SourceMissing}, "", "", "", "", time.Time{})
}

func (b *Builder) record(position int64, auditLogID, prevHash, storedHash string, res Result,
	action, resourceType, resourceID, result string, loggedAt time.Time,
) {
	b.report.Total++
	b.report.Counts.add(res.Class)
	b.report.LastPosition = position
	b.prevStored = storedHash

	ts := ""
	if !loggedAt.IsZero() {
		ts = loggedAt.UTC().Format(time.RFC3339Nano)
	}
	for _, f := range []string{
		fmt.Sprint(position), auditLogID, prevHash, storedHash, string(res.Class),
		Payload(action, resourceType, resourceID, result), ts,
	} {
		_, _ = fmt.Fprintf(b.fp, "%d:", len(f))
		_, _ = b.fp.Write([]byte(f))
		_, _ = b.fp.Write([]byte{'|'})
	}

	if res.Class == Verifies {
		return
	}
	limit := maxExplainedSamples
	if res.Class.Blocking() {
		limit = maxBlockingSamples
	}
	if b.sampled[res.Class] >= limit {
		return
	}
	b.sampled[res.Class]++
	b.report.Samples = append(b.report.Samples, Sample{
		Position: position, AuditLogID: auditLogID, Action: action,
		LoggedAt: loggedAt, Class: res.Class, OffsetNS: res.OffsetNS,
	})
}

// Report finishes the classification.
func (b *Builder) Report() *Report {
	r := b.report
	r.Breaks = r.Counts.Breaks()
	r.Blocking = r.Counts.Blocking()
	r.Fingerprint = hex.EncodeToString(b.fp.Sum(nil))
	r.Samples = append([]Sample{}, b.report.Samples...)
	return &r
}
