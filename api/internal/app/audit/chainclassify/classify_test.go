package chainclassify

import (
	"strings"
	"testing"
	"time"

	cryptopkg "github.com/openctemio/openctem/api/pkg/crypto"
)

// storedTS is a microsecond-exact timestamp, as PostgreSQL stores timestamptz.
var storedTS = time.Date(2026, 6, 1, 10, 0, 0, 123456000, time.UTC)

func baseRow(id, prev string) Row {
	return Row{
		AuditLogID: id, PrevHash: prev,
		Action: "settings.updated", ResourceType: "settings", ResourceID: "r-" + id, Result: "success",
		LoggedAt: storedTS,
	}
}

func payloadOf(r Row) string { return Payload(r.Action, r.ResourceType, r.ResourceID, r.Result) }

// signNow signs the row the way the current code does.
func signNow(r Row) Row {
	r.Hash = cryptopkg.ComputeAuditChainHash(r.PrevHash, r.AuditLogID, payloadOf(r), r.LoggedAt)
	return r
}

// signLegacy reproduces the #79..#361 defect: the write hashed Truncate(t)
// while the database stored Round(t), one microsecond above it.
func signLegacy(r Row) Row {
	r.Hash = cryptopkg.ComputeAuditChainHash(r.PrevHash, r.AuditLogID, payloadOf(r), r.LoggedAt.Add(-time.Microsecond))
	return r
}

// signPre79 reproduces the original nanosecond hash of a timestamp that the
// database then rounded to storedTS.
func signPre79(r Row, offsetNS int) Row {
	r.Hash = rawNanoHash(r.PrevHash, r.AuditLogID, payloadOf(r), r.LoggedAt.Add(time.Duration(offsetNS)))
	return r
}

func TestClassify(t *testing.T) {
	r := baseRow("a", "")
	cases := []struct {
		name   string
		row    Row
		want   Class
		offset int
	}{
		{"verifies", signNow(r), Verifies, 0},
		{"legacy truncate", signLegacy(r), LegacyTruncate, 0},
		{"pre-79 nanosecond, negative remainder", signPre79(r, -317), PreHashReduction, -317},
		{"pre-79 nanosecond, positive remainder", signPre79(r, 499), PreHashReduction, 499},
		{"unexplained: a hash no known defect produces", func() Row { x := r; x.Hash = strings.Repeat("ab", 32); return x }(), Unexplained, 0},
		{"unexplained: data edited after signing", func() Row { x := signNow(r); x.Result = "failure"; return x }(), Unexplained, 0},
		{"unexplained: timestamp moved by more than the rounding window", func() Row {
			x := signNow(r)
			x.LoggedAt = x.LoggedAt.Add(2 * time.Microsecond)
			return x
		}(), Unexplained, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.row)
			if got.Class != tc.want || got.OffsetNS != tc.offset {
				t.Fatalf("Classify = %+v, want class %s offset %d", got, tc.want, tc.offset)
			}
		})
	}
}

func TestClassBlocking(t *testing.T) {
	for c, want := range map[Class]bool{
		Verifies: false, LegacyTruncate: false, PreHashReduction: false,
		Unexplained: true, SourceMissing: true, LinkBroken: true,
	} {
		if c.Blocking() != want {
			t.Errorf("%s.Blocking() = %v, want %v", c, !want, want)
		}
	}
}

// chain builds a linked chain: each row's prev_hash is the previous stored
// hash, as appendChainEntry writes it.
func chain(signers ...func(Row) Row) []Row {
	var out []Row
	prev := ""
	for i, sign := range signers {
		r := sign(baseRow(string(rune('a'+i)), prev))
		r.Position = int64(10 + i)
		out = append(out, r)
		prev = r.Hash
	}
	return out
}

func build(rows []Row) *Report {
	b := NewBuilder()
	for _, r := range rows {
		b.Add(r)
	}
	return b.Report()
}

func TestBuilder_ExplainedChainAllowsRebaseline(t *testing.T) {
	rows := chain(signNow, signLegacy, func(r Row) Row { return signPre79(r, 42) }, signNow)
	rep := build(rows)
	want := Counts{Verifies: 2, LegacyTruncate: 1, PreHashReduction: 1}
	if rep.Counts != want {
		t.Fatalf("counts = %+v, want %+v", rep.Counts, want)
	}
	if rep.Total != 4 || rep.Breaks != 2 || rep.Blocking != 0 || !rep.RebaselineAllowed() {
		t.Fatalf("report = %+v", rep)
	}
	if rep.LastPosition != 13 {
		t.Fatalf("last position = %d, want 13", rep.LastPosition)
	}
	if len(rep.Samples) != 2 || rep.Samples[1].Class != PreHashReduction || rep.Samples[1].OffsetNS != 42 {
		t.Fatalf("samples = %+v", rep.Samples)
	}
}

func TestBuilder_UnexplainedRowRefusesRebaseline(t *testing.T) {
	rows := chain(signNow, signLegacy, signNow)
	rows[2].Result = "failure" // edited after it was signed
	rep := build(rows)
	if rep.Counts.Unexplained != 1 || rep.Blocking != 1 || rep.RebaselineAllowed() {
		t.Fatalf("report = %+v", rep)
	}
	var found bool
	for _, s := range rep.Samples {
		if s.Class == Unexplained && s.Position == rows[2].Position && s.AuditLogID == rows[2].AuditLogID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unexplained row is not listed: %+v", rep.Samples)
	}
}

// A chain row deleted from the middle leaves every remaining row's own hash
// intact; only the link to the previous row shows it.
func TestBuilder_RemovedRowIsLinkBroken(t *testing.T) {
	rows := chain(signNow, signNow, signNow)
	rep := build([]Row{rows[0], rows[2]})
	if rep.Counts.LinkBroken != 1 || rep.Counts.Verifies != 1 || rep.RebaselineAllowed() {
		t.Fatalf("report = %+v", rep)
	}
	// The first row must link to "".
	rep = build(rows[1:])
	if rep.Counts.LinkBroken != 1 || rep.Samples[0].Position != rows[1].Position {
		t.Fatalf("a chain whose first row has a prev_hash must be flagged: %+v", rep)
	}
}

func TestBuilder_MissingSourceRefusesRebaseline(t *testing.T) {
	rows := chain(signNow, signNow)
	b := NewBuilder()
	b.Add(rows[0])
	b.AddMissing(rows[1].Position, rows[1].AuditLogID, rows[1].PrevHash, rows[1].Hash)
	rep := b.Report()
	if rep.Counts.SourceMissing != 1 || rep.RebaselineAllowed() {
		t.Fatalf("report = %+v", rep)
	}
}

func TestBuilder_Fingerprint(t *testing.T) {
	rows := chain(signNow, signLegacy, signNow)
	fp := build(rows).Fingerprint
	if len(fp) != 64 {
		t.Fatalf("fingerprint %q is not a sha256 hex", fp)
	}
	if again := build(rows).Fingerprint; again != fp {
		t.Fatal("the same chain must give the same fingerprint")
	}

	appended := chain(signNow, signLegacy, signNow, signNow)
	if build(appended).Fingerprint == fp {
		t.Fatal("an appended row must change the fingerprint")
	}

	// Data edited after review: still explained-or-not, the fingerprint moves.
	edited := append([]Row{}, rows...)
	edited[0].ResourceID = "other"
	if build(edited).Fingerprint == fp {
		t.Fatal("an edited audit log must change the fingerprint")
	}

	// A different stored hash for the same data.
	resigned := append([]Row{}, rows...)
	resigned[1] = signNow(resigned[1])
	if build(resigned).Fingerprint == fp {
		t.Fatal("a re-signed row must change the fingerprint")
	}
}

func TestBuilder_SampleLimits(t *testing.T) {
	var signers []func(Row) Row
	for i := 0; i < maxExplainedSamples+3; i++ {
		signers = append(signers, signLegacy)
	}
	rep := build(chain(signers...))
	if rep.Counts.LegacyTruncate != maxExplainedSamples+3 || len(rep.Samples) != maxExplainedSamples {
		t.Fatalf("legacy=%d samples=%d", rep.Counts.LegacyTruncate, len(rep.Samples))
	}
}
