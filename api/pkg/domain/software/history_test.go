package software

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// Edge cases of the version history state machine (research 376).

var t0 = time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)

type ver struct {
	id   shared.ID
	raw  string
	norm string
	segs int
}

func mkVer(raw string) ver {
	v := ver{id: shared.NewID(), raw: raw}
	if p, ok := vulnmatch.ParseVersion(raw); ok {
		v.norm, v.segs = p.Normalized(), p.Segments()
	}
	return v
}

func see(v ver, at time.Time, c EvidenceClass, conf int) Sighting {
	return Sighting{VersionID: v.id, Raw: v.raw, Normalized: v.norm, Segments: v.segs, At: at, Class: c, Confidence: conf}
}

// history applies batches in order and returns the rows.
func history(t *testing.T, batches ...[]Sighting) ([]HistoryRow, []bool) {
	t.Helper()
	var rows []HistoryRow
	changed := make([]bool, 0, len(batches))
	for _, b := range batches {
		res := ApplySightings(rows, b)
		rows = res.Rows
		for i := range rows {
			rows[i].New, rows[i].Seen, rows[i].Dirty = false, false, false
		}
		changed = append(changed, res.EstablishedChanged)
	}
	return rows, changed
}

func current(t *testing.T, rows []HistoryRow) HistoryRow {
	t.Helper()
	var cur []HistoryRow
	for _, r := range rows {
		if r.Current() {
			cur = append(cur, r)
		}
	}
	if len(cur) != 1 {
		t.Fatalf("want exactly one established row, got %d: %+v", len(cur), rows)
	}
	return cur[0]
}

func row(t *testing.T, rows []HistoryRow, v ver) HistoryRow {
	t.Helper()
	for _, r := range rows {
		if r.VersionID == v.id {
			return r
		}
	}
	t.Fatalf("no row for %s", v.raw)
	return HistoryRow{}
}

func one(s Sighting) []Sighting { return []Sighting{s} }

// The production case: 7.1.3 seen for four days by technology detection
// (banner class, 65), then 7.1.4 once. 7.1.3 stays established.
func TestSingleWeakSightingDoesNotDisplace(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, changed := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(a, t0.Add(24*time.Hour), ClassBanner, 65)),
		one(see(a, t0.Add(80*time.Hour), ClassBanner, 65)),
		one(see(b, t0.Add(104*time.Hour), ClassBanner, 65)),
	)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3", cur.Raw)
	}
	nb := row(t, rows, b)
	if nb.State != VersionCandidate || nb.Superseded || nb.Streak != 1 || nb.Sightings != 1 {
		t.Fatalf("7.1.4 = %+v, want a candidate with one sighting", nb)
	}
	if changed[3] {
		t.Fatal("a weak sighting must not change the established version")
	}
	if !changed[0] {
		t.Fatal("the first sighting establishes the version")
	}
	if r := row(t, rows, a); r.Sightings != 3 || !r.FirstSeen.Equal(t0) {
		t.Fatalf("7.1.3 history = %+v", r)
	}
}

// Hysteresis: three consecutive readings spanning at least 12 h promote.
func TestConsecutiveSightingsPromote(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, changed := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(1*time.Hour), ClassBanner, 65)),
		one(see(b, t0.Add(7*time.Hour), ClassBanner, 65)),
		one(see(b, t0.Add(14*time.Hour), ClassBanner, 65)),
	)
	if cur := current(t, rows); cur.VersionID != b.id {
		t.Fatalf("established = %s, want 7.1.4", cur.Raw)
	}
	if !changed[3] || changed[2] {
		t.Fatalf("promotion on the third reading only, got %v", changed)
	}
	old := row(t, rows, a)
	if !old.Superseded || !old.SupersededAt.Equal(t0.Add(14*time.Hour)) {
		t.Fatalf("7.1.3 = %+v, want superseded at the confirming reading's time", old)
	}
}

// Three readings in one burst do not count: the span is too short.
func TestBurstOfScansDoesNotPromote(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, _ := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(1*time.Hour), ClassBanner, 65)),
		one(see(b, t0.Add(1*time.Hour+time.Minute), ClassBanner, 65)),
		one(see(b, t0.Add(1*time.Hour+2*time.Minute), ClassBanner, 65)),
	)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3", cur.Raw)
	}
}

// Flapping (load balancer, stale cache, blue/green): the established
// version read again resets the candidate's streak.
func TestFlappingKeepsEstablished(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	var batches [][]Sighting
	batches = append(batches, one(see(a, t0, ClassBanner, 65)))
	for i := 1; i <= 10; i++ {
		v := b
		if i%2 == 0 {
			v = a
		}
		batches = append(batches, one(see(v, t0.Add(time.Duration(i)*12*time.Hour), ClassBanner, 65)))
	}
	rows, changed := history(t, batches...)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3", cur.Raw)
	}
	for i, c := range changed[1:] {
		if c {
			t.Fatalf("batch %d changed the established version while flapping", i+1)
		}
	}
	if nb := row(t, rows, b); nb.Sightings != 5 || nb.Superseded {
		t.Fatalf("7.1.4 = %+v, want 5 sightings, kept as a candidate", nb)
	}
}

// One strong reading (an active probe at 80+, or inventory) promotes.
func TestStrongSourcePromotesAtOnce(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, changed := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(time.Hour), ClassProbe, 80)),
	)
	if cur := current(t, rows); cur.VersionID != b.id || !changed[1] {
		t.Fatalf("established = %s, want 7.1.4 from the probe", cur.Raw)
	}
	// A probe below 80 is not strong.
	c := mkVer("7.1.5")
	rows, _ = history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(c, t0.Add(time.Hour), ClassProbe, 79)),
	)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3 (probe 79 is not strong)", cur.Raw)
	}
}

// A strong reading from a weaker class than the established one's does not
// override it on its own (inventory beats an outside probe).
func TestStrongLowerClassDoesNotOverrideInventory(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, _ := history(t,
		one(see(a, t0, ClassInventory, 95)),
		one(see(b, t0.Add(time.Hour), ClassProbe, 90)),
	)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3 from inventory", cur.Raw)
	}
}

// Sources disagree in one report: the stronger class is the reading.
func TestDisagreementStrongerClassWins(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, _ := history(t,
		one(see(a, t0, ClassBanner, 65)),
		[]Sighting{see(a, t0.Add(time.Hour), ClassHeuristic, 40), see(b, t0.Add(time.Hour), ClassProbe, 85)},
	)
	if cur := current(t, rows); cur.VersionID != b.id {
		t.Fatalf("established = %s, want 7.1.4 (probe beats heuristic)", cur.Raw)
	}
	// Both versions recorded in the history.
	if r := row(t, rows, a); r.LastSeen != t0.Add(time.Hour) || r.Sightings != 2 {
		t.Fatalf("7.1.3 history = %+v", r)
	}
}

// Versions one scan reports together are present together (a partly
// rolled-out deployment, two copies of a library): the new one joins the
// established set after the usual evidence, the old one is never displaced
// while it is still read.
func TestSeenTogetherJoinsWithoutDisplacing(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, changed := history(t,
		one(see(a, t0, ClassBanner, 65)),
		[]Sighting{see(a, t0.Add(12*time.Hour), ClassBanner, 65), see(b, t0.Add(12*time.Hour), ClassBanner, 65)},
		[]Sighting{see(a, t0.Add(24*time.Hour), ClassBanner, 65), see(b, t0.Add(24*time.Hour), ClassBanner, 65)},
	)
	if cur := current(t, rows); cur.VersionID != a.id || changed[2] {
		t.Fatalf("established = %s after two joint readings, want 7.1.3 alone", cur.Raw)
	}
	rows, changed = history(t,
		one(see(a, t0, ClassBanner, 65)),
		[]Sighting{see(a, t0.Add(12*time.Hour), ClassBanner, 65), see(b, t0.Add(12*time.Hour), ClassBanner, 65)},
		[]Sighting{see(a, t0.Add(24*time.Hour), ClassBanner, 65), see(b, t0.Add(24*time.Hour), ClassBanner, 65)},
		[]Sighting{see(a, t0.Add(36*time.Hour), ClassBanner, 65), see(b, t0.Add(36*time.Hour), ClassBanner, 65)},
	)
	if !changed[3] {
		t.Fatal("the third joint reading establishes 7.1.4 too")
	}
	for _, v := range []ver{a, b} {
		if r := row(t, rows, v); !r.Current() {
			t.Fatalf("%s = %+v, want established", v.raw, r)
		}
	}
}

// Two versions in the very first report are both established.
func TestFirstReportWithTwoVersions(t *testing.T) {
	a, b := mkVer("1.12.4"), mkVer("3.5.1")
	res := ApplySightings(nil, []Sighting{see(a, t0, ClassBanner, 65), see(b, t0, ClassBanner, 65)})
	if !res.EstablishedChanged {
		t.Fatal("first report establishes")
	}
	for _, r := range res.Rows {
		if !r.Current() {
			t.Fatalf("%s not established", r.Raw)
		}
	}
	// A later reading of one only: the other is not displaced (not seen is
	// not gone).
	res = ApplySightings(res.Rows, one(see(a, t0.Add(48*time.Hour), ClassProbe, 95)))
	for _, r := range res.Rows {
		if !r.Current() {
			t.Fatalf("%s displaced by a reading that only left it out", r.Raw)
		}
	}
}

// Rollback: 7.1.4 established, 7.1.3 comes back; it is a candidate and
// needs the same evidence to become established again (then the matcher
// reopens the finding it closed).
func TestRollbackNeedsEvidenceThenRestores(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, _ := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(time.Hour), ClassProbe, 90)),
		one(see(a, t0.Add(2*time.Hour), ClassBanner, 65)),
	)
	if cur := current(t, rows); cur.VersionID != b.id {
		t.Fatalf("established = %s, want 7.1.4 after one weak rollback reading", cur.Raw)
	}
	if ra := row(t, rows, a); ra.Superseded || ra.State != VersionCandidate {
		t.Fatalf("7.1.3 = %+v, want a candidate again", ra)
	}
	rows, changed := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(time.Hour), ClassProbe, 90)),
		one(see(a, t0.Add(2*time.Hour), ClassProbe, 90)),
	)
	if cur := current(t, rows); cur.VersionID != a.id || !changed[2] {
		t.Fatalf("established = %s, want 7.1.3 back from a strong reading", cur.Raw)
	}
}

// Out-of-order ingest: an older scan arriving after a newer one only adds
// history; it neither promotes nor breaks the newer streak's order.
func TestOutOfOrderNeverPromotes(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, changed := history(t,
		one(see(a, t0.Add(48*time.Hour), ClassBanner, 65)),
		// Older strong reading of another version arrives late.
		one(see(b, t0, ClassProbe, 95)),
	)
	if cur := current(t, rows); cur.VersionID != a.id || changed[1] {
		t.Fatalf("established = %s, want 7.1.3 (older reading)", cur.Raw)
	}
	if r := row(t, rows, b); !r.LastSeen.Equal(t0) {
		t.Fatalf("7.1.4 = %+v", r)
	}
	// An older reading of the established version inside a candidate's
	// streak breaks the streak (flapping seen late).
	rows, _ = history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(10*time.Hour), ClassBanner, 65)),
		one(see(b, t0.Add(20*time.Hour), ClassBanner, 65)),
		one(see(a, t0.Add(15*time.Hour), ClassBanner, 65)),
		one(see(b, t0.Add(30*time.Hour), ClassBanner, 65)),
	)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3 (streak broken by a late reading)", cur.Raw)
	}
}

// Re-import of the same report (same time): idempotent.
func TestReimportIsIdempotent(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	s := see(b, t0.Add(time.Hour), ClassBanner, 65)
	rows, _ := history(t, one(see(a, t0, ClassBanner, 65)), one(s), one(s), one(s), []Sighting{s, s})
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatalf("established = %s, want 7.1.3", cur.Raw)
	}
	if r := row(t, rows, b); r.Sightings != 1 || r.Streak != 1 {
		t.Fatalf("7.1.4 = %+v, want one sighting", r)
	}
}

// Partial and fuzzy versions: "7.1" is compatible with 7.1.3 and says
// nothing against it; a distribution build of the same upstream version is
// not a version change; no version says nothing.
func TestNeutralSightings(t *testing.T) {
	a := mkVer("7.1.3")
	cases := []ver{mkVer("7.1"), mkVer("7"), mkVer("v7.1.3"), {id: shared.NewID(), raw: ""}}
	for _, n := range cases {
		var batches [][]Sighting
		batches = append(batches, one(see(a, t0, ClassBanner, 65)))
		for i := 1; i <= 5; i++ {
			batches = append(batches, one(see(n, t0.Add(time.Duration(i)*24*time.Hour), ClassProbe, 95)))
		}
		rows, _ := history(t, batches...)
		if cur := current(t, rows); cur.VersionID != a.id {
			t.Fatalf("%q displaced 7.1.3", n.raw)
		}
	}
	// Same upstream, another distribution build (back-port).
	q := mkVer("7.1.3")
	rows, _ := history(t,
		one(see(a, t0, ClassBanner, 65)),
		[]Sighting{{VersionID: q.id, Raw: "7.1.3", Normalized: q.norm, Qualifier: "deb12u4", Segments: 3, At: t0.Add(time.Hour), Class: ClassInventory, Confidence: 95}},
	)
	if cur := current(t, rows); cur.VersionID != a.id {
		t.Fatal("a distribution build of the same version displaced it")
	}
	// A coarser version that is not compatible is a real change.
	c := mkVer("7.2")
	rows, _ = history(t, one(see(a, t0, ClassBanner, 65)), one(see(c, t0.Add(time.Hour), ClassProbe, 95)))
	if cur := current(t, rows); cur.VersionID != c.id {
		t.Fatal("7.2 should displace 7.1.3 from a strong reading")
	}
}

// A version seen before it was superseded (old scan) stays superseded.
func TestOldReadingOfSupersededStaysSuperseded(t *testing.T) {
	a, b := mkVer("7.1.3"), mkVer("7.1.4")
	rows, _ := history(t,
		one(see(a, t0, ClassBanner, 65)),
		one(see(b, t0.Add(10*time.Hour), ClassProbe, 90)),
		one(see(a, t0.Add(5*time.Hour), ClassBanner, 65)),
	)
	if cur := current(t, rows); cur.VersionID != b.id {
		t.Fatalf("established = %s, want 7.1.4", cur.Raw)
	}
	if r := row(t, rows, a); !r.Superseded || r.Sightings != 2 {
		t.Fatalf("7.1.3 = %+v, want superseded with the extra sighting", r)
	}
}

// Every superseded row and a new reading: the reading is established.
func TestReestablishAfterAllSuperseded(t *testing.T) {
	a := mkVer("7.1.3")
	rows := []HistoryRow{{VersionID: a.id, Raw: a.raw, Normalized: a.norm, State: VersionEstablished,
		Superseded: true, SupersededAt: t0, FirstSeen: t0.Add(-time.Hour), LastSeen: t0.Add(-time.Hour), Sightings: 1, Class: ClassBanner}}
	b := mkVer("7.1.4")
	res := ApplySightings(rows, one(see(b, t0.Add(time.Hour), ClassBanner, 50)))
	if !res.EstablishedChanged || current(t, res.Rows).VersionID != b.id {
		t.Fatal("with nothing established, the reading becomes established")
	}
}

func TestClassOf(t *testing.T) {
	full := Parsed{Segments: 3}
	cases := []struct {
		o    Observation
		p    Parsed
		want EvidenceClass
	}{
		{Observation{Source: SourceTechnology}, full, ClassBanner},
		{Observation{Source: SourceService, CPE: "cpe:2.3:a:nginx:nginx:1.18.0"}, full, ClassProbe},
		{Observation{Source: SourceService}, full, ClassBanner},
		{Observation{Source: SourceOS}, full, ClassHeuristic},
		{Observation{Source: SourceTechnology}, Parsed{Segments: 2}, ClassHeuristic},
		{Observation{Source: SourceTechnology, Class: ClassProbe}, full, ClassProbe},
		{Observation{Source: SourceService, Class: "bogus"}, full, ClassBanner},
		{Observation{Source: "package", Class: ClassSBOM}, Parsed{Segments: 1}, ClassSBOM},
	}
	for i, c := range cases {
		if got := ClassOf(c.o, c.p); got != c.want {
			t.Errorf("%d: ClassOf = %s, want %s", i, got, c.want)
		}
	}
	if !Strong(ClassInventory, 0) || !Strong(ClassProbe, 80) || Strong(ClassProbe, 79) || Strong(ClassBanner, 100) {
		t.Fatal("Strong")
	}
}
