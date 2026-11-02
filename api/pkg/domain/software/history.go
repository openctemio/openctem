package software

import (
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
)

// Version history of one product at one place on an asset
// (docs/architecture/software-version-history.md).
//
// Every version a source reports at (asset, product, location) keeps its own
// asset_software row with first and last seen, sightings and the best
// evidence class. The established rows (usually one; several when scans
// report several versions together) are what the vulnerability matcher
// builds findings on and what a later version must displace before a
// finding is closed as fixed. Another version starts as a
// candidate and becomes established only when the evidence is strong, or
// when it is the trusted reading of PromoteSightings consecutive scans
// spanning at least PromoteMinSpan with the established version not read in
// between. A single sighting from a weak source (a banner, a page meta tag)
// therefore never closes or proposes to close a finding, and a host that
// alternates between two versions (load balancer, stale cache, blue/green)
// keeps its established version.

// EvidenceClass is how a source knows the version, strongest first.
type EvidenceClass string

// Evidence classes (asset_software.evidence_class).
const (
	// ClassInventory: an authenticated package or host inventory.
	ClassInventory EvidenceClass = "inventory"
	// ClassSBOM: an uploaded or CI-produced bill of materials.
	ClassSBOM EvidenceClass = "sbom"
	// ClassProbe: an active fingerprint (service probe with a product,
	// version endpoint, CPE from the tool).
	ClassProbe EvidenceClass = "probe"
	// ClassBanner: a banner, Server header, page meta or generator tag.
	ClassBanner EvidenceClass = "banner"
	// ClassHeuristic: inferred (OS guess, partial version, no version).
	ClassHeuristic EvidenceClass = "heuristic"
)

// Rank orders the classes: higher is stronger; 0 for an unknown class.
func (c EvidenceClass) Rank() int {
	switch c {
	case ClassInventory:
		return 5
	case ClassSBOM:
		return 4
	case ClassProbe:
		return 3
	case ClassBanner:
		return 2
	case ClassHeuristic:
		return 1
	}
	return 0
}

// Valid reports whether c is a known class.
func (c EvidenceClass) Valid() bool { return c.Rank() > 0 }

// VersionState is the role of a version row in its history.
type VersionState string

// Version states (asset_software.version_state). A superseded row keeps its
// state and has superseded_at set.
const (
	VersionEstablished VersionState = "established"
	VersionCandidate   VersionState = "candidate"
)

// Hysteresis of a version change.
const (
	// PromoteSightings is how many consecutive trusted readings a candidate
	// needs to displace the established version.
	PromoteSightings = 3
	// PromoteMinSpan is the least time between the first and the last of
	// those readings, so one burst of scans does not count as three.
	PromoteMinSpan = 12 * time.Hour
	// StrongConfidence is the confidence from which an active probe is
	// trusted on its own.
	StrongConfidence = 80
	// maxStreak caps the stored streak.
	maxStreak = 1000
)

// ClassOf is the evidence class of an observation: the producer's when it set
// a valid one, else derived from the source. A partial version or no version
// is at best heuristic.
func ClassOf(o Observation, p Parsed) EvidenceClass {
	c := o.Class
	if !c.Valid() {
		switch o.Source {
		case SourceService, SourceOpenPort:
			c = ClassBanner
			if strings.TrimSpace(o.CPE) != "" {
				c = ClassProbe
			}
		case SourceTechnology:
			c = ClassBanner
		default:
			c = ClassHeuristic
		}
	}
	if p.Segments < 3 && c.Rank() > ClassHeuristic.Rank() && c.Rank() < ClassSBOM.Rank() {
		c = ClassHeuristic
	}
	return c
}

// Strong reports whether one reading of this class and confidence may
// displace an established version without waiting for more scans.
func Strong(c EvidenceClass, confidence int) bool {
	return c.Rank() >= ClassSBOM.Rank() || (c == ClassProbe && confidence >= StrongConfidence)
}

// HistoryRow is one version row of a (asset, product, location) history.
type HistoryRow struct {
	VersionID shared.ID
	// Raw and Normalized are the catalog version (Normalized "" when it
	// does not parse); Qualifier is the distribution build.
	Raw, Normalized, Qualifier string
	State                      VersionState
	Superseded                 bool
	SupersededAt               time.Time
	FirstSeen, LastSeen        time.Time
	Sightings                  int
	// Streak counts the consecutive scans this version was the trusted
	// reading of, since StreakSince; 0 after another version won a scan.
	Streak      int
	StreakSince time.Time
	Class       EvidenceClass
	Confidence  int

	// New: the row does not exist yet. Seen: this batch observed it.
	// Dirty: its stored state changed.
	New, Seen, Dirty bool
}

// Current reports whether the row is the established, not superseded one.
func (r HistoryRow) Current() bool { return r.State == VersionEstablished && !r.Superseded }

// Sighting is one source's reading of a version at a time.
type Sighting struct {
	VersionID                  shared.ID
	Raw, Normalized, Qualifier string
	// Segments is the number of segments of the reported version (0: none
	// or not parseable).
	Segments   int
	At         time.Time
	Class      EvidenceClass
	Confidence int
}

// HistoryResult is the history after a batch.
type HistoryResult struct {
	Rows []HistoryRow
	// EstablishedChanged: the established set changed; findings need a
	// re-match.
	EstablishedChanged bool
}

// ApplySightings records the sightings of one report for one history and
// moves the established version when the evidence allows it. Sightings with
// different times are applied oldest first; a sighting older than the
// history's latest reading only extends the history (out-of-order ingest
// never promotes).
func ApplySightings(rows []HistoryRow, batch []Sighting) HistoryResult {
	out := make([]HistoryRow, len(rows))
	copy(out, rows)
	res := HistoryResult{}
	sorted := make([]Sighting, len(batch))
	copy(sorted, batch)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })
	for i := 0; i < len(sorted); {
		j := i
		for j < len(sorted) && sorted[j].At.Equal(sorted[i].At) {
			j++
		}
		if applyAt(&out, sorted[i:j]) {
			res.EstablishedChanged = true
		}
		i = j
	}
	res.Rows = out
	return res
}

// applyAt applies the sightings of one time; it reports whether the
// established set changed.
//
// The reading of a scan is the set of decisive versions at the strongest
// class it holds: versions one scan reports together are present together
// (two copies of a library on a page, a partly rolled-out deployment);
// weaker sightings of that scan only add history.
func applyAt(rows *[]HistoryRow, batch []Sighting) bool {
	at := batch[0].At
	merged := mergeSightings(batch)
	latest := latestSeen(*rows)
	var est []HistoryRow
	for _, r := range *rows {
		if r.Current() {
			est = append(est, r)
		}
	}

	reading := readingOf(merged, est)
	prevLast := recordSightings(rows, merged, at)

	if len(reading) == 0 {
		// Nothing decisive. With nothing established, a lone sighting
		// (no version, say) is the version.
		if len(est) == 0 && len(merged) == 1 {
			i := indexOf(*rows, merged[0].VersionID)
			if !(*rows)[i].Superseded {
				bumpStreak(&(*rows)[i], at, prevLast)
				(*rows)[i].State, (*rows)[i].Dirty = VersionEstablished, true
				return true
			}
		}
		return false
	}
	in := map[shared.ID]bool{}
	for _, id := range reading {
		in[id] = true
	}
	// The reading breaks the streak of every version it leaves out, when
	// it falls inside that streak (in order or late).
	for k := range *rows {
		r := &(*rows)[k]
		if in[r.VersionID] || r.Superseded || r.Streak == 0 {
			continue
		}
		if r.StreakSince.IsZero() || !at.Before(r.StreakSince) {
			r.Streak, r.StreakSince, r.Dirty = 0, time.Time{}, true
		}
	}
	fresh := map[shared.ID]bool{}
	for _, id := range reading {
		i := indexOf(*rows, id)
		if (*rows)[i].Superseded {
			// An old reading of a superseded version: history only.
			continue
		}
		fresh[id] = bumpStreak(&(*rows)[i], at, prevLast)
	}

	if len(est) == 0 {
		changed := false
		for _, id := range reading {
			i := indexOf(*rows, id)
			if !(*rows)[i].Superseded {
				(*rows)[i].State, (*rows)[i].Dirty = VersionEstablished, true
				changed = true
			}
		}
		return changed
	}
	// Promotion: never from an out-of-order reading.
	if at.Before(latest) {
		return false
	}
	if !promoteReading(*rows, reading, est, fresh) {
		return false
	}
	// The confirming reading replaces what it does not contain.
	for k := range *rows {
		r := &(*rows)[k]
		if !in[r.VersionID] && !r.Superseded {
			r.Superseded, r.SupersededAt, r.Dirty = true, at, true
		}
	}
	return true
}

// readingOf is the reading of a scan: the decisive versions at the
// strongest class among the sightings.
func readingOf(merged []Sighting, est []HistoryRow) []shared.ID {
	top := 0
	var reading []shared.ID
	for _, s := range merged {
		if s.Normalized == "" || neutralToAny(s, est) {
			continue
		}
		switch r := s.Class.Rank(); {
		case r > top:
			top, reading = r, []shared.ID{s.VersionID}
		case r == top:
			reading = append(reading, s.VersionID)
		}
	}
	return reading
}

// promoteReading establishes the candidates of the reading whose evidence
// is enough (strong, or settled by consecutive readings); it reports
// whether any was.
func promoteReading(rows []HistoryRow, reading []shared.ID, est []HistoryRow, fresh map[shared.ID]bool) bool {
	estRank := 0
	for _, r := range est {
		if r.Class.Rank() > estRank {
			estRank = r.Class.Rank()
		}
	}
	promoted := false
	for _, id := range reading {
		c := &rows[indexOf(rows, id)]
		if c.Superseded || c.State == VersionEstablished || !fresh[id] {
			continue
		}
		strong := Strong(c.Class, c.Confidence) && c.Class.Rank() >= estRank
		settled := c.Streak >= PromoteSightings && c.LastSeen.Sub(c.StreakSince) >= PromoteMinSpan
		if strong || settled {
			c.State, c.Dirty = VersionEstablished, true
			promoted = true
		}
	}
	return promoted
}

// recordSightings adds the sightings to the history and returns each
// existing row's last reading before them.
func recordSightings(rows *[]HistoryRow, merged []Sighting, at time.Time) map[shared.ID]time.Time {
	prevLast := map[shared.ID]time.Time{}
	for _, s := range merged {
		i := indexOf(*rows, s.VersionID)
		if i < 0 {
			*rows = append(*rows, HistoryRow{
				VersionID: s.VersionID, Raw: s.Raw, Normalized: s.Normalized, Qualifier: s.Qualifier,
				State: VersionCandidate, FirstSeen: at, LastSeen: at, Sightings: 1,
				Class: s.Class, Confidence: s.Confidence, New: true, Seen: true, Dirty: true,
			})
			continue
		}
		r := &(*rows)[i]
		prevLast[r.VersionID] = r.LastSeen
		r.Seen, r.Dirty = true, true
		switch {
		case at.After(r.LastSeen):
			r.LastSeen = at
			r.Sightings++
		case at.Before(r.FirstSeen):
			r.FirstSeen = at
			r.Sightings++
		case !at.Equal(r.LastSeen) && !at.Equal(r.FirstSeen):
			r.Sightings++
		}
		if s.Class.Rank() > r.Class.Rank() {
			r.Class = s.Class
		}
		if s.Confidence > r.Confidence {
			r.Confidence = s.Confidence
		}
		// A superseded version seen again after it was superseded is a
		// candidate again (a rollback); an older reading only adds history.
		if r.Superseded && at.After(r.SupersededAt) {
			r.Superseded, r.SupersededAt = false, time.Time{}
			r.State, r.Streak, r.StreakSince = VersionCandidate, 0, time.Time{}
		}
	}
	return prevLast
}

// neutralToAny reports whether the sighting says nothing against one of
// the established versions.
func neutralToAny(s Sighting, est []HistoryRow) bool {
	for _, e := range est {
		if neutral(s, e) {
			return true
		}
	}
	return false
}

// bumpStreak counts a trusted reading of r at at; it reports whether the
// reading was fresh (newer than r's previous last reading).
func bumpStreak(r *HistoryRow, at time.Time, prevLast map[shared.ID]time.Time) bool {
	prev, existed := prevLast[r.VersionID]
	if existed && !at.After(prev) {
		return false
	}
	if r.Streak == 0 || r.StreakSince.IsZero() {
		r.StreakSince = at
	}
	if r.Streak < maxStreak {
		r.Streak++
	}
	r.Dirty = true
	return true
}

// neutral reports whether a sighting says nothing against the established
// row: the same version, a coarser version it is compatible with ("7.1" for
// 7.1.3), or the same upstream version with another distribution build (a
// back-port is not a version change).
func neutral(s Sighting, est HistoryRow) bool {
	if s.VersionID == est.VersionID {
		return false
	}
	if s.Normalized == "" || est.Normalized == "" {
		return true
	}
	if s.Normalized == est.Normalized {
		return true
	}
	estSegs := segmentsOf(est.Raw)
	return s.Segments > 0 && s.Segments < estSegs &&
		strings.HasPrefix(est.Normalized+".", s.Normalized+".")
}

func segmentsOf(raw string) int {
	if v, ok := vulnmatch.ParseVersion(raw); ok {
		return v.Segments()
	}
	return 0
}

// mergeSightings keeps one sighting per version: the strongest class and
// the highest confidence.
func mergeSightings(batch []Sighting) []Sighting {
	out := make([]Sighting, 0, len(batch))
	idx := map[shared.ID]int{}
	for _, s := range batch {
		i, ok := idx[s.VersionID]
		if !ok {
			idx[s.VersionID] = len(out)
			out = append(out, s)
			continue
		}
		if s.Class.Rank() > out[i].Class.Rank() {
			out[i].Class = s.Class
		}
		if s.Confidence > out[i].Confidence {
			out[i].Confidence = s.Confidence
		}
		if s.Segments > out[i].Segments {
			out[i].Segments = s.Segments
		}
	}
	return out
}

func latestSeen(rows []HistoryRow) time.Time {
	var t time.Time
	for _, r := range rows {
		if r.LastSeen.After(t) {
			t = r.LastSeen
		}
	}
	return t
}

func indexOf(rows []HistoryRow, id shared.ID) int {
	for i, r := range rows {
		if r.VersionID == id {
			return i
		}
	}
	return -1
}
