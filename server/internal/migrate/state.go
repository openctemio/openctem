package migrate

import (
	"maps"
	"math"
	"sort"
)

// Fence is the version this runner keeps in schema_migrations while the
// database is clean. No migration has it, so the earlier migration tool
// (an older migrations image) refuses the database ("no migration found for
// version ...") instead of migrating it by its rule, which skips every
// version below the highest applied one.
const Fence int64 = math.MaxInt64

// dbState is what the two tracking tables hold.
type dbState struct {
	Tracker int64 // schema_migrations.version: Fence, a dirty version, the earlier tool's version, or 0 (no row)
	Dirty   bool
	Applied map[int64]bool   // schema_migrations_applied
	Names   map[int64]string // schema_migrations_applied.name per version (may be nil)
}

// earlierTool reports whether schema_migrations was last written by the
// earlier tool (a clean version that is not the fence).
func (st dbState) earlierTool() bool { return !st.Dirty && st.Tracker > 0 && st.Tracker != Fence }

// plan is what a run has to do for a dbState and a directory.
type plan struct {
	// Record: migrations the earlier tool applied (Takeover decides which),
	// recorded without running them when this runner takes the database
	// over.
	Record []Migration
	// Pending: migrations to run, lowest version first.
	Pending []Migration
	// Unknown: applied versions this directory does not ship and that are
	// neither below its baseline nor above its newest file (a migration
	// removed from the tree, or one of a newer release). Reported only.
	Unknown []int64
	// Renamed: applied migrations whose recorded name differs from the
	// shipped file's (a merged migration renamed, or another file under
	// its version). Reported only.
	Renamed []Renamed
	// Highest applied version once Record is recorded.
	Highest int64
}

// Renamed is an applied migration recorded under another name than the
// file this directory ships for its version.
type Renamed struct {
	Version          int64
	Applied, Shipped string
}

// Release is a group of release tags that shipped the same migration
// versions while they used the earlier tool (released.json).
type Release struct {
	Tags     []string `json:"tags"`
	Versions []int64  `json:"versions"`
}

func (r Release) highest() int64 {
	var v int64
	for _, x := range r.Versions {
		v = max(v, x)
	}
	return v
}

// Takeover is what decides which migrations the earlier tool applied on a
// database it left at one version (it records nothing else).
type Takeover struct {
	// Releases: the migration versions of every release that shipped the
	// earlier tool. A database at version V took exactly the files of the
	// release whose highest version is V: a file merged below V after that
	// release was cut (003420 after v0.15.4 shipped 003428) never ran there.
	Releases []Release
	// AssumeApplied: an operator's explicit list of the applied versions,
	// for a database no release matches (one migrated from a development
	// branch, or left dirty). When set it replaces the release match.
	AssumeApplied map[int64]bool
}

// takeover decides which shipped migrations the earlier tool applied on a
// database it left at version v (clean): the operator's list, else the
// files of the one release whose highest version is v. Anything else is
// undecidable (that tool skips a version merged after a higher one).
func (t Takeover) takeover(v int64, dirty bool, migs []Migration) ([]Migration, error) {
	pick := func(set map[int64]bool) []Migration {
		var out []Migration
		for _, m := range migs {
			if set[m.Version] {
				out = append(out, m)
			}
		}
		return out
	}
	if t.AssumeApplied != nil {
		return pick(t.AssumeApplied), nil
	}
	if dirty {
		return nil, ErrUndecidedTakeover{Tracker: v, Dirty: true}
	}
	if len(migs) > 0 && migs[0].Baseline() && v == migs[0].Version {
		// At the baseline itself: it replaces every file up to it.
		return migs[:1], nil
	}
	var match map[int64]bool
	var tags []string
	ambiguous := false
	for _, r := range t.Releases {
		if r.highest() != v {
			continue
		}
		set := make(map[int64]bool, len(r.Versions))
		for _, x := range r.Versions {
			set[x] = true
		}
		tags = append(tags, r.Tags...)
		if match == nil {
			match = set
		} else if !maps.Equal(match, set) {
			ambiguous = true
		}
	}
	if match == nil || ambiguous {
		var amb []string
		if ambiguous {
			amb = tags
		}
		return nil, ErrUndecidedTakeover{Tracker: v, Ambiguous: amb}
	}
	return pick(match), nil
}

// earlierToolRecord is the takeover of a clean database the earlier tool
// left: refused when this runner recorded versions since (another tool
// rewrote the tracker) or when it predates the baseline.
func (t Takeover) earlierToolRecord(st dbState, migs []Migration) ([]Migration, error) {
	if len(st.Applied) > 0 {
		return nil, ErrTrackerMismatch{Tracker: st.Tracker}
	}
	if len(migs) > 0 && migs[0].Baseline() && st.Tracker < migs[0].Version {
		return nil, ErrOlderThanBaseline{Version: st.Tracker, Baseline: migs[0].Version}
	}
	return t.takeover(st.Tracker, false, migs)
}

// resolve decides, without touching the database, what a run does. Its
// errors are refusals: nothing may be changed. With ErrNewerDatabase the
// plan is still complete (Pending in particular): a newer release migrated
// the database, and the caller decides whether that is acceptable when
// something this directory ships is still not applied.
func resolve(st dbState, migs []Migration, tk Takeover) (plan, error) {
	var p plan
	if st.Dirty {
		return p, ErrDirty{Version: st.Tracker, EarlierTool: len(st.Applied) == 0 && st.Tracker > 0}
	}
	applied := make(map[int64]bool, len(st.Applied)+len(migs))
	for v := range st.Applied {
		applied[v] = true
	}
	var newest int64
	if len(migs) > 0 {
		newest = migs[len(migs)-1].Version
	}

	var newer *ErrNewerDatabase
	noteNewer := func(v int64) {
		if v > newest && (newer == nil || v > newer.Applied) {
			newer = &ErrNewerDatabase{Applied: v, Shipped: newest}
		}
	}
	if st.earlierTool() {
		recorded, err := tk.earlierToolRecord(st, migs)
		if err != nil {
			return p, err
		}
		noteNewer(st.Tracker)
		p.Record = recorded
		for _, m := range recorded {
			applied[m.Version] = true
		}
	}
	if len(migs) == 0 {
		if newer != nil {
			return p, *newer
		}
		return p, nil
	}

	shipped := make(map[int64]bool, len(migs))
	for _, m := range migs {
		shipped[m.Version] = true
	}
	var baseline int64
	if migs[0].Baseline() {
		baseline = migs[0].Version
	}
	// A database that has anything applied but not the baseline predates
	// it: the files it still needs were replaced by the baseline.
	if baseline > 0 && (st.earlierTool() || len(applied) > 0) && !applied[baseline] {
		v := st.Tracker
		if !st.earlierTool() {
			v = 0
			for a := range applied {
				v = max(v, a)
			}
		}
		return p, ErrOlderThanBaseline{Version: v, Baseline: baseline}
	}
	for v := range applied {
		switch {
		case v > newest:
			noteNewer(v)
		case !shipped[v] && v > baseline:
			p.Unknown = append(p.Unknown, v)
		}
		p.Highest = max(p.Highest, v)
	}
	sort.Slice(p.Unknown, func(i, j int) bool { return p.Unknown[i] < p.Unknown[j] })
	for _, m := range migs {
		if !applied[m.Version] {
			p.Pending = append(p.Pending, m)
			continue
		}
		if name := st.Names[m.Version]; name != "" && name != m.Name {
			p.Renamed = append(p.Renamed, Renamed{Version: m.Version, Applied: name, Shipped: m.Name})
		}
	}
	if newer != nil {
		return p, *newer
	}
	return p, nil
}
