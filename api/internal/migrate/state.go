package migrate

import (
	"math"
	"sort"
)

// Fence is the version this runner keeps in schema_migrations while the
// database is clean. No migration has it, so the earlier migration tool
// (an older migrations image) refuses the database ("no migration found for
// version ...") instead of migrating it by its rule, which skips every
// version below the highest applied one.
const Fence int64 = math.MaxInt64

// firstTimestamp is the lowest timestamp version (YYYYMMDDHHMMSS, 14
// digits). Lower versions are the legacy sequential numbers, which only
// ever grew, so the earlier tool never skipped one of them.
const firstTimestamp int64 = 10_000_000_000_000

// dbState is what the two tracking tables hold.
type dbState struct {
	Tracker int64 // schema_migrations.version: Fence, a dirty version, the earlier tool's version, or 0 (no row)
	Dirty   bool
	Applied map[int64]bool // schema_migrations_applied
}

// earlierTool reports whether schema_migrations was last written by the
// earlier tool (a clean version that is not the fence).
func (st dbState) earlierTool() bool { return !st.Dirty && st.Tracker > 0 && st.Tracker != Fence }

// plan is what a run has to do for a dbState and a directory.
type plan struct {
	// Record: migrations the earlier tool applied (its legacy-numbered
	// files up to its version), recorded without running them when this
	// runner takes the database over.
	Record []Migration
	// Pending: migrations to run, lowest version first.
	Pending []Migration
	// Unknown: applied versions this directory does not ship and that are
	// neither below its baseline nor above its newest file (a migration
	// removed from the tree, or one of a newer release). Reported only.
	Unknown []int64
	// Highest applied version once Record is recorded.
	Highest int64
}

// takeover splits the files up to the earlier tool's version into the
// legacy ones (applied: that tool applied every version above the current
// one, and legacy numbers only grew) and timestamp ones (which it may have
// skipped: undecidable).
func takeover(v int64, migs []Migration) (legacy []Migration, undecided []int64) {
	for _, m := range migs {
		switch {
		case m.Version > v:
		case m.Version < firstTimestamp:
			legacy = append(legacy, m)
		default:
			undecided = append(undecided, m.Version)
		}
	}
	return legacy, undecided
}

// resolve decides, without touching the database, what a run does. Its
// errors are refusals: nothing may be changed.
func resolve(st dbState, migs []Migration) (plan, error) {
	var p plan
	if st.Dirty {
		return p, ErrDirty{Version: st.Tracker}
	}
	applied := make(map[int64]bool, len(st.Applied)+len(migs))
	for v := range st.Applied {
		applied[v] = true
	}
	var newest int64
	if len(migs) > 0 {
		newest = migs[len(migs)-1].Version
	}

	if st.earlierTool() {
		if len(st.Applied) > 0 {
			return p, ErrTrackerMismatch{Tracker: st.Tracker}
		}
		if st.Tracker > newest {
			return p, ErrNewerDatabase{Applied: st.Tracker, Shipped: newest}
		}
		legacy, undecided := takeover(st.Tracker, migs)
		if len(undecided) > 0 {
			return p, ErrUndecidedTakeover{Tracker: st.Tracker, Versions: undecided}
		}
		p.Record = legacy
		for _, m := range legacy {
			applied[m.Version] = true
		}
	}
	if len(migs) == 0 {
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
			return p, ErrNewerDatabase{Applied: v, Shipped: newest}
		case !shipped[v] && v > baseline:
			p.Unknown = append(p.Unknown, v)
		}
		p.Highest = max(p.Highest, v)
	}
	sort.Slice(p.Unknown, func(i, j int) bool { return p.Unknown[i] < p.Unknown[j] })
	for _, m := range migs {
		if !applied[m.Version] {
			p.Pending = append(p.Pending, m)
		}
	}
	return p, nil
}
