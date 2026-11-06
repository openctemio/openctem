package scanwindow

// The evaluator: given the sources that govern a target and the tier of the
// work, may it run now, why not, and when next. Pure; every caller (claim,
// trigger, scheduler, closing-window controller, API) uses Decide, so what
// the console explains and what dispatch enforces cannot differ.

import (
	"slices"
	"sort"
	"time"
)

// Origin says where a source comes from.
type Origin string

const (
	// OriginPolicy is a scan window policy of the organization.
	OriginPolicy Origin = "policy"
	// OriginProgram is a bug-bounty program's testing windows: never
	// overridable (third-party terms).
	OriginProgram Origin = "program"
)

// Search horizons for the next opening or closing: a short one first (the
// common weekly case), then the long one before answering "never".
const (
	horizonShort = 8 * 24 * time.Hour
	horizonLong  = 400 * 24 * time.Hour
)

// LocalSlot is a weekly window in its own time zone: ISO days, minutes after
// local midnight. End <= Start runs past midnight (equal: 24 hours).
type LocalSlot struct {
	Days  []int
	Start int
	End   int
	Loc   *time.Location
}

// Source is one thing that governs when targets may be scanned: a policy, or
// a program's testing windows.
type Source struct {
	ID            string
	Name          string
	Kind          Kind
	Origin        Origin
	MinTier       int
	Slots         []LocalSlot
	OneOffs       []OneOff
	GraceMinutes  int
	RateLimitRPS  int
	MaxConcurrent int
	Overridable   bool
	// Broken: a time zone or time could not be read. It fails closed: an
	// allow source is never open, a blackout is always active.
	Broken bool
}

// PolicySource is the source of a policy.
func PolicySource(p *Policy) Source {
	s := Source{
		ID: p.ID.String(), Name: p.Name, Kind: p.Kind, Origin: OriginPolicy, MinTier: p.MinTier,
		OneOffs: slices.Clone(p.OneOffs), GraceMinutes: p.GraceMinutes, RateLimitRPS: p.RateLimitRPS,
		MaxConcurrent: p.MaxConcurrent, Overridable: true,
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		s.Broken = true
		return s
	}
	for _, sl := range p.Slots {
		start, err1 := ParseMinute(sl.Start)
		end, err2 := ParseMinute(sl.End)
		if err1 != nil || err2 != nil {
			s.Broken = true
			return s
		}
		s.Slots = append(s.Slots, LocalSlot{Days: slices.Clone(sl.Days), Start: start, End: end, Loc: loc})
	}
	return s
}

// Ref names a source in an explanation.
type Ref struct {
	SourceID string `json:"source_id"`
	Name     string `json:"name"`
	Kind     Kind   `json:"kind"`
	Origin   Origin `json:"origin"`
}

// Block is a source that keeps the work from running now. Until is when
// this source alone stops blocking (an allow source's next window, the end
// of a blackout); nil when it never does within the horizon.
type Block struct {
	Ref
	Until *time.Time `json:"until,omitempty"`
}

// Cap is a concurrency cap of a governing allow source.
type Cap struct {
	SourceID      string
	MaxConcurrent int
}

// Decision is the evaluator's answer for some work at an instant.
type Decision struct {
	// Governed: at least one source governs the work.
	Governed bool
	// Open: the work may run now.
	Open bool
	// NextOpen: when closed, the earliest instant it may run; nil and Never
	// set when there is none within the horizon.
	NextOpen *time.Time
	Never    bool
	// ClosesAt: when open and governed, when it stops being open (nil: not
	// within the horizon).
	ClosesAt *time.Time
	// Blocking: the sources that keep it from running now.
	Blocking []Block
	// Governing: every governing source.
	Governing []Ref
	// RateLimitRPS: the smallest rate cap of the governing allow sources
	// (0: none).
	RateLimitRPS int
	// Caps: the concurrency caps of the governing allow sources.
	Caps []Cap
	// GraceMinutes: the smallest grace of the blocking sources (how long
	// running work may continue after it closed).
	GraceMinutes int
}

// Governs reports whether s governs work of the given tier.
func (s Source) Governs(tier int) bool { return tier >= s.MinTier }

func (s Source) ref() Ref { return Ref{SourceID: s.ID, Name: s.Name, Kind: s.Kind, Origin: s.Origin} }

// Decide answers whether work of tier governed by sources may run at now.
// Allow sources intersect (each must be open), blackout sources subtract
// (none may be active). Sources with the same ID count once.
func Decide(sources []Source, tier int, now time.Time) Decision {
	gov := governing(sources, tier)
	if len(gov) == 0 {
		return Decision{Open: true}
	}
	d := Decision{Governed: true}
	for _, s := range gov {
		d.Governing = append(d.Governing, s.ref())
	}
	ev := newEvaluation(gov, now, horizonShort)
	if ev.openAt(now) {
		d.Open = true
		closes := ev.next(now, false)
		if closes == nil {
			closes = newEvaluation(gov, now, horizonLong).next(now, false)
		}
		d.ClosesAt = closes
		for _, s := range gov {
			if s.Kind != KindAllow {
				continue
			}
			if s.RateLimitRPS > 0 && (d.RateLimitRPS == 0 || s.RateLimitRPS < d.RateLimitRPS) {
				d.RateLimitRPS = s.RateLimitRPS
			}
			if s.MaxConcurrent > 0 {
				d.Caps = append(d.Caps, Cap{SourceID: s.ID, MaxConcurrent: s.MaxConcurrent})
			}
		}
		return d
	}
	long := newEvaluation(gov, now, horizonLong)
	d.NextOpen = ev.next(now, true)
	if d.NextOpen == nil {
		d.NextOpen = long.next(now, true)
	}
	d.Never = d.NextOpen == nil
	d.GraceMinutes = -1
	for i, s := range gov {
		blocked, until := long.blocking(i, now)
		if !blocked {
			continue
		}
		d.Blocking = append(d.Blocking, Block{Ref: s.ref(), Until: until})
		if d.GraceMinutes < 0 || s.GraceMinutes < d.GraceMinutes {
			d.GraceMinutes = s.GraceMinutes
		}
	}
	if d.GraceMinutes < 0 {
		d.GraceMinutes = 0
	}
	return d
}

// Openings lists up to n intervals from now in which work of tier governed
// by sources may run (the policy preview), within the long horizon.
func Openings(sources []Source, tier int, now time.Time, n int) []Window {
	gov := governing(sources, tier)
	if len(gov) == 0 || n <= 0 {
		return nil
	}
	ev := newEvaluation(gov, now, horizonLong)
	var out []Window
	t := now
	for len(out) < n {
		var start time.Time
		if ev.openAt(t) {
			start = t
		} else {
			nx := ev.next(t, true)
			if nx == nil {
				break
			}
			start = *nx
		}
		end := ev.next(start, false)
		w := Window{Start: start}
		if end != nil {
			w.End = *end
		}
		out = append(out, w)
		if end == nil {
			break
		}
		t = *end
	}
	return out
}

// Window is an interval in which work may run; a zero End means it lasts
// beyond the horizon.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func governing(sources []Source, tier int) []Source {
	out := make([]Source, 0, len(sources))
	seen := map[string]bool{}
	for _, s := range sources {
		if !s.Governs(tier) || seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	return out
}

// interval is [start, end).
type interval struct{ start, end time.Time }

// far stands for "beyond any horizon" for a broken blackout.
var (
	farPast   = time.Unix(0, 0).UTC()
	farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
)

// evaluation holds the merged occurrences of each governing source between
// now and now+horizon.
type evaluation struct {
	sources []Source
	ivs     [][]interval
	from    time.Time
	to      time.Time
}

func newEvaluation(sources []Source, now time.Time, horizon time.Duration) *evaluation {
	ev := &evaluation{sources: sources, from: now, to: now.Add(horizon)}
	ev.ivs = make([][]interval, len(sources))
	for i, s := range sources {
		ev.ivs[i] = s.intervals(ev.from, ev.to)
	}
	return ev
}

// intervals returns the merged occurrences of s overlapping [from, to).
func (s Source) intervals(from, to time.Time) []interval {
	if s.Broken {
		if s.Kind == KindBlackout {
			return []interval{{farPast, farFuture}}
		}
		return nil
	}
	var out []interval
	for _, sl := range s.Slots {
		out = append(out, sl.occurrences(from, to)...)
	}
	for _, o := range s.OneOffs {
		if o.EndsAt.After(from) && o.StartsAt.Before(to) {
			out = append(out, interval{o.StartsAt, o.EndsAt})
		}
	}
	return merge(out)
}

// occurrences lists the slot's occurrences overlapping [from, to). Each
// starts on a local date at Start and ends at End that day, or the next day
// when End <= Start; time.Date normalises a wall-clock time the clocks skip
// or repeat (Go picks one of the two offsets).
func (sl LocalSlot) occurrences(from, to time.Time) []interval {
	if sl.Loc == nil || len(sl.Days) == 0 {
		return nil
	}
	lf, lt := from.In(sl.Loc), to.In(sl.Loc)
	// Start one day early: an overnight occurrence that began yesterday.
	day := time.Date(lf.Year(), lf.Month(), lf.Day()-1, 12, 0, 0, 0, sl.Loc)
	last := time.Date(lt.Year(), lt.Month(), lt.Day(), 12, 0, 0, 0, sl.Loc)
	var out []interval
	for !day.After(last) {
		if slices.Contains(sl.Days, isoWeekday(day)) {
			y, m, d := day.Date()
			start := time.Date(y, m, d, sl.Start/60, sl.Start%60, 0, 0, sl.Loc)
			endDay := d
			if sl.End <= sl.Start {
				endDay = d + 1
			}
			end := time.Date(y, m, endDay, sl.End/60, sl.End%60, 0, 0, sl.Loc)
			if end.After(start) && end.After(from) && start.Before(to) {
				out = append(out, interval{start.UTC(), end.UTC()})
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return out
}

func isoWeekday(t time.Time) int {
	if wd := int(t.Weekday()); wd != 0 {
		return wd
	}
	return 7
}

// merge sorts intervals and joins the ones that overlap or touch.
func merge(in []interval) []interval {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].start.Before(in[j].start) })
	out := []interval{in[0]}
	for _, iv := range in[1:] {
		last := &out[len(out)-1]
		if !iv.start.After(last.end) {
			if iv.end.After(last.end) {
				last.end = iv.end
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// containing returns the interval of ivs containing t, if any.
func containing(ivs []interval, t time.Time) (interval, bool) {
	i := sort.Search(len(ivs), func(i int) bool { return ivs[i].end.After(t) })
	if i < len(ivs) && !ivs[i].start.After(t) {
		return ivs[i], true
	}
	return interval{}, false
}

// openAt reports whether the work may run at t.
func (ev *evaluation) openAt(t time.Time) bool {
	for i, s := range ev.sources {
		_, in := containing(ev.ivs[i], t)
		if s.Kind == KindAllow && !in {
			return false
		}
		if s.Kind == KindBlackout && in {
			return false
		}
	}
	return true
}

// next returns the first boundary after t (strictly) at which openAt equals
// want, within the evaluation's horizon.
func (ev *evaluation) next(t time.Time, want bool) *time.Time {
	var bounds []time.Time
	for _, ivs := range ev.ivs {
		for _, iv := range ivs {
			if iv.start.After(t) && !iv.start.After(ev.to) {
				bounds = append(bounds, iv.start)
			}
			if iv.end.After(t) && !iv.end.After(ev.to) {
				bounds = append(bounds, iv.end)
			}
		}
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i].Before(bounds[j]) })
	for i, b := range bounds {
		if i > 0 && b.Equal(bounds[i-1]) {
			continue
		}
		if ev.openAt(b) == want {
			v := b
			return &v
		}
	}
	return nil
}

// blocking reports whether source i blocks at now and until when.
func (ev *evaluation) blocking(i int, now time.Time) (bool, *time.Time) {
	s := ev.sources[i]
	iv, in := containing(ev.ivs[i], now)
	switch s.Kind {
	case KindAllow:
		if in {
			return false, nil
		}
		for _, x := range ev.ivs[i] {
			if x.start.After(now) {
				v := x.start
				return true, &v
			}
		}
		return true, nil
	case KindBlackout:
		if !in {
			return false, nil
		}
		if iv.end.Equal(farFuture) {
			return true, nil
		}
		v := iv.end
		return true, &v
	}
	return false, nil
}
