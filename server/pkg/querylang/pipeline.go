package querylang

import (
	"strconv"
	"strings"
)

// pipelineBuilder checks the stages and fills the plan's output shape.
// Order: an optional bucket, then at most one aggregation (count, count
// by or stats; a plain count when there is none), then top or sort, and
// limit.
type pipelineBuilder struct {
	p    *Plan
	ent  *Entity
	may  func(string) bool
	errs *errList
}

func (b *pipelineBuilder) build(stages []Stage) {
	if len(stages) > MaxStages {
		b.errs.add(stages[MaxStages].Span, "at most "+strconv.Itoa(MaxStages)+" stages")
		return
	}
	var agg, top, sorted, limited *Stage
	for i := range stages {
		st := &stages[i]
		switch st.Kind {
		case StageBucket:
			if agg != nil || top != nil || sorted != nil || limited != nil {
				b.errs.add(st.Span, "bucket comes before count or stats")
				continue
			}
			if b.p.Bucket != nil {
				b.errs.add(st.Span, "only one bucket")
				continue
			}
			b.bucket(st)
		case StageCount, StageStats:
			if agg != nil {
				b.errs.add(st.Span, "only one count or stats stage")
				continue
			}
			if top != nil || sorted != nil || limited != nil {
				b.errs.add(st.Span, "count and stats come before top, sort and limit")
				continue
			}
			agg = st
			b.aggregate(st)
		case StageTop:
			if top != nil || sorted != nil {
				b.errs.add(st.Span, "use one top or one sort")
				continue
			}
			top = st
		case StageSort:
			if top != nil || sorted != nil {
				b.errs.add(st.Span, "use one top or one sort")
				continue
			}
			sorted = st
		case StageLimit:
			if limited != nil {
				b.errs.add(st.Span, "only one limit")
				continue
			}
			limited = st
		}
	}
	if agg == nil {
		if (top != nil || sorted != nil || limited != nil) && b.p.Bucket == nil {
			s := firstOf(top, sorted, limited)
			b.errs.add(s.Span, "top, sort and limit need count by or stats ... by first (row lists come in a later version)")
			return
		}
		b.p.Aggs = append(b.p.Aggs, AggRef{Func: AggCount, Name: "count"})
	}
	b.columns()
	b.order(top, sorted)
	b.limit(top, limited)
}

func firstOf(ss ...*Stage) *Stage {
	var out *Stage
	for _, s := range ss {
		if s != nil && (out == nil || s.Span.Start < out.Span.Start) {
			out = s
		}
	}
	return out
}

func (b *pipelineBuilder) bucket(st *Stage) {
	f := b.ent.Time(st.Field.Name)
	if f == "" || !b.allowed(st.Field.Name) {
		b.errs.add(st.Field.Span, "cannot bucket by "+safePath(st.Field.Name)+" (time fields: "+strings.Join(b.ent.Times(), ", ")+")")
		return
	}
	b.p.Bucket = &BucketRef{Path: st.Field.Name, Field: f, Interval: st.Interval}
}

// allowed checks the path's registry field permission (and that it is not
// internal), as the filter does.
func (b *pipelineBuilder) allowed(path string) bool {
	_, ok := b.ent.field(path, b.may)
	return ok
}

func safePath(p string) string {
	if len(p) > 64 {
		return "this field"
	}
	return `"` + p + `"`
}

func (b *pipelineBuilder) aggregate(st *Stage) {
	seen := map[string]bool{}
	for _, p := range st.By {
		f := b.ent.Dimension(p.Name)
		if f == "" || !b.allowed(p.Name) {
			b.errs.add(p.Span, "cannot group by "+safePath(p.Name))
			continue
		}
		if seen[p.Name] {
			b.errs.add(p.Span, "grouped twice by "+safePath(p.Name))
			continue
		}
		seen[p.Name] = true
		b.p.Dims = append(b.p.Dims, DimRef{Path: p.Name, Field: f})
	}
	dims := len(b.p.Dims)
	if b.p.Bucket != nil {
		dims++
	}
	if dims > MaxDimensions {
		b.errs.add(st.Span, "at most "+strconv.Itoa(MaxDimensions)+" groups, a bucket included")
	}
	if st.Kind == StageCount {
		b.p.Aggs = append(b.p.Aggs, AggRef{Func: AggCount, Name: "count"})
		return
	}
	if len(st.Aggs) > MaxAggs {
		b.errs.add(st.Span, "at most "+strconv.Itoa(MaxAggs)+" aggregates")
		return
	}
	for _, a := range st.Aggs {
		ref := AggRef{Func: a.Func, Path: a.Field.Name}
		switch a.Func {
		case AggCount:
			if a.Field.Name != "" {
				b.errs.add(a.Field.Span, "count() takes no field (use distinct(field) for distinct values)")
				continue
			}
		case AggDistinct:
			ref.Field = b.ent.Dimension(a.Field.Name)
			if ref.Field == "" || !b.allowed(a.Field.Name) {
				b.errs.add(spanOr(a.Field.Span, a.Span), "distinct needs a field you can group by")
				continue
			}
		default:
			ref.Field = b.ent.Measure(a.Field.Name)
			if ref.Field == "" || !b.allowed(a.Field.Name) {
				b.errs.add(spanOr(a.Field.Span, a.Span), string(a.Func)+" needs a numeric field (one of: "+strings.Join(b.ent.Measures(), ", ")+")")
				continue
			}
		}
		ref.Name = a.As
		if ref.Name == "" {
			ref.Name = string(a.Func)
			if ref.Path != "" {
				ref.Name += "_" + strings.ReplaceAll(ref.Path, ".", "_")
			}
		}
		b.p.Aggs = append(b.p.Aggs, ref)
	}
}

func spanOr(s, def Span) Span {
	if s.End > s.Start {
		return s
	}
	return def
}

// columns fills the output columns and rejects duplicate names.
func (b *pipelineBuilder) columns() {
	seen := map[string]bool{}
	add := func(name string, kind ColumnKind) {
		if seen[name] {
			b.errs.add(Span{}, "two output columns are named "+safePath(name)+` (rename one with "as")`)
			return
		}
		seen[name] = true
		b.p.Columns = append(b.p.Columns, Column{Name: name, Kind: kind})
	}
	if b.p.Bucket != nil {
		add(b.p.Bucket.Path, ColumnTime)
	}
	for _, d := range b.p.Dims {
		add(d.Path, ColumnDimension)
	}
	for _, a := range b.p.Aggs {
		add(a.Name, ColumnMeasure)
	}
}

func (b *pipelineBuilder) column(p Path) (int, bool) {
	for i, c := range b.p.Columns {
		if c.Name == p.Name {
			return i, true
		}
	}
	names := make([]string, 0, len(b.p.Columns))
	for _, c := range b.p.Columns {
		names = append(names, c.Name)
	}
	b.errs.add(p.Span, "not an output column (one of: "+strings.Join(names, ", ")+")")
	return 0, false
}

func (b *pipelineBuilder) order(top, sorted *Stage) {
	nb := len(b.p.Columns) - len(b.p.Aggs) // bucket + dimensions
	switch {
	case top != nil:
		if i, ok := b.column(top.Keys[0].Name); ok {
			b.p.Order = append(b.p.Order, OrderRef{Column: i, Desc: true})
		}
	case sorted != nil:
		if len(sorted.Keys) > MaxSortKeys {
			b.errs.add(sorted.Span, "at most "+strconv.Itoa(MaxSortKeys)+" sort keys")
			return
		}
		for _, k := range sorted.Keys {
			if i, ok := b.column(k.Name); ok {
				b.p.Order = append(b.p.Order, OrderRef{Column: i, Desc: k.Desc})
			}
		}
	case b.p.Bucket != nil:
		b.p.Order = append(b.p.Order, OrderRef{Column: 0})
	case nb > 0:
		b.p.Order = append(b.p.Order, OrderRef{Column: nb, Desc: true})
	}
	// Ties break on the group columns, so results are deterministic.
	for i := 0; i < nb; i++ {
		dup := false
		for _, o := range b.p.Order {
			dup = dup || o.Column == i
		}
		if !dup {
			b.p.Order = append(b.p.Order, OrderRef{Column: i})
		}
	}
}

func (b *pipelineBuilder) limit(top, limited *Stage) {
	b.p.Limit = MaxGroups
	if top != nil {
		if top.N < 1 || top.N > MaxTop {
			b.errs.add(top.Span, "top takes 1 to "+strconv.Itoa(MaxTop))
			return
		}
		b.p.Limit = top.N
	}
	if limited != nil {
		if limited.N < 1 || limited.N > MaxGroups {
			b.errs.add(limited.Span, "limit takes 1 to "+strconv.Itoa(MaxGroups))
			return
		}
		b.p.Limit = min(b.p.Limit, limited.N)
	}
}
