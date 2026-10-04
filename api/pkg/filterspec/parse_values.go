package filterspec

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Reserved param names read outside the filter.
const (
	paramPage    = "page"
	paramPerPage = "per_page"
	paramCursor  = "cursor"
)

// UnknownMode says what to do with a param the registry does not know.
type UnknownMode int

const (
	// UnknownWarn ignores the param and records it in Spec.UnknownParams,
	// for the one-release log-count-deprecate window (RFC-048 §3.8).
	UnknownWarn UnknownMode = iota
	// UnknownStrict rejects the request with INVALID_FILTER.
	UnknownStrict
)

// Options tune a parse. The zero value is warn mode, MaxOffset 10,000,
// per_page capped at 100.
type Options struct {
	Unknown UnknownMode
	// Extra are params the endpoint reads itself (group_by, count_by, tab):
	// neither filters nor unknown.
	Extra []string
	// Now is the clock for relative times (default time.Now).
	Now func() time.Time
	// MaxPerPage clamps per_page (default 100). MaxOffset bounds
	// page × per_page (default DefaultMaxOffset; negative disables).
	MaxPerPage int
	MaxOffset  int
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o Options) maxPerPage() int {
	if o.MaxPerPage > 0 {
		return o.MaxPerPage
	}
	return 100
}

func (o Options) isExtra(name string) bool {
	for _, e := range o.Extra {
		if e == name {
			return true
		}
	}
	return false
}

// ParseValues decodes flat GET params. Every param is ANDed; a comma list (or
// repeated key) is OR within one field.
func ParseValues(q url.Values, reg *Registry, opts Options) (*Spec, error) {
	spec := &Spec{}
	var e errs
	now := opts.now()

	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)

	leaves := make([]*Node, 0, len(names))
	for _, name := range names {
		vals := q[name]
		if opts.isExtra(name) {
			continue
		}
		target, values := name, vals
		if a, ok := reg.Aliases[name]; ok {
			target = a.To
			spec.AliasesUsed = append(spec.AliasesUsed, AliasUse{Old: name, New: a.To})
			if a.Value != nil {
				values = make([]string, 0, len(vals))
				for _, v := range vals {
					if nv, keep := a.Value(v); keep {
						values = append(values, nv)
					}
				}
				if len(values) == 0 {
					continue
				}
			}
		}
		switch target {
		case "q":
			parseQ(spec, &e, name, values)
			continue
		case "sort":
			parseSortParam(spec, reg, &e, name, values)
			continue
		case paramPage, paramPerPage, paramCursor, "fields", "view":
			parsePaging(spec, &e, target, values, opts)
			continue
		}
		f, op, err := reg.resolveParam(target)
		if err != nil {
			if opts.Unknown == UnknownStrict {
				e.param(name, "unknown parameter", "", true)
			} else {
				spec.UnknownParams = append(spec.UnknownParams, name)
			}
			continue
		}
		raw := splitValues(f, op, values)
		if len(raw) == 0 {
			continue // "severity=" means no filter, as before
		}
		leaf, ok := buildLeaf(f, op, raw, f.MaxValues, now, func(reason, v string) {
			e.param(name, reason, v, f.FreeText)
		})
		if !ok {
			continue
		}
		leaf.src = name
		leaves = append(leaves, &Node{Leaf: leaf})
	}
	if len(leaves) > MaxLeaves {
		e.param("filter", "too many filter params", "", true)
	}
	checkOffset(spec, &e, opts)
	if err := e.err(); err != nil {
		return nil, err
	}
	if len(leaves) > 0 {
		spec.Root = &Node{All: leaves}
	}
	return spec, nil
}

// splitValues merges repeated keys and splits comma lists. Free-text
// values are never split; empty items are dropped.
func splitValues(f *Field, op Op, vals []string) []string {
	out := make([]string, 0, len(vals))
	single := f.FreeText || op == OpContains || op == OpIsNull
	for _, v := range vals {
		if single {
			if strings.TrimSpace(v) != "" {
				out = append(out, v)
			}
			continue
		}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// buildLeaf validates raw textual values for (field, op) and returns a leaf.
func buildLeaf(f *Field, op Op, raw []string, maxValues int, now time.Time, fail func(reason, v string)) (*Leaf, bool) {
	multi := op == OpIn || op == OpNotIn
	if !multi && len(raw) != 1 {
		fail("takes exactly one value", "")
		return nil, false
	}
	if len(raw) > maxValues {
		fail("too many values (max "+strconv.Itoa(maxValues)+")", "")
		return nil, false
	}
	leaf := &Leaf{Field: f.Name, Op: op, Values: make([]any, 0, len(raw))}
	seen := make(map[any]bool, len(raw))
	ok := true
	for _, r := range raw {
		var v any
		var err error
		switch op {
		case OpIsNull:
			v, err = parseScalar(&Field{Type: TypeBool}, r, now, false)
		case OpContains:
			if err = checkText(r, MaxValueLen); err == nil {
				v = r
			}
		default:
			v, err = parseScalar(f, r, now, op == OpLte)
		}
		if err != nil {
			fail(err.Error(), r)
			ok = false
			continue
		}
		key := v
		if t, isTime := v.(time.Time); isTime {
			key = t.UnixNano()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		leaf.Values = append(leaf.Values, v)
	}
	return leaf, ok
}

func parseQ(spec *Spec, e *errs, name string, vals []string) {
	if len(vals) != 1 {
		e.param(name, "takes exactly one value", "", true)
		return
	}
	v := strings.TrimSpace(vals[0])
	if err := checkText(v, MaxQLen); err != nil {
		e.param(name, err.Error(), "", true)
		return
	}
	spec.Q = v
}

func parseSortParam(spec *Spec, reg *Registry, e *errs, name string, vals []string) {
	keys := make([]string, 0, 4)
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				keys = append(keys, p)
			}
		}
	}
	sk, reasons := parseSortKeys(reg, keys)
	for _, r := range reasons {
		e.param(name, r.reason, r.value, false)
	}
	spec.Sort = sk
}

type sortProblem struct{ reason, value string }

func parseSortKeys(reg *Registry, keys []string) ([]SortKey, []sortProblem) {
	if len(keys) > MaxSortKeys {
		return nil, []sortProblem{{reason: "too many sort keys (max " + strconv.Itoa(MaxSortKeys) + ")"}}
	}
	out := make([]SortKey, 0, len(keys))
	var probs []sortProblem
	seen := map[string]bool{}
	for _, k := range keys {
		desc := false
		switch {
		case strings.HasPrefix(k, "-"):
			desc, k = true, k[1:]
		case strings.HasPrefix(k, "+"):
			k = k[1:]
		}
		f, ok := reg.fields[k]
		if !ok || !f.Sortable {
			probs = append(probs, sortProblem{reason: "not a sortable field", value: safeName(k)})
			continue
		}
		if seen[k] {
			probs = append(probs, sortProblem{reason: "sort key repeated", value: k})
			continue
		}
		seen[k] = true
		out = append(out, SortKey{Field: k, Desc: desc})
	}
	return out, probs
}

func parsePaging(spec *Spec, e *errs, name string, vals []string, opts Options) {
	switch name {
	case paramCursor, "fields", "view":
		// Read by the endpoint (cursor, view) or reserved for later (fields).
		return
	}
	if len(vals) != 1 {
		e.param(name, "takes exactly one value", "", false)
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(vals[0]))
	if err != nil || n < 1 {
		e.param(name, "must be a positive integer", vals[0], false)
		return
	}
	if name == paramPage {
		spec.Page = n
		return
	}
	spec.PerPage = min(n, opts.maxPerPage())
}

func checkOffset(spec *Spec, e *errs, opts Options) {
	maxOff := opts.MaxOffset
	if maxOff == 0 {
		maxOff = DefaultMaxOffset
	}
	if maxOff < 0 || spec.Page <= 1 {
		return
	}
	per := spec.PerPage
	if per == 0 {
		per = 20
	}
	if int64(spec.Page-1)*int64(per) >= int64(maxOff) {
		e.param(paramPage, "page is too deep; narrow the filter or use a cursor", "", false)
	}
}
