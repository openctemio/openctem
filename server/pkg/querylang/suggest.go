package querylang

import (
	"sort"
	"strings"
)

// maxSuggestDistance is the edit distance within which a name is offered
// as "did you mean".
const maxSuggestDistance = 2

// SuggestFields returns the paths (and short names) the caller may use
// that are closest to name, within two edits, nearest first. Fields the
// caller may not use are never considered, so a forbidden field and a
// nonsense one get the same kind of answer.
func (e *Entity) SuggestFields(name string, may func(string) bool) []string {
	var names []string
	for _, f := range e.Registry.Fields() {
		p := e.pathOf(f.Name)
		if _, ok := e.field(p, may); ok {
			names = append(names, p)
		}
	}
	for a, p := range e.aliases {
		if _, ok := e.field(p, may); ok {
			names = append(names, a)
		}
	}
	return closest(name, names, 3)
}

// closest returns up to n candidates within maxSuggestDistance edits of s
// (or starting with it), nearest first, then alphabetical.
func closest(s string, candidates []string, n int) []string {
	type scored struct {
		name string
		d    int
	}
	var out []scored
	seen := map[string]bool{}
	for _, c := range candidates {
		lc := strings.ToLower(c)
		if seen[lc] || lc == s {
			continue
		}
		seen[lc] = true
		d := editDistance(s, lc, maxSuggestDistance)
		if d > maxSuggestDistance && (len(s) < 2 || !strings.HasPrefix(lc, s)) {
			continue
		}
		out = append(out, scored{c, d})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].d != out[j].d {
			return out[i].d < out[j].d
		}
		return out[i].name < out[j].name
	})
	res := make([]string, 0, min(n, len(out)))
	for i := 0; i < len(out) && i < n; i++ {
		res = append(res, out[i].name)
	}
	return res
}

// editDistance is the Levenshtein distance of a and b, or limit+1 once it
// is certainly above limit (inputs are short names).
func editDistance(a, b string, limit int) int {
	if len(a) > 64 || len(b) > 64 {
		return limit + 1
	}
	if d := len(a) - len(b); d > limit || -d > limit {
		return limit + 1
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
