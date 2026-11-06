package component

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// ShortestPaths returns up to limit shortest paths (root first) that end at
// one of targets, walking parent links (up: child -> parents). A path stops
// at a link without parents or at maxDepth hops. Cycles are skipped.
func ShortestPaths(targets []string, up map[string][]string, maxDepth, limit int) [][]string {
	type item struct{ path []string }
	queue := make([]item, 0, len(targets))
	for _, t := range targets {
		queue = append(queue, item{path: []string{t}})
	}
	out := [][]string{}
	expansions := 0
	for len(queue) > 0 && len(out) < limit {
		it := queue[0]
		queue = queue[1:]
		head := it.path[0]
		parents := up[head]
		if len(parents) == 0 || len(it.path) > maxDepth {
			out = append(out, it.path)
			continue
		}
		for _, p := range parents {
			if contains(it.path, p) {
				continue
			}
			expansions++
			if expansions > MaxGraphNodes*MaxPaths {
				return out
			}
			next := make([]string, 0, len(it.path)+1)
			next = append(next, p)
			next = append(next, it.path...)
			queue = append(queue, item{path: next})
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Descend walks from roots along child links breadth-first, up to depth hops
// and limit nodes. It returns the visited ids, the edges among them and
// whether the bounds cut the walk short.
func Descend(roots []string, down map[string][]string, depth, limit int) ([]string, []GraphEdge, bool) {
	seen := map[string]int{}
	ids := []string{}
	queue := []string{}
	truncated := false
	for _, r := range roots {
		if _, ok := seen[r]; ok {
			continue
		}
		if len(ids) >= limit {
			truncated = true
			break
		}
		seen[r] = 0
		ids = append(ids, r)
		queue = append(queue, r)
	}
	edges := []GraphEdge{}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range down[n] {
			if _, ok := seen[c]; ok {
				edges = append(edges, GraphEdge{From: n, To: c})
				continue
			}
			if seen[n] >= depth || len(ids) >= limit {
				truncated = true
				continue
			}
			seen[c] = seen[n] + 1
			ids = append(ids, c)
			queue = append(queue, c)
			edges = append(edges, GraphEdge{From: n, To: c})
		}
	}
	return ids, edges, truncated
}

// Neighborhood returns the focus links, their ancestors and descendants up
// to depth hops each, bounded by limit nodes.
func Neighborhood(focus []string, down, up map[string][]string, depth, limit int) ([]string, []GraphEdge, bool) {
	seen := map[string]bool{}
	ids := []string{}
	truncated := false
	add := func(id string) bool {
		if seen[id] {
			return true
		}
		if len(ids) >= limit {
			truncated = true
			return false
		}
		seen[id] = true
		ids = append(ids, id)
		return true
	}
	for _, f := range focus {
		add(f)
	}
	walk := func(next map[string][]string) {
		frontier := append([]string(nil), focus...)
		for d := 0; d < depth && len(frontier) > 0; d++ {
			var nf []string
			for _, n := range frontier {
				for _, m := range next[n] {
					if !seen[m] && add(m) {
						nf = append(nf, m)
					}
				}
			}
			frontier = nf
		}
		if len(frontier) > 0 {
			for _, n := range frontier {
				for _, m := range next[n] {
					if !seen[m] {
						truncated = true
					}
				}
			}
		}
	}
	walk(up)
	walk(down)
	edges := []GraphEdge{}
	for _, p := range ids {
		for _, c := range down[p] {
			if seen[c] {
				edges = append(edges, GraphEdge{From: p, To: c})
			}
		}
	}
	return ids, edges, truncated
}

// versionParts splits a version into numeric and text runs for ordering.
func versionParts(v string) []string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var parts []string
	var cur strings.Builder
	digit := false
	flush := func() {
		if cur.Len() > 0 {
			parts = append(parts, cur.String())
			cur.Reset()
		}
	}
	for _, r := range v {
		switch {
		case r == '.' || r == '-' || r == '_' || r == '+':
			flush()
		case unicode.IsDigit(r):
			if !digit {
				flush()
			}
			digit = true
			cur.WriteRune(r)
		default:
			if digit {
				flush()
			}
			digit = false
			cur.WriteRune(r)
		}
	}
	flush()
	return parts
}

// CompareVersions orders two versions by their numeric and text runs (a
// best-effort comparison across schemes; a text run sorts before a number,
// so 1.0.0-rc1 < 1.0.0 is not guaranteed and not needed for advice).
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case ea == nil:
			return 1
		case eb == nil:
			return -1
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// SortVersions sorts and de-duplicates versions ascending.
func SortVersions(vs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		v = strings.TrimSpace(v)
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) < 0 })
	return out
}

// AdviseUpgrade picks the upgrade for a version with open findings from the
// fixed versions those findings list (several release lines may be listed):
// the highest fix on the current major line when one is above the current
// version, otherwise the nearest fix above it on a newer line (Breaking).
// Complete: no listed fix on the chosen line is above the pick.
func AdviseUpgrade(current string, fixed []string, hasOpen bool) *UpgradeAdvice {
	if !hasOpen || len(fixed) == 0 {
		return nil
	}
	var above []string
	for _, f := range SortVersions(fixed) {
		if CompareVersions(f, current) > 0 {
			above = append(above, f)
		}
	}
	if len(above) == 0 {
		return nil
	}
	major := majorOf(current)
	var same []string
	for _, f := range above {
		if majorOf(f) == major {
			same = append(same, f)
		}
	}
	if len(same) > 0 {
		return &UpgradeAdvice{Version: same[len(same)-1], Complete: true}
	}
	pick := above[0]
	complete := true
	for _, f := range above[1:] {
		if majorOf(f) == majorOf(pick) {
			complete = false
		}
	}
	return &UpgradeAdvice{Version: pick, Breaking: true, Complete: complete}
}

func majorOf(v string) string {
	for _, p := range versionParts(v) {
		if _, err := strconv.Atoi(p); err == nil {
			return strings.TrimLeft(p, "0")
		}
	}
	return ""
}
