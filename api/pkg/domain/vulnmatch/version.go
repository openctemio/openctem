package vulnmatch

import (
	"strconv"
	"strings"
)

// Version is a product version split into comparable segments. Versions
// compare segment by segment: numbers numerically, a pre-release tag
// (dev, alpha, beta, pre, rc) before the release it precedes, any other
// letters (a patch letter such as "p1" in 8.2p1 or "w" in 1.1.1w) after it.
// A missing numeric segment counts as 0, so 1.0 equals 1.0.0.
type Version struct {
	raw  string
	segs []segment
}

type segment struct {
	num   uint64
	alpha string
	isNum bool
	pre   int // pre-release rank (1..5), 0 for a number or a patch letter
}

// preRelease ranks the pre-release tags; every rank is below the release.
var preRelease = map[string]int{
	"dev": 1, "snapshot": 1,
	"alpha": 2, "a": 2,
	"beta": 3, "b": 3,
	"pre": 4, "preview": 4,
	"rc": 5, "cr": 5,
}

// ParseVersion parses a product version. It refuses empty strings, strings
// longer than MaxVersionLen, characters other than letters, digits and
// . - _ + ~, and versions with more than 16 segments. A leading "v" is
// dropped. ok is false when the version cannot be compared; such a version
// never matches a range.
func ParseVersion(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > MaxVersionLen {
		return Version{}, false
	}
	t := strings.ToLower(s)
	if len(t) > 1 && t[0] == 'v' && t[1] >= '0' && t[1] <= '9' {
		t = t[1:]
	}
	if t[0] < '0' || t[0] > '9' {
		return Version{}, false
	}
	segs, ok := tokenize(t)
	if !ok {
		return Version{}, false
	}
	if len(segs) == 0 {
		return Version{}, false
	}
	// A pre-release word is a tag; the single letters "a" and "b" are a tag
	// only when a number follows (1.0a1, 2.0b3). A trailing letter is a
	// patch letter (OpenSSL 1.1.1a is after 1.1.1).
	for k := range segs {
		if segs[k].isNum {
			continue
		}
		r, ok := preRelease[segs[k].alpha]
		if !ok {
			continue
		}
		if len(segs[k].alpha) == 1 && (k+1 >= len(segs) || !segs[k+1].isNum) {
			continue
		}
		segs[k].pre = r
	}
	return Version{raw: s, segs: segs}, true
}

// tokenize splits a lower-case version into number and letter segments.
func tokenize(t string) ([]segment, bool) {
	var segs []segment
	for i := 0; i < len(t); {
		c := t[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(t) && t[j] >= '0' && t[j] <= '9' {
				j++
			}
			n, ok := parseNum(t[i:j])
			if !ok {
				return nil, false
			}
			segs = append(segs, segment{num: n, isNum: true})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(t) && t[j] >= 'a' && t[j] <= 'z' {
				j++
			}
			segs = append(segs, segment{alpha: t[i:j]})
			i = j
		case c == '.' || c == '-' || c == '_' || c == '+' || c == '~':
			i++
		default:
			return nil, false
		}
		if len(segs) > maxVersionParts {
			return nil, false
		}
	}
	return segs, true
}

func parseNum(d string) (uint64, bool) {
	d = strings.TrimLeft(d, "0")
	if d == "" {
		return 0, true
	}
	if len(d) > 18 {
		return 0, false
	}
	n, err := strconv.ParseUint(d, 10, 64)
	return n, err == nil
}

// String returns the version as it was given.
func (v Version) String() string { return v.raw }

// Segments is the number of segments, used to tell a partial version
// ("2.4") from a full one.
func (v Version) Segments() int { return len(v.segs) }

// Compare returns -1, 0 or 1 as v is lower than, equal to or higher than w.
func (v Version) Compare(w Version) int {
	n := len(v.segs)
	if len(w.segs) > n {
		n = len(w.segs)
	}
	for i := 0; i < n; i++ {
		a, aok := at(v.segs, i)
		b, bok := at(w.segs, i)
		switch {
		case aok && bok:
			if c := compareSeg(a, b); c != 0 {
				return c
			}
		case aok:
			if c := tail(a); c != 0 {
				return c
			}
		case bok:
			if c := tail(b); c != 0 {
				return -c
			}
		}
	}
	return 0
}

func at(s []segment, i int) (segment, bool) {
	if i < len(s) {
		return s[i], true
	}
	return segment{}, false
}

// tail is how an extra segment compares to "nothing more": a number above
// zero or a patch letter is higher, a pre-release tag is lower, a zero is
// equal.
func tail(s segment) int {
	if s.isNum {
		if s.num == 0 {
			return 0
		}
		return 1
	}
	if s.pre > 0 {
		return -1
	}
	return 1
}

func compareSeg(a, b segment) int {
	switch {
	case a.isNum && b.isNum:
		return cmpUint(a.num, b.num)
	case !a.isNum && !b.isNum:
		switch {
		case a.pre > 0 && b.pre > 0:
			return cmpInt(a.pre, b.pre)
		case a.pre > 0:
			return -1
		case b.pre > 0:
			return 1
		}
		return strings.Compare(a.alpha, b.alpha)
	case a.isNum:
		// 1.0.1 vs 1.0rc1: a number beats a pre-release tag; 1.0.1 vs
		// 1.0a (a patch letter on 1.0) also: the number starts a later
		// release.
		return 1
	default:
		return -1
	}
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Normalized is the canonical form of the version: lower case, segments
// joined by dots, leading zeros and trailing zero segments dropped
// ("v1.18.0" → "1.18", "8.2p1" → "8.2.p.1", "1.0rc1" → "1.0.~rc.1"). Two versions compare equal
// exactly when their canonical forms are equal, so it is the version's key
// in the catalog.
func (v Version) Normalized() string {
	n := len(v.segs)
	for n > 1 && v.segs[n-1].isNum && v.segs[n-1].num == 0 {
		n--
	}
	parts := make([]string, 0, n)
	for _, s := range v.segs[:n] {
		switch {
		case s.isNum:
			parts = append(parts, strconv.FormatUint(s.num, 10))
		case s.pre > 0:
			// A tag and a patch letter can be the same letter ("a"):
			// mark the tag so the two stay apart.
			parts = append(parts, "~"+s.alpha)
		default:
			parts = append(parts, s.alpha)
		}
	}
	return strings.Join(parts, ".")
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
