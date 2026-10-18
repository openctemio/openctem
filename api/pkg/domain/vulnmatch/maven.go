package vulnmatch

import (
	"strings"
)

// Maven version ordering (the ComparableVersion algorithm). A version is a
// list of items: numbers, qualifiers and sub-lists; "-" and a change between
// digits and letters open a sub-list, "." separates items. Known qualifiers
// order alpha < beta < milestone < rc (= cr) < snapshot < release (= "", ga,
// final, release) < sp; unknown qualifiers sort after them, lexically.
// Trailing zeros and release qualifiers are dropped, so 1 = 1.0 = 1.0.0 =
// 1-ga.

type mavenKind int

const (
	mavenInt mavenKind = iota
	mavenString
	mavenList
)

type mavenItem struct {
	kind  mavenKind
	num   string // mavenInt: digits without leading zeros ("" is 0)
	qual  string // mavenString: comparable qualifier key
	items []*mavenItem
}

type mavenV struct{ root *mavenItem }

var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// mavenReleaseKey is the comparable key of the release qualifier "".
const mavenReleaseKey = "5"

func mavenQualifierKey(q string) string {
	for i, k := range mavenQualifiers {
		if q == k {
			return string(rune('0' + i))
		}
	}
	return "7-" + q
}

func newMavenString(s string, followedByDigit bool) *mavenItem {
	if followedByDigit && len(s) == 1 {
		switch s[0] {
		case 'a':
			s = "alpha"
		case 'b':
			s = "beta"
		case 'm':
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return &mavenItem{kind: mavenString, qual: mavenQualifierKey(s)}
}

func newMavenItem(isDigit bool, s string) *mavenItem {
	if isDigit {
		return &mavenItem{kind: mavenInt, num: strings.TrimLeft(s, "0")}
	}
	return newMavenString(s, false)
}

func (it *mavenItem) isNull() bool {
	switch it.kind {
	case mavenInt:
		return it.num == ""
	case mavenString:
		return it.qual == mavenReleaseKey
	}
	return len(it.items) == 0
}

func (it *mavenItem) add(c *mavenItem) { it.items = append(it.items, c) }

// normalize drops trailing null items, stopping at the first item that is
// neither null nor a list.
func (it *mavenItem) normalize() {
	for i := len(it.items) - 1; i >= 0; i-- {
		last := it.items[i]
		if last.isNull() {
			it.items = append(it.items[:i], it.items[i+1:]...)
		} else if last.kind != mavenList {
			break
		}
	}
}

//nolint:cyclop // the parser mirrors the reference algorithm one branch per character class
func parseMaven(s string) (schemeVersion, bool) {
	s = strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '.' && c != '-' && c != '_' && c != '+' {
			return nil, false
		}
	}
	root := &mavenItem{kind: mavenList}
	list := root
	stack := []*mavenItem{list}
	push := func() {
		n := &mavenItem{kind: mavenList}
		list.add(n)
		list = n
		stack = append(stack, n)
	}
	isDig := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if i == start {
				list.add(&mavenItem{kind: mavenInt})
			} else {
				list.add(newMavenItem(isDig, s[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.add(&mavenItem{kind: mavenInt})
			} else {
				list.add(newMavenItem(isDig, s[start:i]))
			}
			start = i + 1
			push()
		case isDigit(c):
			if !isDig && i > start {
				// "1.0.0.x1" sorts like "1.0.0-x1".
				if len(list.items) > 0 {
					push()
				}
				list.add(newMavenString(s[start:i], true))
				start = i
				push()
			}
			isDig = true
		default:
			if isDig && i > start {
				list.add(newMavenItem(true, s[start:i]))
				start = i
				push()
			}
			isDig = false
		}
	}
	if len(s) > start {
		if !isDig && len(list.items) > 0 {
			push()
		}
		list.add(newMavenItem(isDig, s[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	// A version must hold at least one number.
	if !strings.ContainsAny(s, "0123456789") {
		return nil, false
	}
	return mavenV{root: root}, true
}

func (a mavenV) cmp(o schemeVersion) int { return mavenCmp(a.root, o.(mavenV).root) }

// mavenCmp compares item a with item b; b may be nil (padding).
//
//nolint:cyclop // one case per pair of item kinds
func mavenCmp(a, b *mavenItem) int {
	switch a.kind {
	case mavenInt:
		if b == nil {
			if a.num == "" {
				return 0
			}
			return 1
		}
		switch b.kind {
		case mavenInt:
			return cmpDigits(a.num, b.num)
		default:
			return 1
		}
	case mavenString:
		if b == nil {
			return strings.Compare(a.qual, mavenReleaseKey)
		}
		switch b.kind {
		case mavenInt, mavenList:
			return -1
		default:
			return strings.Compare(a.qual, b.qual)
		}
	}
	// a is a list.
	if b == nil {
		if len(a.items) == 0 {
			return 0
		}
		return mavenCmp(a.items[0], nil)
	}
	switch b.kind {
	case mavenInt:
		return -1
	case mavenString:
		return 1
	}
	n := len(a.items)
	if len(b.items) > n {
		n = len(b.items)
	}
	for i := 0; i < n; i++ {
		var l, r *mavenItem
		if i < len(a.items) {
			l = a.items[i]
		}
		if i < len(b.items) {
			r = b.items[i]
		}
		var c int
		switch {
		case l == nil && r == nil:
			c = 0
		case l == nil:
			c = -mavenCmp(r, nil)
		default:
			c = mavenCmp(l, r)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}
