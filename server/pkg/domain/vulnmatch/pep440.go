package vulnmatch

import (
	"regexp"
	"strings"
)

// PEP 440 (Python package versions). The grammar is the specification's own
// permissive pattern, which accepts every spelling that normalises to a
// canonical version ("1.0.0-RC1" is "1.0.0rc1", "1.0-1" is "1.0.post1").
// Go regular expressions run in linear time.
var pep440Re = regexp.MustCompile(`^(?i)v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|a|b|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

var pep440Group = func() map[string]int {
	m := map[string]int{}
	for i, n := range pep440Re.SubexpNames() {
		if n != "" {
			m[n] = i
		}
	}
	return m
}()

// pep440V is a PEP 440 version in its ordering form.
type pep440V struct {
	epoch   string
	release []string // trailing zeros removed
	// preRank: 0 none, 1 a, 2 b, 3 rc.
	preRank int
	preN    string
	hasPost bool
	postN   string
	hasDev  bool
	devN    string
	local   []string // lower case
}

func parsePEP440(s string) (schemeVersion, bool) {
	m := pep440Re.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	g := func(n string) string { return m[pep440Group[n]] }
	v := pep440V{epoch: g("epoch")}
	if v.epoch == "" {
		v.epoch = "0"
	}
	rel := strings.Split(g("release"), ".")
	for len(rel) > 1 && strings.Trim(rel[len(rel)-1], "0") == "" {
		rel = rel[:len(rel)-1]
	}
	v.release = rel
	if g("pre") != "" {
		switch strings.ToLower(g("pre_l")) {
		case "a", "alpha":
			v.preRank = 1
		case "b", "beta":
			v.preRank = 2
		default: // c, rc, pre, preview
			v.preRank = 3
		}
		v.preN = zeroIfEmpty(g("pre_n"))
	}
	if g("post") != "" {
		v.hasPost = true
		v.postN = zeroIfEmpty(g("post_n1") + g("post_n2"))
	}
	if g("dev") != "" {
		v.hasDev = true
		v.devN = zeroIfEmpty(g("dev_n"))
	}
	if l := g("local"); l != "" {
		v.local = strings.FieldsFunc(strings.ToLower(l), func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	}
	return v, true
}

func zeroIfEmpty(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// cmp follows the PEP 440 ordering: epoch, release, then pre-release (a
// development release of a final version sorts before all its
// pre-releases), post-release, development release, local version.
func (a pep440V) cmp(o schemeVersion) int {
	b := o.(pep440V)
	if c := cmpDigits(a.epoch, b.epoch); c != 0 {
		return c
	}
	n := len(a.release)
	if len(b.release) > n {
		n = len(b.release)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := cmpDigits(x, y); c != 0 {
			return c
		}
	}
	if c := cmpInt(a.preKey(), b.preKey()); c != 0 {
		return c
	}
	if a.preRank != 0 && b.preRank != 0 {
		if c := cmpDigits(a.preN, b.preN); c != 0 {
			return c
		}
	}
	switch {
	case a.hasPost && b.hasPost:
		if c := cmpDigits(a.postN, b.postN); c != 0 {
			return c
		}
	case a.hasPost:
		return 1
	case b.hasPost:
		return -1
	}
	switch {
	case a.hasDev && b.hasDev:
		if c := cmpDigits(a.devN, b.devN); c != 0 {
			return c
		}
	case a.hasDev:
		return -1
	case b.hasDev:
		return 1
	}
	return cmpLocal(a.local, b.local)
}

// preKey places "X.devN" (no pre, no post) below every pre-release of X and
// a final release above them.
func (a pep440V) preKey() int {
	switch {
	case a.preRank != 0:
		return a.preRank
	case a.hasDev && !a.hasPost:
		return -1
	default:
		return 10
	}
}

// cmpLocal orders local version labels: none is lowest; segments compare
// pairwise, a numeric segment above an alphanumeric one, numbers
// numerically, strings lexically; a longer label wins on a tie.
func cmpLocal(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	case len(b) == 0:
		return 1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, bn := allDigits(a[i]), allDigits(b[i])
		var c int
		switch {
		case an && bn:
			c = cmpDigits(a[i], b[i])
		case an:
			c = 1
		case bn:
			c = -1
		default:
			c = strings.Compare(a[i], b[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}
