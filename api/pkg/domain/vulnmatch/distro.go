package vulnmatch

import (
	"strings"
)

// Distribution package versions: Debian (dpkg), RPM and Alpine (apk-tools).
//
// These compare the distribution's own version string. A distribution
// often backports a fix without changing the upstream part of the version,
// so comparing a distro version with an upstream range can call a fixed
// build affected; MatchVersion marks such results (ReasonBackportPossible).

// ---- deb: [epoch:]upstream[-revision], compared with dpkg's verrevcmp ----

type debV struct {
	epoch, upstream, revision string
}

func parseDeb(s string) (schemeVersion, bool) {
	var v debV
	if i := strings.IndexByte(s, ':'); i >= 0 {
		v.epoch = s[:i]
		if !allDigits(v.epoch) {
			return nil, false
		}
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.revision = s[i+1:]
		s = s[:i]
		if v.revision == "" {
			return nil, false
		}
	}
	v.upstream = s
	if v.upstream == "" || !isDigit(v.upstream[0]) {
		return nil, false
	}
	for i := 0; i < len(v.upstream); i++ {
		c := v.upstream[i]
		if !isAlnum(c) && !strings.ContainsRune(".+~-", rune(c)) {
			return nil, false
		}
	}
	for i := 0; i < len(v.revision); i++ {
		c := v.revision[i]
		if !isAlnum(c) && !strings.ContainsRune(".+~", rune(c)) {
			return nil, false
		}
	}
	if v.epoch == "" {
		v.epoch = "0"
	}
	return v, true
}

func (a debV) cmp(o schemeVersion) int {
	b := o.(debV)
	if c := cmpDigits(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := verrevcmp(a.upstream, b.upstream); c != 0 {
		return c
	}
	return verrevcmp(a.revision, b.revision)
}

// debOrder is dpkg's character order: "~" before the end of the string,
// the end before letters, letters before everything else.
func debOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

// verrevcmp is dpkg's comparison of an upstream version or a revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(a, i), debOrder(b, j)
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if first == 0 {
				first = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if first != 0 {
			return sign(first)
		}
	}
	return 0
}

// ---- rpm: [epoch:]version[-release], compared with rpmvercmp ----

type rpmV struct {
	epoch, version, release string
}

func parseRPM(s string) (schemeVersion, bool) {
	var v rpmV
	if i := strings.IndexByte(s, ':'); i >= 0 {
		v.epoch = s[:i]
		if !allDigits(v.epoch) {
			return nil, false
		}
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.release = s[i+1:]
		s = s[:i]
		if v.release == "" {
			return nil, false
		}
	}
	v.version = s
	if v.version == "" || !isAlnum(v.version[0]) || !strings.ContainsAny(v.version, "0123456789") {
		return nil, false
	}
	for _, part := range []string{v.version, v.release} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !isAlnum(c) && !strings.ContainsRune("._+~^", rune(c)) {
				return nil, false
			}
		}
	}
	if v.epoch == "" {
		v.epoch = "0"
	}
	return v, true
}

// cmp compares epoch, version, then release; a release missing on either
// side is not compared, so the bound "1.2.3" covers every build of 1.2.3.
func (a rpmV) cmp(o schemeVersion) int {
	b := o.(rpmV)
	if c := cmpDigits(a.epoch, b.epoch); c != 0 {
		return c
	}
	if c := rpmvercmp(a.version, b.version); c != 0 {
		return c
	}
	if a.release == "" || b.release == "" {
		return 0
	}
	return rpmvercmp(a.release, b.release)
}

// rpmvercmp is RPM's segment comparison, with "~" (sorts before anything,
// even the end) and "^" (sorts after the end, before anything else).
//
//nolint:cyclop,gocognit // mirrors the reference algorithm
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	sep := func(c byte) bool { return !isAlnum(c) && c != '~' && c != '^' }
	for i < len(a) || j < len(b) {
		for i < len(a) && sep(a[i]) {
			i++
		}
		for j < len(b) && sep(b[j]) {
			j++
		}
		at := func(s string, k int) byte {
			if k < len(s) {
				return s[k]
			}
			return 0
		}
		ca, cb := at(a, i), at(b, j)
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		if ca == '^' || cb == '^' {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case ca != '^':
				return 1
			case cb != '^':
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		if sj == j {
			// The segments are of different kinds: a number is newer.
			if isNum {
				return 1
			}
			return -1
		}
		x, y := a[si:i], b[sj:j]
		if isNum {
			if c := cmpDigits(x, y); c != 0 {
				return c
			}
			continue
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}

// ---- apk: number{.number}[letter]{_suffix[number]}[-rN] ----

// apkSuffixRank orders apk suffixes: pre-release suffixes below the plain
// release (0), post-release suffixes above it.
var apkSuffixRank = map[string]int{
	"alpha": -4, "beta": -3, "pre": -2, "rc": -1,
	"cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5,
}

type apkSuffix struct {
	rank int
	num  string
}

type apkV struct {
	nums     []string
	letter   byte
	suffixes []apkSuffix
	rev      string // "" when there is no -rN
}

//nolint:cyclop // one branch per part of the grammar
func parseAPK(s string) (schemeVersion, bool) {
	var v apkV
	if i := strings.LastIndex(s, "-r"); i >= 0 {
		v.rev = s[i+2:]
		if !allDigits(v.rev) {
			return nil, false
		}
		s = s[:i]
	}
	i := 0
	for {
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == i {
			return nil, false
		}
		v.nums = append(v.nums, s[i:j])
		i = j
		if i < len(s) && s[i] == '.' {
			i++
			continue
		}
		break
	}
	if i < len(s) && s[i] >= 'a' && s[i] <= 'z' {
		v.letter = s[i]
		i++
	}
	for i < len(s) {
		if s[i] != '_' {
			return nil, false
		}
		i++
		j := i
		for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
			j++
		}
		rank, ok := apkSuffixRank[s[i:j]]
		if !ok {
			return nil, false
		}
		k := j
		for k < len(s) && isDigit(s[k]) {
			k++
		}
		v.suffixes = append(v.suffixes, apkSuffix{rank: rank, num: s[j:k]})
		i = k
	}
	return v, true
}

// cmp orders numbers (a component after the first that starts with "0"
// compares as a decimal fraction, so 1.05 < 1.5; more components is newer),
// then the letter, then the suffixes, then the revision.
//
//nolint:cyclop // one step per part of the grammar
func (a apkV) cmp(o schemeVersion) int {
	b := o.(apkV)
	for i := 0; i < len(a.nums) && i < len(b.nums); i++ {
		x, y := a.nums[i], b.nums[i]
		var c int
		if i > 0 && (x[0] == '0' || y[0] == '0') {
			c = strings.Compare(strings.TrimRight(x, "0"), strings.TrimRight(y, "0"))
		} else {
			c = cmpDigits(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if c := cmpInt(len(a.nums), len(b.nums)); c != 0 {
		return c
	}
	if c := cmpInt(int(a.letter), int(b.letter)); c != 0 {
		return c
	}
	for i := 0; i < len(a.suffixes) || i < len(b.suffixes); i++ {
		var x, y apkSuffix
		if i < len(a.suffixes) {
			x = a.suffixes[i]
		}
		if i < len(b.suffixes) {
			y = b.suffixes[i]
		}
		if c := cmpInt(x.rank, y.rank); c != 0 {
			return c
		}
		if c := cmpDigits(x.num, y.num); c != 0 {
			return c
		}
	}
	switch {
	case a.rev == "" && b.rev == "":
		return 0
	case a.rev == "":
		return -1
	case b.rev == "":
		return 1
	}
	return cmpDigits(a.rev, b.rev)
}
