package vulnmatch

// Scheme-aware version comparison (RFC-066 §5.1; identifier spec §9.2).
//
// Each scheme compares versions the way its ecosystem does. A version or a
// range bound that does not parse under its scheme compares with nothing:
// the matcher then reports no match for it, never a guessed one.

import (
	"strings"
)

// MaxSchemeVersionLen caps a version string handed to a scheme comparator.
// Every comparator runs in time linear in the input, and this cap bounds it.
const MaxSchemeVersionLen = 128

// SchemeVersion is a version parsed under one scheme. Two values compare
// only when their schemes are the same.
type SchemeVersion struct {
	scheme Scheme
	raw    string
	v      schemeVersion
}

// schemeVersion is one scheme's parsed form; cmp is called only with a
// value of the same concrete type.
type schemeVersion interface {
	cmp(other schemeVersion) int
}

// genericVersion adapts the generic Version.
type genericVersion struct{ v Version }

func (g genericVersion) cmp(o schemeVersion) int { return g.v.Compare(o.(genericVersion).v) }

// ParseSchemeVersion parses raw under scheme s. ok is false when the scheme
// has no comparator, or the string is empty, too long, or not a version of
// that scheme.
func ParseSchemeVersion(s Scheme, raw string) (SchemeVersion, bool) {
	t := strings.TrimSpace(raw)
	if t == "" || len(t) > MaxSchemeVersionLen {
		return SchemeVersion{}, false
	}
	var (
		v  schemeVersion
		ok bool
	)
	switch s {
	case SchemeGeneric:
		var g Version
		g, ok = ParseVersion(t)
		v = genericVersion{g}
	case SchemeSemver, SchemeNPM, SchemeGo:
		v, ok = parseSemver(t)
	case SchemePEP440:
		v, ok = parsePEP440(t)
	case SchemeMaven:
		v, ok = parseMaven(t)
	case SchemeDeb:
		v, ok = parseDeb(t)
	case SchemeRPM:
		v, ok = parseRPM(t)
	case SchemeAPK:
		v, ok = parseAPK(t)
	}
	if !ok {
		return SchemeVersion{}, false
	}
	return SchemeVersion{scheme: s, raw: t, v: v}, true
}

// Scheme is the scheme the version was parsed under.
func (v SchemeVersion) Scheme() Scheme { return v.scheme }

// String returns the version as it was given (trimmed).
func (v SchemeVersion) String() string { return v.raw }

// Compare returns -1, 0 or 1 as v is lower than, equal to or higher than w.
// ok is false when the two were parsed under different schemes (or either
// is the zero value): such versions have no order.
func (v SchemeVersion) Compare(w SchemeVersion) (c int, ok bool) {
	if v.v == nil || w.v == nil || v.scheme != w.scheme {
		return 0, false
	}
	return sign(v.v.cmp(w.v)), true
}

// CompareVersions parses a and b under scheme s and compares them. ok is
// false when either does not parse.
func CompareVersions(s Scheme, a, b string) (int, bool) {
	va, ok := ParseSchemeVersion(s, a)
	if !ok {
		return 0, false
	}
	vb, ok := ParseSchemeVersion(s, b)
	if !ok {
		return 0, false
	}
	return va.Compare(vb)
}

// IsDistro reports whether the scheme is a distribution package scheme.
// Distributions backport fixes without changing the upstream version, so an
// upstream range can call a fixed distro build affected.
func (s Scheme) IsDistro() bool { return s == SchemeDeb || s == SchemeRPM || s == SchemeAPK }

func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	}
	return 0
}

// cmpDigits compares two runs of ASCII digits numerically, at any length.
func cmpDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isAlpha(c) || isDigit(c) }

// ---- semver (SemVer 2.0.0), npm (node-semver) and Go module versions ----

// semverV is a SemVer 2.0.0 version. The core may have one to four numeric
// parts (missing parts count as 0, so "2.0" equals "2.0.0"; NuGet versions
// carry a fourth). Build metadata ("+incompatible", "+build.5") is ignored
// for ordering, as SemVer requires. A leading "v" or "=" is accepted (Go
// module versions always carry "v"; node-semver tolerates both). A Go
// pseudo-version is a pre-release of its base and orders correctly as such.
type semverV struct {
	core [4]string
	pre  []string
}

func parseSemver(s string) (schemeVersion, bool) {
	s = strings.TrimPrefix(s, "=")
	if s != "" && (s[0] == 'v' || s[0] == 'V') {
		s = s[1:]
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !semverIdents(s[i+1:]) {
			return nil, false
		}
		s = s[:i]
	}
	var v semverV
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core = s[:i]
		pre := s[i+1:]
		if !semverIdents(pre) {
			return nil, false
		}
		v.pre = strings.Split(pre, ".")
	}
	parts := strings.Split(core, ".")
	if len(parts) > 4 {
		return nil, false
	}
	for i := range v.core {
		v.core[i] = "0"
	}
	for i, p := range parts {
		if !allDigits(p) {
			return nil, false
		}
		v.core[i] = p
	}
	return v, true
}

// semverIdents validates dot-separated identifiers of [0-9A-Za-z-].
func semverIdents(s string) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			if !isAlnum(id[i]) && id[i] != '-' {
				return false
			}
		}
	}
	return true
}

func (a semverV) cmp(o schemeVersion) int {
	b := o.(semverV)
	for i := range a.core {
		if c := cmpDigits(a.core[i], b.core[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := allDigits(x), allDigits(y)
		var c int
		switch {
		case xn && yn:
			c = cmpDigits(x, y)
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmpInt(len(a.pre), len(b.pre))
}
