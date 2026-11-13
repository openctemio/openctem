package contentpkg

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?/[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)
	// semverPattern is semantic version 2.0 without build metadata.
	semverPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)` +
		`(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?$`)
	// partialPattern is a version in a comparator: MAJOR, MAJOR.MINOR or a
	// full version.
	partialPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2}$`)
)

// ValidID reports whether id is <namespace>/<name>.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Version is a parsed semantic version.
type Version struct{ canon string }

// ParseVersion parses a semantic version without build metadata and at
// most 64 bytes.
func ParseVersion(s string) (Version, error) {
	if len(s) > 64 || !semverPattern.MatchString(s) {
		return Version{}, fmt.Errorf("%q is not a semantic version (MAJOR.MINOR.PATCH[-PRERELEASE])", clip(s))
	}
	return Version{canon: "v" + s}, nil
}

// String is the version without the "v" prefix.
func (v Version) String() string { return strings.TrimPrefix(v.canon, "v") }

// Compare returns -1, 0 or +1.
func (v Version) Compare(o Version) int { return semver.Compare(v.canon, o.canon) }

// Prerelease reports whether v has a pre-release part.
func (v Version) Prerelease() bool { return semver.Prerelease(v.canon) != "" }

// CompareVersions orders two version strings; an invalid one sorts first.
func CompareVersions(a, b string) int {
	va, ea := ParseVersion(a)
	vb, eb := ParseVersion(b)
	switch {
	case ea != nil && eb != nil:
		return strings.Compare(a, b)
	case ea != nil:
		return -1
	case eb != nil:
		return 1
	}
	return va.Compare(vb)
}

type comparator struct {
	op string
	v  Version
}

// Range is a conjunction of comparators.
type Range struct {
	raw string
	cs  []comparator
}

// String is the range as written.
func (r Range) String() string { return r.raw }

// ParseRange parses "OP VERSION[, OP VERSION]..." with OP one of =, >, >=,
// <, <=. A partial version (">=3", ">=1.2") is padded with zeros.
func ParseRange(s string) (Range, error) {
	if s == "" || len(s) > 128 {
		return Range{}, errors.New("a version range is required (at most 128 bytes)")
	}
	parts := strings.Split(s, ",")
	if len(parts) > 4 {
		return Range{}, errors.New("at most 4 comparators")
	}
	r := Range{raw: s}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		op := ""
		for _, o := range []string{">=", "<=", "=", ">", "<"} {
			if strings.HasPrefix(p, o) {
				op = o
				break
			}
		}
		if op == "" {
			return Range{}, fmt.Errorf("comparator %q needs =, >, >=, < or <=", clip(p))
		}
		vs := strings.TrimSpace(strings.TrimPrefix(p, op))
		v, err := ParseVersion(vs)
		if err != nil {
			if !partialPattern.MatchString(vs) {
				return Range{}, err
			}
			for strings.Count(vs, ".") < 2 {
				vs += ".0"
			}
			if v, err = ParseVersion(vs); err != nil {
				return Range{}, err
			}
		}
		r.cs = append(r.cs, comparator{op: op, v: v})
	}
	return r, nil
}

// Contains reports whether v satisfies every comparator. A pre-release
// satisfies the range only when a comparator names a pre-release of the
// same MAJOR.MINOR.PATCH.
func (r Range) Contains(v Version) bool {
	if len(r.cs) == 0 {
		return false
	}
	if v.Prerelease() {
		base := semver.Canonical(strings.SplitN(v.canon, "-", 2)[0])
		named := false
		for _, c := range r.cs {
			named = named || (c.v.Prerelease() && semver.Canonical(strings.SplitN(c.v.canon, "-", 2)[0]) == base)
		}
		if !named {
			return false
		}
	}
	for _, c := range r.cs {
		d := v.Compare(c.v)
		ok := false
		switch c.op {
		case "=":
			ok = d == 0
		case ">":
			ok = d > 0
		case ">=":
			ok = d >= 0
		case "<":
			ok = d < 0
		case "<=":
			ok = d <= 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// Satisfies reports whether version string v is in range string rng.
func Satisfies(rng, v string) (bool, error) {
	r, err := ParseRange(rng)
	if err != nil {
		return false, err
	}
	pv, err := ParseVersion(strings.TrimPrefix(v, "v"))
	if err != nil {
		return false, err
	}
	return r.Contains(pv), nil
}
