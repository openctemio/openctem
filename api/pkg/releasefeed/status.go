package releasefeed

import (
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Status is what a feed says about the running version, computed on the
// instance.
type Status struct {
	// Running is the running version as reported by the build.
	Running string `json:"running"`
	// Comparable is false when the running version is not a release
	// version (a local build without a tag): nothing else is computed.
	Comparable bool `json:"comparable"`
	// Latest is the newest release in the feed.
	Latest string `json:"latest,omitempty"`
	// UpdateAvailable: a release newer than the running one exists.
	UpdateAvailable bool `json:"update_available"`
	// Newer lists the releases newer than the running one, newest first.
	Newer []Release `json:"newer"`
	// Advisories lists the advisories that affect the running version,
	// most severe first.
	Advisories []Advisory `json:"advisories"`
	// Severity is the highest severity among Advisories ("" when none).
	Severity string `json:"severity,omitempty"`
	// FixedIn is the lowest version that fixes every advisory in
	// Advisories ("" when none).
	FixedIn string `json:"fixed_in,omitempty"`
	// Stale: the feed is past its expiry, so newer releases may be missing.
	Stale bool `json:"stale"`
}

// Compared returns the version the running build is compared as: a release
// or a release candidate as itself, a development build ("v1.2.3-dev",
// "v1.2.3-dev.4+abc") as its base release. ok is false when the version is
// not comparable.
func Compared(running string) (string, bool) {
	v := strings.TrimSpace(running)
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return "", false
	}
	v = semver.Canonical(v) // drops build metadata
	if pre := semver.Prerelease(v); strings.HasPrefix(pre, "-dev") {
		v = strings.TrimSuffix(v, pre)
	}
	return v, true
}

// Affects reports whether the advisory affects version v (canonical).
func (a Advisory) Affects(v string) bool {
	if a.Introduced != "" && semver.Compare(v, a.Introduced) < 0 {
		return false
	}
	return semver.Compare(v, a.FixedIn) < 0
}

// Evaluate compares the feed with the running version at now.
func Evaluate(f *Feed, running string, now time.Time) Status {
	st := Status{Running: running, Newer: []Release{}, Advisories: []Advisory{}}
	if f == nil {
		return st
	}
	st.Stale = !f.ExpiresAt.After(now)
	cur, ok := Compared(running)
	if !ok {
		return st
	}
	st.Comparable = true
	for _, r := range f.Releases {
		if st.Latest == "" || semver.Compare(r.Version, st.Latest) > 0 {
			st.Latest = r.Version
		}
		if semver.Compare(r.Version, cur) > 0 {
			st.Newer = append(st.Newer, r)
		}
	}
	slices.SortFunc(st.Newer, func(a, b Release) int { return semver.Compare(b.Version, a.Version) })
	st.UpdateAvailable = len(st.Newer) > 0
	for _, a := range f.Advisories {
		if !a.Affects(cur) {
			continue
		}
		st.Advisories = append(st.Advisories, a)
		if severityRank(a.Severity) > severityRank(st.Severity) {
			st.Severity = a.Severity
		}
		if semver.Compare(a.FixedIn, st.FixedIn) > 0 {
			st.FixedIn = a.FixedIn
		}
	}
	slices.SortStableFunc(st.Advisories, func(a, b Advisory) int {
		return severityRank(b.Severity) - severityRank(a.Severity)
	})
	return st
}

func severityRank(s string) int { return slices.Index(Severities, s) + 1 }
