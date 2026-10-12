package sensor

import (
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// VersionStatus says how a sensor's version compares with the release channel
// the platform is configured with (SENSOR_LATEST_VERSION, SENSOR_MIN_VERSION).
type VersionStatus string

const (
	// VersionLatest: the newest release or newer.
	VersionLatest VersionStatus = "latest"
	// VersionUpdateAvailable: supported, but a newer release exists.
	VersionUpdateAvailable VersionStatus = "update_available"
	// VersionUnsupported: older than the minimum supported release.
	VersionUnsupported VersionStatus = "unsupported"
	// VersionUnknown: the sensor reported no version, or not a release
	// version (a dev build), or the platform has no release channel set.
	VersionUnknown VersionStatus = "unknown"
)

// MaxVersionLength caps a reported version string. The version comes from the
// sensor process and is display data only.
const MaxVersionLength = 64

// gitDescribeSuffix matches the "-<commits>-g<hash>[-dirty]" a build made with
// `git describe` appends to the tag it was built after.
var gitDescribeSuffix = regexp.MustCompile(`-\d+-g[0-9a-f]{4,40}(-dirty)?$`)

// NormalizeVersion gives a reported version one display form: a release
// version becomes canonical semver with a single "v" ("0.4.2", "v0.4.2" and
// "vv0.4.2" all become "v0.4.2"; "0.4" becomes "v0.4.0"; build metadata is
// dropped). Anything else ("dev") is returned trimmed, without control
// characters and capped at MaxVersionLength. Empty stays empty.
func NormalizeVersion(raw string) string {
	v := sanitizeVersion(raw)
	if v == "" {
		return ""
	}
	core := strings.TrimLeft(v, "vV")
	if c := semver.Canonical("v" + core); c != "" {
		return c
	}
	return v
}

// sanitizeVersion keeps printable ASCII, trims it and caps the length.
func sanitizeVersion(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c > 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	v := b.String()
	if len(v) > MaxVersionLength {
		v = v[:MaxVersionLength]
	}
	return v
}

// comparableVersion returns the semver form used for comparisons, or "" when
// v is not a release version. A git-describe build counts as the tag it was
// built after (it is newer than that tag, not a pre-release of it).
func comparableVersion(v string) string {
	n := NormalizeVersion(v)
	if !semver.IsValid(n) {
		return ""
	}
	if pre := semver.Prerelease(n); pre != "" && gitDescribeSuffix.MatchString(pre) {
		n = strings.TrimSuffix(n, pre)
	}
	return n
}

// ClassifyVersion compares a sensor version with the release channel. latest
// and minimum may be empty (not configured); a value that is not a release
// version is treated as not configured.
func ClassifyVersion(version, latest, minimum string) VersionStatus {
	v := comparableVersion(version)
	if v == "" {
		return VersionUnknown
	}
	if m := comparableVersion(minimum); m != "" && semver.Compare(v, m) < 0 {
		return VersionUnsupported
	}
	l := comparableVersion(latest)
	if l == "" {
		return VersionUnknown
	}
	if semver.Compare(v, l) < 0 {
		return VersionUpdateAvailable
	}
	return VersionLatest
}

// IsReleaseVersion reports whether v is a version the release channel can
// compare against (a semver release or pre-release).
func IsReleaseVersion(v string) bool {
	return comparableVersion(v) != ""
}

// CompareVersions orders two reported versions: release versions by semver,
// a release version above anything that is not one, and two non-release
// versions ("dev", "") by their text. It returns -1, 0 or +1.
func CompareVersions(a, b string) int {
	ca, cb := comparableVersion(a), comparableVersion(b)
	switch {
	case ca != "" && cb != "":
		return semver.Compare(ca, cb)
	case ca != "":
		return 1
	case cb != "":
		return -1
	}
	return strings.Compare(NormalizeVersion(a), NormalizeVersion(b))
}
