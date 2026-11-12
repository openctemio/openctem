package sensor

// Build information: which sensor product, version, commit and SDK a sensor
// runs (docs/architecture/sensors.md "Build information"). A heartbeat may
// carry it as structured members (sdk: {name, version}, sensor: {name,
// version, commit, build_time}); sensors that do not are read from the
// User-Agent their SDK sends, "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0".
// Everything here comes from an untrusted process: it is display and policy
// data only, reduced to safe tokens before it is stored.

import (
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// BuildInfo is what a sensor reports about its own build. Empty fields are
// unknown.
type BuildInfo struct {
	// SDKName is the SDK the sensor is built with ("openctem-sdk-go").
	SDKName string
	// SDKVersion is the SDK version, normalized ("v0.9.0").
	SDKVersion string
	// Product is the sensor product ("openctemio-sensor"). The sensor's
	// version is Sensor.Version.
	Product string
	// Commit is the source commit of the sensor binary (hex, 7-40 chars).
	Commit string
	// BuildTime is when the sensor binary was built.
	BuildTime *time.Time
}

// DefaultProduct is the product of a sensor that reports none: the scanning
// sensor, the only product before sensors reported theirs. It equals
// versions.DefaultProductID (a test keeps them equal).
const DefaultProduct = "openctemio-sensor"

// ProductID is the sensor's product for the release-line lookup: the
// reported product, or DefaultProduct when it reported none. Like all build
// information it is the sensor's own claim: it chooses which release line
// the sensor is compared with (display and health reasons), never what it
// may do.
func (b BuildInfo) ProductID() string {
	if b.Product == "" {
		return DefaultProduct
	}
	return b.Product
}

// IsEmpty reports whether nothing is known.
func (b BuildInfo) IsEmpty() bool {
	return b.SDKName == "" && b.SDKVersion == "" && b.Product == "" && b.Commit == "" && b.BuildTime == nil
}

// BuildReport is the build information a heartbeat carried, not yet trusted.
type BuildReport struct {
	SDKName       string
	SDKVersion    string
	SensorName    string
	SensorVersion string
	Commit        string
	BuildTime     string
}

// Limits on reported build information.
const (
	maxBuildNameLen = 64
	maxCommitLen    = 40
)

var (
	buildNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	commitRE    = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
)

// sdkTokenPrefix marks an SDK product token in a User-Agent
// ("openctem-sdk-go", a future "openctem-sdk-python").
const sdkTokenPrefix = "openctem-sdk"

// ResolveBuild turns what a heartbeat carried into build information and the
// sensor version: the structured members win, and each part they leave empty
// is taken from the User-Agent. version is the heartbeat's top-level version
// member, which stays the sensor version when present. now bounds the build
// time (no later than a day after now).
func ResolveBuild(rep BuildReport, version, userAgent string, now time.Time) (BuildInfo, string) {
	ua := parseUserAgent(userAgent)
	out := BuildInfo{
		SDKName:    sanitizeBuildName(rep.SDKName),
		SDKVersion: sanitizeBuildVersion(rep.SDKVersion),
		Product:    sanitizeBuildName(rep.SensorName),
		Commit:     sanitizeCommit(rep.Commit),
		BuildTime:  parseBuildTime(rep.BuildTime, now),
	}
	if out.SDKName == "" && out.SDKVersion == "" {
		out.SDKName, out.SDKVersion = ua.sdkName, ua.sdkVersion
	}
	if out.Product == "" {
		out.Product = ua.product
	}

	sensorVersion := strings.TrimSpace(version)
	if sensorVersion == "" {
		sensorVersion = sanitizeBuildVersion(rep.SensorVersion)
	}
	if sensorVersion == "" && ua.product != "" && (out.Product == "" || out.Product == ua.product) {
		sensorVersion = ua.productVersion
	}
	return out, sensorVersion
}

type userAgentBuild struct {
	sdkName, sdkVersion     string
	product, productVersion string
}

// parseUserAgent reads the product tokens of a User-Agent: the first
// "openctem-sdk*/<version>" token is the SDK, the first other token naming
// a product with a release version is the sensor. The generic "sdk/1.0" the
// SDK sent before it named itself, and HTTP library tokens, carry no
// information and are skipped.
func parseUserAgent(ua string) userAgentBuild {
	var out userAgentBuild
	for _, tok := range strings.Fields(SanitizeUserAgent(ua)) {
		name, ver, ok := strings.Cut(tok, "/")
		if !ok {
			continue
		}
		name = sanitizeBuildName(strings.ToLower(name))
		ver = sanitizeBuildVersion(ver)
		if name == "" || ver == "" {
			continue
		}
		switch {
		case strings.HasPrefix(name, sdkTokenPrefix):
			if out.sdkName == "" {
				out.sdkName, out.sdkVersion = name, ver
			}
		case name == "sdk", name == "go-http-client", name == "curl", name == "mozilla":
			continue
		default:
			if out.product == "" && IsReleaseVersion(ver) {
				out.product, out.productVersion = name, ver
			}
		}
	}
	return out
}

func sanitizeBuildName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > maxBuildNameLen || !buildNameRE.MatchString(s) {
		return ""
	}
	return s
}

// sanitizeBuildVersion normalizes a release version and refuses anything
// else: an SDK or sensor version that is not a version is unknown.
func sanitizeBuildVersion(v string) string {
	n := NormalizeVersion(v)
	if !semver.IsValid(n) {
		return ""
	}
	return n
}

func sanitizeCommit(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > maxCommitLen || !commitRE.MatchString(s) {
		return ""
	}
	return s
}

func parseBuildTime(s string, now time.Time) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() < 2000 || t.After(now.Add(24*time.Hour)) {
		return nil
	}
	t = t.UTC()
	return &t
}

// SDKStatus says how a sensor's SDK version compares with the platform's SDK
// policy: the platform-owned floor and advisories of versions.yaml (sdk.min,
// sdk.advisories) and the latest SDK release (learned from the release feed).
// "outdated" is informational; an advisory and a release below the floor
// degrade the sensor. It applies to every sensor product, first-party or a
// tenant's own, built with sdk-go (docs/rfcs/RFC-037 §13).
type SDKStatus string

// SDKGoName is the SDK name sdk-go reports. Only a sensor built with it (or
// one that reports no SDK name: SDKs before names were reported) is compared
// with sdk-go's releases.
const SDKGoName = "openctem-sdk-go"

const (
	// SDKCurrent: at least the latest SDK (or no latest is set).
	SDKCurrent SDKStatus = "current"
	// SDKOutdated: older than sdk.latest (no health effect).
	SDKOutdated SDKStatus = "outdated"
	// SDKAdvisory: a release listed in sdk.advisories (a published security
	// advisory); the sensor is degraded with a warning.
	SDKAdvisory SDKStatus = "advisory"
	// SDKUnsupported: older than sdk.min, the oldest SDK the platform's
	// protocol supports; the sensor is degraded until it is rebuilt.
	SDKUnsupported SDKStatus = "unsupported"
	// SDKUnknown: the sensor reported no SDK version, or was built with
	// another SDK than sdk-go.
	SDKUnknown SDKStatus = "unknown"
)

// AllSDKStatuses lists every SDK status (for stable breakdowns).
func AllSDKStatuses() []SDKStatus {
	return []SDKStatus{SDKCurrent, SDKOutdated, SDKAdvisory, SDKUnsupported, SDKUnknown}
}

// SDKStatusFor classifies the sensor's SDK (BuildInfo) against the platform's
// SDK policy; a sensor built with another SDK than sdk-go is unknown.
func (b BuildInfo) SDKStatusFor(latest, minimum string, advisories []string) SDKStatus {
	if b.SDKName != "" && b.SDKName != SDKGoName {
		return SDKUnknown
	}
	return ClassifySDK(b.SDKVersion, latest, minimum, advisories)
}

// ClassifySDK compares an SDK version with the oldest supported SDK, the
// releases with an advisory and the latest SDK; latest and minimum may be
// empty (not set). Below the minimum wins over an advisory.
func ClassifySDK(version, latest, minimum string, advisories []string) SDKStatus {
	v := comparableVersion(version)
	if v == "" {
		return SDKUnknown
	}
	if m := comparableVersion(minimum); m != "" && semver.Compare(v, m) < 0 {
		return SDKUnsupported
	}
	for _, a := range advisories {
		// Exact release match: a git-describe build after an advised tag
		// carries the tag's code plus later commits, so it counts as the tag.
		if c := comparableVersion(a); c != "" && semver.Compare(v, c) == 0 {
			return SDKAdvisory
		}
	}
	if l := comparableVersion(latest); l != "" && semver.Compare(v, l) < 0 {
		return SDKOutdated
	}
	return SDKCurrent
}

// VersionDirection says which way a version moved: "upgrade", "downgrade",
// or "changed" when either side is not a release version.
func VersionDirection(from, to string) string {
	f, t := comparableVersion(from), comparableVersion(to)
	if f == "" || t == "" {
		return "changed"
	}
	switch semver.Compare(t, f) {
	case 1:
		return "upgrade"
	case -1:
		return "downgrade"
	default:
		return "changed"
	}
}
