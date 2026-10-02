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

// SDKStatus says how a sensor's SDK version compares with the SDK policy
// (SENSOR_SDK_MIN_VERSION, SENSOR_SDK_LATEST_VERSION).
type SDKStatus string

const (
	// SDKCurrent: at least the latest configured SDK (or no latest is set
	// and it meets the minimum).
	SDKCurrent SDKStatus = "current"
	// SDKOutdated: supported, but older than SENSOR_SDK_LATEST_VERSION.
	SDKOutdated SDKStatus = "outdated"
	// SDKUnsupported: older than SENSOR_SDK_MIN_VERSION.
	SDKUnsupported SDKStatus = "unsupported"
	// SDKUnknown: the sensor reported no SDK version.
	SDKUnknown SDKStatus = "unknown"
)

// AllSDKStatuses lists every SDK status (for stable breakdowns).
func AllSDKStatuses() []SDKStatus {
	return []SDKStatus{SDKCurrent, SDKOutdated, SDKUnsupported, SDKUnknown}
}

// ClassifySDK compares an SDK version with the SDK policy; latest and minimum
// may be empty (not configured).
func ClassifySDK(version, latest, minimum string) SDKStatus {
	v := comparableVersion(version)
	if v == "" {
		return SDKUnknown
	}
	if m := comparableVersion(minimum); m != "" && semver.Compare(v, m) < 0 {
		return SDKUnsupported
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
