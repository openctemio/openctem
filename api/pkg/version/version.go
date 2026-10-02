// Package version reports which build of the API is running.
//
// Release builds set Version, Commit and BuildTime with -ldflags, from the tag
// (Dockerfile + docker-publish.yml):
//
//	-X github.com/openctemio/openctem/api/pkg/version.Version=v0.9.0
//	-X github.com/openctemio/openctem/api/pkg/version.Commit=<sha>
//	-X github.com/openctemio/openctem/api/pkg/version.BuildTime=2026-10-02T10:00:00Z
//
// The dev container's air build passes "<highest tag>-dev" and the short HEAD
// (.air.toml). A binary built with none of them (go run, an air config from
// before the ldflags, a local go build) falls back to the git metadata of the
// checkout it runs in, read from the filesystem (see gitinfo.go), so a dev
// deployment still says which commit it is.
package version

import (
	"os"
	"regexp"
	"strings"
	"sync"
)

// Set with -ldflags -X. Empty means "not set by the build".
var (
	Version   = ""
	Commit    = ""
	BuildTime = ""
)

const (
	// ChannelRelease is a build of a release tag.
	ChannelRelease = "release"
	// ChannelDevelopment is any other build (dev container, local build).
	ChannelDevelopment = "development"

	// DevVersion is reported when neither the build nor the checkout names a version.
	DevVersion = "dev"
	// UnknownCommit is reported when the commit cannot be determined.
	UnknownCommit = "unknown"

	shortSHALen = 8
)

// Info is the build identity served by GET /api/v1/version.
type Info struct {
	Version   string `json:"version" example:"v0.9.0"`
	Commit    string `json:"commit" example:"4d2f4b02"`
	BuildTime string `json:"build_time,omitempty" example:"2026-10-02T10:00:00Z"`
	Channel   string `json:"channel" example:"release" enums:"release,development"`
}

// releaseVersion matches a release tag: v1.2.3, optionally with a pre-release
// suffix (v1.2.3-rc.1, v1.2.3-staging). "-dev" builds are not releases.
var releaseVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

var (
	fallbackOnce sync.Once
	fallback     Info
)

// Get returns the running build's identity. Values set at build time win; the
// checkout's git metadata is read once, only when the build set no version.
func Get() Info {
	v := strings.TrimSpace(Version)
	c := strings.TrimSpace(Commit)
	if v == "" {
		fallbackOnce.Do(func() {
			wd, err := os.Getwd()
			if err != nil {
				fallback = Info{Version: DevVersion, Commit: UnknownCommit}
				return
			}
			fallback = fromCheckout(wd)
		})
		v = fallback.Version
		if c == "" {
			c = fallback.Commit
		}
	}
	return build(v, c, strings.TrimSpace(BuildTime))
}

func build(v, c, t string) Info {
	if v == "" {
		v = DevVersion
	}
	if c == "" {
		c = UnknownCommit
	}
	if len(c) > shortSHALen && isHex(c) {
		c = c[:shortSHALen]
	}
	return Info{Version: v, Commit: c, BuildTime: t, Channel: channelOf(v)}
}

func channelOf(v string) string {
	if releaseVersion.MatchString(v) && !strings.HasSuffix(v, "-dev") {
		return ChannelRelease
	}
	return ChannelDevelopment
}

// fromCheckout derives "<highest tag>-dev" and the short HEAD from the git
// checkout containing dir. It never fails: missing data becomes dev/unknown.
func fromCheckout(dir string) Info {
	g, ok := ReadGit(dir)
	if !ok {
		return Info{Version: DevVersion, Commit: UnknownCommit}
	}
	v := DevVersion
	if g.LatestTag != "" {
		v = g.LatestTag + "-dev"
	}
	c := UnknownCommit
	if g.Head != "" {
		c = g.Head
	}
	return Info{Version: v, Commit: c}
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
