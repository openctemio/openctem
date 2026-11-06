package sensor

import (
	"strings"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"0.4.2", "v0.4.2"},
		{"v0.4.2", "v0.4.2"},
		{"V0.4.2", "v0.4.2"},
		{" v0.4.2\n", "v0.4.2"},
		{"vv0.4.2", "v0.4.2"}, // the double prefix some builds reported
		{"0.4", "v0.4.0"},
		{"1", "v1.0.0"},
		{"v0.5.0-rc.1", "v0.5.0-rc.1"},
		{"v0.4.2+build.7", "v0.4.2"},
		{"v0.4.2-3-gabc1234", "v0.4.2-3-gabc1234"},
		{"dev", "dev"},
		{"unknown", "unknown"},
		// Untrusted input: control characters are dropped and the value is capped.
		{"dev\x1b[31m", "dev[31m"},
		{strings.Repeat("a", 100), strings.Repeat("a", MaxVersionLength)},
	}
	for _, c := range cases {
		if got := NormalizeVersion(c.in); got != c.want {
			t.Errorf("NormalizeVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClassifyVersion(t *testing.T) {
	cases := []struct {
		name, v, latest, min string
		want                 VersionStatus
	}{
		{"latest", "v0.4.2", "v0.4.2", "", VersionLatest},
		{"newer than latest", "v0.5.0", "v0.4.2", "", VersionLatest},
		{"older", "v0.4.1", "v0.4.2", "", VersionUpdateAvailable},
		{"unprefixed input", "0.4.1", "0.4.2", "", VersionUpdateAvailable},
		{"below minimum", "v0.3.0", "v0.4.2", "v0.4.0", VersionUnsupported},
		{"at minimum", "v0.4.0", "v0.4.2", "v0.4.0", VersionUpdateAvailable},
		{"minimum only", "v0.3.0", "", "v0.4.0", VersionUnsupported},
		{"no latest configured", "v0.4.0", "", "", VersionUnknown},
		{"empty version", "", "v0.4.2", "v0.4.0", VersionUnknown},
		{"not semver", "dev", "v0.4.2", "v0.4.0", VersionUnknown},
		{"pre-release of latest", "v0.4.2-rc.1", "v0.4.2", "", VersionUpdateAvailable},
		// A git-describe build is newer than its tag, not a pre-release of it.
		{"git describe build", "v0.4.2-3-gabc1234", "v0.4.2", "", VersionLatest},
		{"git describe dirty", "v0.4.2-3-gabc1234-dirty", "v0.4.2", "", VersionLatest},
		{"invalid latest ignored", "v0.4.2", "latest", "", VersionUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyVersion(c.v, c.latest, c.min); got != c.want {
				t.Errorf("ClassifyVersion(%q, %q, %q) = %q, want %q", c.v, c.latest, c.min, got, c.want)
			}
		})
	}
}
