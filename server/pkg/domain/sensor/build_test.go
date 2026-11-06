package sensor

import (
	"testing"
	"time"
)

func TestResolveBuild(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		rep         BuildReport
		version, ua string
		want        BuildInfo
		wantVersion string
	}{
		{name: "user agent of a current sensor", ua: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0",
			want:        BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.9.0", Product: "openctemio-sensor"},
			wantVersion: "v0.5.0"},
		{name: "the heartbeat version stays the sensor version", ua: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0", version: "0.5.0-rc1",
			want:        BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.9.0", Product: "openctemio-sensor"},
			wantVersion: "0.5.0-rc1"},
		{name: "old generic SDK token carries nothing", ua: "sdk/1.0", version: "0.4.1", wantVersion: "0.4.1"},
		{name: "SDK only", ua: "openctem-sdk-go/0.7.4", want: BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.7.4"}},
		{name: "devel SDK is unknown", ua: "openctemio-sensor/0.5.0 openctem-sdk-go/devel",
			want: BuildInfo{Product: "openctemio-sensor"}, wantVersion: "v0.5.0"},
		{name: "structured members win", ua: "openctemio-sensor/0.5.0 openctem-sdk-go/0.9.0",
			rep:         BuildReport{SDKName: "Openctem-SDK-Go", SDKVersion: "v0.9.1", SensorName: "openctemio-sensor", SensorVersion: "0.5.1", Commit: "0123ABC", BuildTime: "2026-10-01T10:00:00Z"},
			want:        BuildInfo{SDKName: "openctem-sdk-go", SDKVersion: "v0.9.1", Product: "openctemio-sensor", Commit: "0123abc", BuildTime: ptrTime(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC))},
			wantVersion: "v0.5.1"},
		{name: "hostile values are dropped",
			rep: BuildReport{SDKName: "x; rm -rf /", SDKVersion: "not a version", SensorName: "<script>", Commit: "zz", BuildTime: "2099-01-01T00:00:00Z"},
			ua:  "<evil>/1.0 x;y/2.0"},
		{name: "http library token is not a product", ua: "Go-http-client/1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, v := ResolveBuild(tc.rep, tc.version, tc.ua, now)
			if got.SDKName != tc.want.SDKName || got.SDKVersion != tc.want.SDKVersion || got.Product != tc.want.Product ||
				got.Commit != tc.want.Commit || (got.BuildTime == nil) != (tc.want.BuildTime == nil) ||
				(got.BuildTime != nil && !got.BuildTime.Equal(*tc.want.BuildTime)) {
				t.Errorf("build = %+v, want %+v", got, tc.want)
			}
			if v != tc.wantVersion {
				t.Errorf("version = %q, want %q", v, tc.wantVersion)
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestClassifySDK(t *testing.T) {
	adv := []string{"v0.7.4", "v0.9.0"}
	cases := []struct {
		v, latest string
		want      SDKStatus
	}{
		{"", "v0.9.0", SDKUnknown},
		{"v0.7.4", "v0.9.0", SDKAdvisory},
		{"0.7.4", "v0.9.0", SDKAdvisory},
		{"v0.7.4-3-gabcdef1", "v0.9.0", SDKAdvisory}, // a build after the advised tag
		{"v0.7.5", "v0.9.0", SDKOutdated},            // older, but no advisory: informational
		{"v0.7.0", "v0.9.0", SDKOutdated},
		{"v0.9.0", "v0.9.0", SDKAdvisory}, // the latest can have an advisory too
		{"v0.9.1", "v0.9.0", SDKCurrent},
		{"v0.1.0", "", SDKCurrent},
	}
	for _, c := range cases {
		if got := ClassifySDK(c.v, c.latest, "", adv); got != c.want {
			t.Errorf("ClassifySDK(%q, %q) = %s, want %s", c.v, c.latest, got, c.want)
		}
	}
	if got := ClassifySDK("v0.7.4", "v0.9.0", "", nil); got != SDKOutdated {
		t.Errorf("no advisories: %s", got)
	}
}

// The platform-owned SDK floor applies to any product built with sdk-go,
// first-party or a tenant's own; it wins over an advisory; a sensor built
// with another SDK is never judged against sdk-go's releases.
func TestClassifySDK_Minimum(t *testing.T) {
	adv := []string{"v0.7.4"}
	for _, c := range []struct {
		v, min string
		want   SDKStatus
	}{
		{"v0.7.4", "v0.8.0", SDKUnsupported}, // below the floor wins over the advisory
		{"v0.7.9", "v0.8.0", SDKUnsupported},
		{"v0.8.0", "v0.8.0", SDKOutdated}, // at the floor: supported, older than latest
		{"v0.9.0", "v0.8.0", SDKCurrent},
		{"v0.7.4", "", SDKAdvisory},
		{"dev", "v0.8.0", SDKUnknown},
	} {
		if got := ClassifySDK(c.v, "v0.9.0", c.min, adv); got != c.want {
			t.Errorf("ClassifySDK(%q, min %q) = %s, want %s", c.v, c.min, got, c.want)
		}
	}
	for _, c := range []struct {
		b    BuildInfo
		want SDKStatus
	}{
		{BuildInfo{SDKName: SDKGoName, SDKVersion: "v0.1.0", Product: "acme-scanner"}, SDKUnsupported},
		{BuildInfo{SDKVersion: "v0.1.0"}, SDKUnsupported}, // an SDK before names were reported
		{BuildInfo{SDKName: "openctem-sdk-python", SDKVersion: "v0.1.0"}, SDKUnknown},
	} {
		if got := c.b.SDKStatusFor("v0.9.0", "v0.8.0", nil); got != c.want {
			t.Errorf("%+v: %s, want %s", c.b, got, c.want)
		}
	}
}

func TestBuildInfo_ProductID(t *testing.T) {
	if got := (BuildInfo{}).ProductID(); got != DefaultProduct {
		t.Errorf("no product reported -> %q, want %q", got, DefaultProduct)
	}
	if got := (BuildInfo{Product: "openctemio-connector-tenable"}).ProductID(); got != "openctemio-connector-tenable" {
		t.Errorf("reported product -> %q", got)
	}
}

func TestVersionDirection(t *testing.T) {
	if VersionDirection("v0.4.1", "v0.5.0") != "upgrade" || VersionDirection("v0.5.0", "v0.4.2") != "downgrade" ||
		VersionDirection("dev", "v0.5.0") != "changed" {
		t.Error("direction")
	}
}
