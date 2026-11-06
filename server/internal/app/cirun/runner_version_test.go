package cirun

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// versionOf reads a runner version from a User-Agent the way the exchange does.
func versionOf(userAgent string) string {
	_, v := sensor.ResolveBuild(sensor.BuildReport{}, "", userAgent, time.Now())
	return sensor.NormalizeVersion(v)
}

// A CI runner is judged against the CI runner release line. The released
// runners (openctem-ci v0.1.0, v0.2.0) are far below the sensor minimum
// (v0.9.0): judged against it, every exchange would be refused.
func TestRunnerRefusal_CIRunnerReleaseLine(t *testing.T) {
	cases := []struct {
		name, ua string
		pol      cirun.StatusPolicy
		refused  bool
	}{
		{"released runner, no minimum", "openctem-ci/v0.2.0", cirun.StatusPolicy{LatestVersion: "v0.2.0"}, false},
		{"released runner at the minimum", "openctem-ci/v0.2.0", cirun.StatusPolicy{MinVersion: "v0.2.0"}, false},
		{"runner without the v prefix", "openctem-ci/0.3.1", cirun.StatusPolicy{MinVersion: "v0.3.0"}, false},
		{"runner below the minimum", "openctem-ci/v0.2.0", cirun.StatusPolicy{MinVersion: "v0.3.0"}, true},
		{"development build reports no version", "openctem-ci/dev", cirun.StatusPolicy{MinVersion: "v0.3.0"}, false},
		{"no User-Agent", "", cirun.StatusPolicy{MinVersion: "v0.3.0"}, false},
		// The sensor minimum of earlier releases, shown here to pin the bug:
		// a v0.2.0 runner is below it, so it must never be the policy used.
		{"sensor minimum would refuse a released runner", "openctem-ci/v0.2.0", cirun.StatusPolicy{MinVersion: "v0.9.0"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runnerRefusal(versionOf(c.ua), c.pol)
			if (r != nil) != c.refused {
				t.Fatalf("refused = %v, want %v (%+v)", r != nil, c.refused, r)
			}
			if r != nil && (r.Code != "runner_outdated" || !strings.Contains(r.Detail, c.pol.MinVersion)) {
				t.Fatalf("refusal = %+v", r)
			}
		})
	}
}

// Pipeline health uses the same policy: a pipeline on the newest CI runner
// release is current, not "unsupported".
func TestPipelineHealth_CIRunnerReleaseLine(t *testing.T) {
	pol := cirun.StatusPolicy{LatestVersion: "v0.2.0"}
	if got := sensor.ClassifyVersion("v0.2.0", pol.LatestVersion, pol.MinVersion); got == sensor.VersionUnsupported {
		t.Fatalf("v0.2.0 on the CI runner line = %s", got)
	}
	if got := sensor.ClassifyVersion("v0.1.0", pol.LatestVersion, pol.MinVersion); got == sensor.VersionUnsupported {
		t.Fatalf("an older runner with no minimum is outdated at most, got %s", got)
	}
}
