package scan

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// The incident: the only sensor's local policy allows no target. The
// trigger is refused with a reason that names the sensor and the file to
// edit, instead of queueing work that sensor would refuse.
func TestJudge_EmptyAllowListNamesTheSensor(t *testing.T) {
	sc := &scan.Scan{ScannerName: "subfinder"}
	job := scanJob(sc, []string{"example.com"})
	if !job.NetworkTarget {
		t.Fatal("a scan job with targets must count as naming a network target")
	}
	empty := &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Summary: &sensordom.LocalPolicySummary{TargetsAllow: 0}}
	open := &sensordom.LocalPolicyReport{State: sensordom.LocalPolicyEnforced, Summary: &sensordom.LocalPolicySummary{TargetsAllow: -1}}

	v := judge([]*sensordom.LocalPolicyReport{empty}, []string{"office-1"}, job, sensordom.DispatchOptions{})
	if len(v.accepted) != 0 {
		t.Fatal("a sensor whose policy allows nothing accepted the job")
	}
	reason := v.reason("this organization")
	for _, want := range []string{"targets.allow", `sensor "office-1"`, "sensor-policy.yaml"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q lacks %q", reason, want)
		}
	}
	// A sensor that follows the platform's scope takes it.
	v = judge([]*sensordom.LocalPolicyReport{empty, open}, []string{"office-1", "vps-1"}, job, sensordom.DispatchOptions{})
	if len(v.accepted) != 1 || v.accepted[0] != 1 {
		t.Fatalf("accepted %v, want only the sensor without an allow list", v.accepted)
	}
}

func TestQuoteNames(t *testing.T) {
	for in, want := range map[string]string{"a": `sensor "a"`, "a,b": `sensors "a" and "b"`, "a,b,c": `sensors "a", "b" and "c"`} {
		if got := quoteNames(strings.Split(in, ",")); got != want {
			t.Errorf("quoteNames(%s) = %s, want %s", in, got, want)
		}
	}
}
