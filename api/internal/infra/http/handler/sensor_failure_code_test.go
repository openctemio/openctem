package handler

import (
	"testing"

	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// A sensor may name only what it can observe. A platform decision code
// (NO_SENSOR, NO_MATCHING_TOOL, ALL_TARGETS_EXCLUDED...) from a sensor is
// refused: it would mark the failure permanent and stop retries.
func TestSensorFailureCode(t *testing.T) {
	cases := []struct {
		code    string
		refused bool
		want    string
	}{
		{scanrundom.FailureToolExit, false, scanrundom.FailureToolExit},
		{scanrundom.FailureTargetRefused, false, scanrundom.FailureTargetRefused},
		{scanrundom.FailureNoSensor, false, scanrundom.FailureCommandFailed},
		{scanrundom.FailureNoMatchingTool, false, scanrundom.FailureCommandFailed},
		{"no_such_code", false, scanrundom.FailureCommandFailed},
		{"", true, scanrundom.FailurePolicyRefused},
		{"", false, scanrundom.FailureCommandFailed},
	}
	for _, c := range cases {
		if got := sensorFailureCode(c.code, c.refused); got != c.want {
			t.Errorf("sensorFailureCode(%q, %v) = %q, want %q", c.code, c.refused, got, c.want)
		}
	}
}
