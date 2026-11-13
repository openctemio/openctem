package command

import (
	"encoding/json"
	"testing"
)

func TestRunStopped(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		stopped bool
		why     string
	}{
		{"no result: the command status decides", ``, false, ""},
		{"null result", `null`, false, ""},
		{"exit 0, completed", `{"status":"completed","exit_code":0}`, false, ""},
		{"no exit code, no status", `{"metadata":{"outcome":"not_detected"}}`, false, ""},
		{"success status", `{"status":"Success"}`, false, ""},
		// The legacy shape (research/467 F6): a scanner killed by the job
		// budget reports -1 and the sensor still says "completed".
		{"legacy budget kill: exit -1, completed", `{"status":"completed","exit_code":-1,"metadata":{"coverage_type":"full"}}`, true, StopNonZeroExit},
		{"tool gave up: exit 1", `{"status":"completed","exit_code":1}`, true, StopNonZeroExit},
		{"exit code as a float", `{"exit_code":0.5}`, true, StopNonZeroExit},
		{"exit code 0 as a string", `{"exit_code":"0"}`, false, ""},
		{"exit code -1 as a string", `{"exit_code":"-1"}`, true, StopNonZeroExit},
		{"exit code not a number", `{"exit_code":"killed"}`, true, StopUnreadable},
		{"partial status", `{"status":"partial","exit_code":0}`, true, StopStatus},
		{"timeout status", `{"status":"timeout"}`, true, StopStatus},
		{"stopped flag", `{"exit_code":0,"stopped":true}`, true, StopSensorStopped},
		{"stop reason", `{"exit_code":0,"stop_reason":"lease_lost"}`, true, StopSensorStopped},
		{"stop reason in metadata", `{"exit_code":0,"metadata":{"stop_reason":"drain"}}`, true, StopSensorStopped},
		{"stopped in metadata", `{"metadata":{"stopped":true}}`, true, StopSensorStopped},
		{"a failure", `{"exit_code":0,"failure":{"class":"infra.tool_crashed"}}`, true, StopSensorStopped},
		{"a null failure is no failure", `{"exit_code":0,"failure":null}`, false, ""},
		{"blank stop reason is none", `{"exit_code":0,"stop_reason":"  "}`, false, ""},
		{"not an object", `[1,2]`, true, StopUnreadable},
		{"not JSON", `{"exit_code":`, true, StopUnreadable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stopped, why := RunStopped(json.RawMessage(c.raw))
			if stopped != c.stopped || why != c.why {
				t.Fatalf("RunStopped(%s) = %v %q, want %v %q", c.raw, stopped, why, c.stopped, c.why)
			}
		})
	}
}
