package scanrun

import "testing"

func TestClassifyStepFailure(t *testing.T) {
	cases := []struct {
		code, msg string
		want      string
		retryable bool
	}{
		{"COMMAND_FAILED", "scanner not found: nuclei", FailureScannerNotFound, false},
		{"COMMAND_FAILED", "scanner trivy not found", FailureScannerNotFound, false},
		{"COMMAND_FAILED", "invalid scan target: 2 of 2 targets refused: 10.0.0.1", FailureTargetRefused, false},
		{"COMMAND_FAILED", `scan target host "metadata.internal" is blocked`, FailureTargetRefused, false},
		{"COMMAND_FAILED", "refusing to scan filesystem root", FailureTargetRefused, false},
		{"COMMAND_FAILED", "no targets in payload", FailureNoTargets, false},
		{FailureNoSensor, "nobody took it", FailureNoSensor, false},
		// A web-scoped job the sensor's tool cannot keep to: permanent on
		// that sensor, never retried there.
		{"COMMAND_FAILED", "scan failed: nuclei does not keep to a web scope (features.web_scope); the job has one", FailureWebScopeUnsupported, false},
		{"COMMAND_FAILED", "scan failed: nuclei keeps to a web scope only in a tool sandbox that confines its network, and this sensor's does not (SENSOR_SANDBOX_NETWORK; the container needs the seccomp profile in docker/seccomp); the job has a web scope", FailureWebScopeUnsupported, false},
		// The target could not be reached from the sensor: placement, not a
		// tool error, and never "completed with nothing found".
		{"COMMAND_FAILED", "target_unreachable: all 3 targets failed", FailureTargetUnreachable, false},
		{"COMMAND_FAILED", "scan failed: dial tcp 10.2.0.7:443: connect: network is unreachable", FailureTargetUnreachable, false},
		{"COMMAND_FAILED", "dial tcp [2001:db8::7]:22: connect: no route to host", FailureTargetUnreachable, false},
		{"COMMAND_FAILED", "naabu: 192.0.2.7: host is unreachable", FailureTargetUnreachable, false},
		{FailureTargetUnreachable, "anything", FailureTargetUnreachable, false},
		// A closed port means the path works: not unreachable.
		{"COMMAND_FAILED", "dial tcp: connection refused", "COMMAND_FAILED", true},
		// Unrelated "unreachable" text stays a tool failure.
		{"COMMAND_FAILED", "results upload failed: platform unreachable, will retry", "COMMAND_FAILED", true},
		// Transient: kept and retryable.
		{"COMMAND_FAILED", "i/o timeout reading results", "COMMAND_FAILED", true},
		{"COMMAND_EXPIRED", "command expired", "COMMAND_EXPIRED", true},
		{FailureCommandExhausted, "Max dispatch attempts exceeded", FailureCommandExhausted, true},
	}
	for _, c := range cases {
		got, retryable := ClassifyStepFailure(c.code, c.msg)
		if got != c.want || retryable != c.retryable {
			t.Errorf("ClassifyStepFailure(%q, %q) = %q, %v; want %q, %v", c.code, c.msg, got, retryable, c.want, c.retryable)
		}
	}
}

func TestFailureClasses(t *testing.T) {
	for code, want := range map[string]FailureClass{
		FailureNoMatchingTool:      FailureClassConfig,
		FailureIncompatibleTargets: FailureClassConfig,
		FailureStageNotChainable:   FailureClassConfig,
		FailureTargetRefused:       FailureClassScope,
		FailureNoSensor:            FailureClassPlacement,
		FailureTargetUnreachable:   FailureClassPlacement,
		FailurePolicyRefused:       FailureClassPolicy,
		FailureLeaseLost:           FailureClassTransient,
		FailureCommandExhausted:    FailureClassTransient,
		FailureToolExit:            FailureClassTool,
		FailureTimeout:             FailureClassTimeout,
		FailureCanceled:            FailureClassCanceled,
		FailureCoverageGaps:        FailureClassPartial,
		"SOMETHING_NEW":            FailureClassTool,
	} {
		if got := ClassOf(code); got != want {
			t.Errorf("ClassOf(%s) = %s, want %s", code, got, want)
		}
	}
	for _, code := range []string{FailureNoMatchingTool, FailureIncompatibleTargets, FailureStageNotChainable, FailurePolicyRefused, FailureCanceled} {
		if !IsPermanentFailure(code) {
			t.Errorf("%s must be permanent (never retried)", code)
		}
	}
	for _, code := range []string{FailureLeaseLost, FailureCommandExhausted, FailureCommandFailed, FailureTimeout} {
		if IsPermanentFailure(code) {
			t.Errorf("%s must stay retryable", code)
		}
	}
	// A structured code wins over the text; COMMAND_FAILED still falls back
	// to the text classification for sensors that send no code.
	if code, retry := ClassifyStepFailure(FailureToolExit, "scanner not found"); code != FailureToolExit || !retry {
		t.Errorf("structured TOOL_EXIT: %s %v", code, retry)
	}
	if code, retry := ClassifyStepFailure(FailureNoMatchingTool, "x"); code != FailureNoMatchingTool || retry {
		t.Errorf("NO_MATCHING_TOOL: %s %v", code, retry)
	}
}

func TestTargetUnreachableIsSensorCode(t *testing.T) {
	if !SensorFailureCodes[FailureTargetUnreachable] || !IsKnownFailureCode(FailureTargetUnreachable) {
		t.Fatal("a sensor may report TARGET_UNREACHABLE in a structured fail")
	}
	if !IsPermanentFailure(FailureTargetUnreachable) {
		t.Fatal("TARGET_UNREACHABLE is not retried: the same sensor fails the same way")
	}
}

func TestCoverageGapsIsAKnownPartialCode(t *testing.T) {
	if !IsKnownFailureCode(ErrCodeCoverageGaps) || ClassOf(ErrCodeCoverageGaps).Retryable() {
		t.Fatal("COVERAGE_GAPS is a known code of the partial class, not a retryable failure")
	}
}
