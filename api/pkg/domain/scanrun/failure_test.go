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
		// Transient: kept and retryable.
		{"COMMAND_FAILED", "dial tcp: connection refused", "COMMAND_FAILED", true},
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
