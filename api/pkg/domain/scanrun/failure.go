package scanrun

import "strings"

// Step failure codes. The four permanent ones name failures that a retry
// cannot fix: the same command on the same configuration fails the same way
// (D7). Retrying them only burns sensor time and hides the real error behind
// "max retries exceeded".
const (
	// FailureScannerNotFound: the sensor does not have the tool.
	FailureScannerNotFound = "SCANNER_NOT_FOUND"
	// FailureTargetRefused: the sensor's target guard refused the target.
	FailureTargetRefused = "TARGET_REFUSED"
	// FailureNoTargets: the work has nothing to scan.
	FailureNoTargets = "NO_TARGETS"
	// FailureNoSensor: no sensor could, or did, take the work.
	FailureNoSensor = "NO_SENSOR"

	// FailureCommandExhausted: the command was handed out max-dispatch times
	// and never finished (a poison command). Transient by nature.
	FailureCommandExhausted = "COMMAND_EXHAUSTED"
)

// PermanentFailureCodes are the step error codes that are never retried,
// neither as a step retry nor as a scan-level retry of the run.
var PermanentFailureCodes = []string{
	FailureScannerNotFound,
	FailureTargetRefused,
	FailureNoTargets,
	FailureNoSensor,
}

// failurePatterns map a sensor's error text to a permanent code. The sensor
// reports failures as free text (the command handler passes COMMAND_FAILED),
// so the class is recovered from the messages the sensor and SDK actually
// produce.
var failurePatterns = []struct {
	code    string
	needles []string
}{
	{FailureScannerNotFound, []string{"scanner not found", "collector not found", "unknown scanner"}},
	{FailureTargetRefused, []string{
		"invalid scan target", "refusing to scan", "not allowed as scan targets",
		"scan target scheme", "scan target host", "scan target ip", "scan target range",
		"binding addresses not allowed", "target refused",
	}},
	{FailureNoTargets, []string{"no targets", "no target "}},
	{FailureNoSensor, []string{"no sensor"}},
}

// ClassifyStepFailure returns the code to record for a step failure and
// whether a retry can help. A known permanent code is kept; otherwise the
// message is matched against the known permanent failures; anything else
// keeps its code and is retryable.
func ClassifyStepFailure(code, message string) (string, bool) {
	if IsPermanentFailure(code) {
		return code, false
	}
	lower := strings.ToLower(message)
	scannerNotFound := strings.Contains(lower, "scanner ") && strings.Contains(lower, " not found")
	for _, p := range failurePatterns {
		if p.code == FailureScannerNotFound && scannerNotFound {
			return p.code, false
		}
		for _, n := range p.needles {
			if strings.Contains(lower, n) {
				return p.code, false
			}
		}
	}
	return code, true
}

// IsPermanentFailure reports whether code is one of PermanentFailureCodes.
func IsPermanentFailure(code string) bool {
	for _, c := range PermanentFailureCodes {
		if c == code {
			return true
		}
	}
	return false
}
