package scanrun

import (
	"sort"
	"strings"
)

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
// neither as a step retry nor as a scan-level retry of the run: every code
// whose class a retry cannot fix (see FailureClass.Retryable).
var PermanentFailureCodes = permanentFailureCodes()

func permanentFailureCodes() []string {
	out := make([]string, 0, len(failureClasses))
	for code, class := range failureClasses {
		if !class.Retryable() {
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
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
	if IsKnownFailureCode(code) && code != FailureCommandFailed {
		return code, ClassOf(code).Retryable()
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
	return code, ClassOf(code).Retryable()
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

// FailureClass groups step failure codes by what can fix them (research/62
// §5.3). The class decides whether a retry can help; the console maps it to
// the text and the fix action it shows.
type FailureClass string

const (
	// FailureClassConfig: the step's own configuration cannot run (no tool
	// for the capability, incompatible targets). Fix: edit the step.
	FailureClassConfig FailureClass = "config"
	// FailureClassScope: the targets are out of scope or unconfirmed.
	FailureClassScope FailureClass = "scope"
	// FailureClassPlacement: no sensor can take the work.
	FailureClassPlacement FailureClass = "placement"
	// FailureClassPolicy: a sensor's local policy or a freeze window refused.
	FailureClassPolicy FailureClass = "policy"
	// FailureClassTransient: the sensor went away, a lease was lost, the
	// platform or the network failed. A retry can help.
	FailureClassTransient FailureClass = "transient"
	// FailureClassTool: the tool itself failed (crash, exit code, parse).
	FailureClassTool FailureClass = "tool"
	// FailureClassTimeout: the step ran out of time.
	FailureClassTimeout FailureClass = "timeout"
	// FailureClassCanceled: a person or the run deadline stopped it.
	FailureClassCanceled FailureClass = "canceled"
)

// More step failure codes, recorded by the platform before or around
// dispatch (queue time) or sent by a sensor in its structured fail.
const (
	FailureNoMatchingTool      = "NO_MATCHING_TOOL"
	FailureCapabilityAmbiguous = "STEP_CAPABILITY_AMBIGUOUS"
	FailureIncompatibleTargets = "INCOMPATIBLE_TARGETS"
	FailureStageNotChainable   = "STAGE_NOT_CHAINABLE"
	FailureStepTargetsRefused  = "STEP_TARGETS_REFUSED"
	FailureAllTargetsExcluded  = "ALL_TARGETS_EXCLUDED"
	FailureAllTargetsUnconfirm = "ALL_TARGETS_UNCONFIRMED"
	FailureNoSensorForTool     = "NO_SENSOR_FOR_TOOL"
	FailureNoSensorAvailable   = "NO_SENSOR_AVAILABLE"
	FailurePolicyRefused       = "POLICY_REFUSED"
	FailureFreezeWindow        = "FREEZE_WINDOW"
	FailureCommandFailed       = "COMMAND_FAILED"
	FailureCommandExpired      = "COMMAND_EXPIRED"
	FailureLeaseLost           = "LEASE_LOST"
	FailureToolExit            = "TOOL_EXIT"
	FailureParseError          = "PARSE_ERROR"
	FailureTimeout             = "TIMEOUT"
	FailureCanceled            = "CANCELED"
	FailureBatchFailed         = "BATCH_FAILED"
	FailureQueueError          = "QUEUE_ERROR"
	// FailureScopeChanged: the scope changed while the job was queued and
	// the claim-time re-check refused every target.
	FailureScopeChanged = "SCOPE_CHANGED"
	// FailureGateRecordMissing: a probing job queued without a dispatch
	// gate record whose targets the claim cannot read to re-check them;
	// it is refused, and its owner creates it again.
	FailureGateRecordMissing = "GATE_RECORD_MISSING"
)

var failureClasses = map[string]FailureClass{
	FailureNoMatchingTool:      FailureClassConfig,
	FailureCapabilityAmbiguous: FailureClassConfig,
	FailureIncompatibleTargets: FailureClassConfig,
	FailureStageNotChainable:   FailureClassConfig,
	FailureScannerNotFound:     FailureClassPlacement,
	FailureTargetRefused:       FailureClassScope,
	FailureNoTargets:           FailureClassScope,
	FailureStepTargetsRefused:  FailureClassScope,
	FailureAllTargetsExcluded:  FailureClassScope,
	FailureAllTargetsUnconfirm: FailureClassScope,
	FailureScopeChanged:        FailureClassScope,
	FailureGateRecordMissing:   FailureClassScope,
	FailureNoSensor:            FailureClassPlacement,
	FailureNoSensorForTool:     FailureClassPlacement,
	FailureNoSensorAvailable:   FailureClassPlacement,
	FailurePolicyRefused:       FailureClassPolicy,
	FailureFreezeWindow:        FailureClassPolicy,
	FailureCommandExhausted:    FailureClassTransient,
	FailureCommandExpired:      FailureClassTransient,
	FailureLeaseLost:           FailureClassTransient,
	FailureQueueError:          FailureClassTransient,
	FailureCommandFailed:       FailureClassTool,
	FailureToolExit:            FailureClassTool,
	FailureParseError:          FailureClassTool,
	FailureBatchFailed:         FailureClassTool,
	FailureTimeout:             FailureClassTimeout,
	FailureCanceled:            FailureClassCanceled,
}

// ClassOf returns the class of a step failure code. An unknown code is a
// tool failure: the work ran and failed for a reason the platform does not
// name.
func ClassOf(code string) FailureClass {
	if c, ok := failureClasses[code]; ok {
		return c
	}
	return FailureClassTool
}

// Retryable reports whether a retry of the same work can succeed: config,
// scope, placement, policy and canceled failures fail the same way again.
func (c FailureClass) Retryable() bool {
	switch c {
	case FailureClassTransient, FailureClassTool, FailureClassTimeout:
		return true
	}
	return false
}

// IsKnownFailureCode reports whether code is one the platform names. A
// sensor's structured fail may only use these; anything else is recorded
// as COMMAND_FAILED.
func IsKnownFailureCode(code string) bool {
	_, ok := failureClasses[code]
	return ok
}

// SensorFailureCodes are the codes a sensor may put in a structured fail:
// what the sensor itself can observe. Platform-only codes (queue time,
// placement, scope decisions) are refused from a sensor.
var SensorFailureCodes = map[string]bool{
	FailureScannerNotFound: true,
	FailureTargetRefused:   true,
	FailureNoTargets:       true,
	FailurePolicyRefused:   true,
	FailureToolExit:        true,
	FailureParseError:      true,
	FailureTimeout:         true,
	FailureCommandFailed:   true,
}
