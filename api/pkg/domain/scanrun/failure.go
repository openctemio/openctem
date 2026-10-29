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
	{FailureWebScopeUnsupported, []string{"does not keep to a web scope", "keeps to a web scope only in"}},
	// A sensor that sends no reach summary reports an unreachable job as
	// text: the SDK's tool error class, or the operating system's own
	// connect errors toward the target.
	{FailureTargetUnreachable, []string{
		"target_unreachable", "target unreachable", "targets unreachable",
		"network is unreachable", "no route to host", "host is unreachable",
	}},
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
	// FailureClassPartial: the step completed, but not on everything it was
	// given (hosts not fully covered, targets left unfinished). Its results
	// are kept; running again covers the rest.
	FailureClassPartial FailureClass = "partial"
	// FailureClassTarget: a fact about the targets, not a fault of the
	// platform, the sensor or the tool (no target name resolves in DNS).
	// Running again fails the same way until the targets change.
	FailureClassTarget FailureClass = "target"
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
	// FailureSignerRefused: the job signer refused the job because its
	// scope ledger does not authorize it (RFC-040 §5.6 point 4).
	FailureSignerRefused = "SIGNER_REFUSED"
	// FailureIntensityExceeded: the job probes above the intensity of the
	// scan it belongs to (RFC-071); refused at claim.
	FailureIntensityExceeded = "INTENSITY_EXCEEDED"
	// FailureWebScopeUnsupported: the job has a web scope (the tenant
	// excluded a path on a target host) and the sensor's tool cannot keep
	// to it: the tool does not declare features.web_scope, or it keeps to
	// one only in a sandbox that confines its network and the sensor's
	// does not (RFC-055 §6.1). The same sensor fails the same way again.
	FailureWebScopeUnsupported = "WEB_SCOPE_UNSUPPORTED"
	// FailureNoConfinedSensor: the job needs a sensor whose tool runs are
	// network-confined (net.confined@1; a web-scoped template scan) and
	// the organization has no active sensor that reports it, so it could
	// never be taken. Refused when the step is queued.
	FailureNoConfinedSensor = "NO_CONFINED_SENSOR"
	// FailureDeadlineTooClose: the step was not started because less time
	// was left before its run's deadline than its tool needs to do anything
	// useful; its targets are the run's unfinished targets (research/122).
	FailureDeadlineTooClose = "DEADLINE_TOO_CLOSE"
	// FailureCoverageGaps: the step completed with hosts its sensor could
	// not fully cover, or targets it left unfinished. The step output
	// carries the hosts and reasons (coverage_gaps) and the counts.
	FailureCoverageGaps = "COVERAGE_GAPS"
	// FailureNoResolvingTargets: no target name of the job resolves in DNS
	// any more, and the job's tool needs an address to probe; recorded at
	// claim when that is the only reason its targets are refused. A fact
	// about the names, never a scope change.
	FailureNoResolvingTargets = "NO_RESOLVING_TARGETS"

	// Infrastructure failures of a command (research/302): not about the
	// target. A command moves to another sensor on these; they name why it
	// finally failed.
	//
	// FailureToolUnavailable: the tool is missing or broken on every sensor
	// that could take the work.
	FailureToolUnavailable = "TOOL_UNAVAILABLE"
	// FailureToolCrashedOnInput: the tool crashed on this work on more than
	// one sensor (the input, not a sensor, is the likely cause).
	FailureToolCrashedOnInput = "TOOL_CRASHED_ON_INPUT"
	// FailureResourceExhausted: the sensors ran out of memory or disk.
	FailureResourceExhausted = "RESOURCE_EXHAUSTED"
	// FailureContentUnavailable: the tool's content pack could not be read.
	FailureContentUnavailable = "CONTENT_UNAVAILABLE"
	// FailureSensorLost: the sensors that held the work stopped answering.
	FailureSensorLost = "SENSOR_LOST"
	// FailureFleetToolFailure: the same tool and content version failed on
	// two sensors, so the work was not moved to more of them (fleet stop
	// rule).
	FailureFleetToolFailure = "FLEET_TOOL_FAILURE"
)

// FailureCodeForInfra is the step failure code of a command that ended on
// the infrastructure class class (command.FailureClass spelling). An
// unknown class gives COMMAND_FAILED.
func FailureCodeForInfra(class string) string {
	switch class {
	case "infra.tool_unavailable":
		return FailureToolUnavailable
	case "infra.tool_crashed":
		return FailureToolCrashedOnInput
	case "infra.resource.memory", "infra.resource.disk":
		return FailureResourceExhausted
	case "infra.content_unavailable":
		return FailureContentUnavailable
	case "infra.sensor_offline":
		return FailureSensorLost
	}
	return FailureCommandFailed
}

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
	FailureIntensityExceeded:   FailureClassScope,
	FailureSignerRefused:       FailureClassScope,
	FailureNoSensor:            FailureClassPlacement,
	FailureNoSensorForTool:     FailureClassPlacement,
	FailureNoSensorAvailable:   FailureClassPlacement,
	FailureWebScopeUnsupported: FailureClassPlacement,
	FailureTargetUnreachable:   FailureClassPlacement,
	FailureNoConfinedSensor:    FailureClassPlacement,
	FailurePolicyRefused:       FailureClassPolicy,
	FailureFreezeWindow:        FailureClassPolicy,
	FailureDeadlineTooClose:    FailureClassPolicy,
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
	FailureCoverageGaps:        FailureClassPartial,
	FailureNoResolvingTargets:  FailureClassTarget,
	FailureToolUnavailable:     FailureClassTool,
	FailureToolCrashedOnInput:  FailureClassTool,
	FailureResourceExhausted:   FailureClassTransient,
	FailureContentUnavailable:  FailureClassTransient,
	FailureSensorLost:          FailureClassTransient,
	FailureFleetToolFailure:    FailureClassTool,
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
	FailureScannerNotFound:   true,
	FailureTargetRefused:     true,
	FailureTargetUnreachable: true,
	FailureNoTargets:         true,
	FailurePolicyRefused:     true,
	FailureToolExit:          true,
	FailureParseError:        true,
	FailureTimeout:           true,
	FailureCommandFailed:     true,
}
