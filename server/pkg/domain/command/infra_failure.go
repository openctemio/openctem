package command

// A sensor's infrastructure failure of a command (research/302): the tool
// crashed or is missing, the sensor ran out of memory or disk, the content
// pack cannot be read, or the sensor was lost while it held the command.
// These say nothing about the target. Routed scan work is re-queued to
// another eligible sensor, every sensor that already failed it is excluded,
// and the attempt budget is the one every other cause shares
// (MaxDispatchAttempts). A fact about the target (unreachable, blocked by a
// WAF or CDN, rate limited) is never an infrastructure failure and is never
// sent to another sensor.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxDispatchAttempts is how many times one command is handed to a sensor,
// whatever the cause of each return (a lost lease, a refusal, an
// infrastructure failure). The job-recovery sweep fails a command at this
// count.
const MaxDispatchAttempts = 3

// MaxInfraAttempts bounds the failures remembered on one command.
const MaxInfraAttempts = 16

// FailureClass is the closed set of reasons a sensor reports for a failure
// that is not a refusal. The wire spelling is the string value.
type FailureClass string

// Failure classes.
const (
	ClassToolUnavailable    FailureClass = "infra.tool_unavailable"
	ClassToolCrashed        FailureClass = "infra.tool_crashed"
	ClassResourceMemory     FailureClass = "infra.resource.memory"
	ClassResourceDisk       FailureClass = "infra.resource.disk"
	ClassResourceOutput     FailureClass = "infra.resource.output_limit"
	ClassContentUnavailable FailureClass = "infra.content_unavailable"
	ClassSensorOffline      FailureClass = "infra.sensor_offline"
	ClassSensorNetwork      FailureClass = "infra.sensor_network"
	ClassDNSResolver        FailureClass = "infra.dns_resolver"
	ClassEgressPool         FailureClass = "infra.egress.pool_exhausted"
	ClassBudgetExceeded     FailureClass = "infra.budget_exceeded"

	// ClassTargetPrefix starts every class that is a fact about the target.
	ClassTargetPrefix = "target."
)

// ParseFailureClass returns the class named by s and whether it is one the
// platform knows. A target.* class parses (it is known) but is not movable.
func ParseFailureClass(s string) (FailureClass, bool) {
	c := FailureClass(strings.TrimSpace(s))
	switch c {
	case ClassToolUnavailable, ClassToolCrashed, ClassResourceMemory, ClassResourceDisk,
		ClassResourceOutput, ClassContentUnavailable, ClassSensorOffline, ClassSensorNetwork,
		ClassDNSResolver, ClassEgressPool, ClassBudgetExceeded:
		return c, true
	}
	if strings.HasPrefix(string(c), ClassTargetPrefix) && len(c) > len(ClassTargetPrefix) && len(c) <= 64 {
		return c, true
	}
	return "", false
}

// TargetSide reports whether the class is a fact about the target.
func (c FailureClass) TargetSide() bool {
	return strings.HasPrefix(string(c), ClassTargetPrefix)
}

// Movable reports whether a command that failed with this class may be
// handed to another sensor: the sensor, its tool or its content is at
// fault, and another sensor can have a different answer. Not movable: a
// fact about the target (never retried elsewhere in the run), a limit every
// sensor shares (output size, the job's time budget) and a proxy pool
// without a healthy endpoint (held, never sent to a sensor with the same
// pool).
func (c FailureClass) Movable() bool {
	switch c {
	case ClassToolUnavailable, ClassToolCrashed, ClassResourceMemory, ClassResourceDisk,
		ClassContentUnavailable, ClassSensorOffline, ClassSensorNetwork, ClassDNSResolver:
		return true
	}
	return false
}

// ToolScoped reports whether the class is about a tool and content
// version rather than one sensor: the fleet stop rule watches these.
func (c FailureClass) ToolScoped() bool {
	switch c {
	case ClassToolUnavailable, ClassToolCrashed, ClassContentUnavailable:
		return true
	}
	return false
}

// Short is the class without its infra. prefix, as timeline codes spell it.
func (c FailureClass) Short() string { return strings.TrimPrefix(string(c), "infra.") }

// FailureEvidence is the bounded evidence a sensor attaches to a failure.
// Every member is optional; the platform trims and sanitizes it
// (SanitizeEvidence) before use.
type FailureEvidence struct {
	Tool          string `json:"tool,omitempty"`
	ToolDigest    string `json:"tool_digest,omitempty"`
	ContentDigest string `json:"content_digest,omitempty"`
	Stage         string `json:"stage,omitempty"`
	ExitCode      *int   `json:"exit_code,omitempty"`
	Signal        string `json:"signal,omitempty"`
}

// Evidence bounds.
const (
	maxEvidenceToken  = 96
	maxEvidenceDigest = 96
)

// SanitizeEvidence trims e to closed, bounded tokens: letters, digits and
// . _ - : / @ + only, so a hostile sensor cannot put control characters,
// markup or long text into the timeline, logs or breaker keys.
func SanitizeEvidence(e FailureEvidence) FailureEvidence {
	e.Tool = evidenceToken(e.Tool, maxEvidenceToken)
	e.ToolDigest = evidenceToken(e.ToolDigest, maxEvidenceDigest)
	e.ContentDigest = evidenceToken(e.ContentDigest, maxEvidenceDigest)
	e.Stage = evidenceToken(e.Stage, 32)
	e.Signal = evidenceToken(e.Signal, 32)
	if e.ExitCode != nil && (*e.ExitCode < -1 || *e.ExitCode > 255) {
		e.ExitCode = nil
	}
	return e
}

// evidenceToken returns s when it is a short token of safe characters,
// else "".
func evidenceToken(s string, max int) string {
	if s == "" || len(s) > max {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == ':', c == '/', c == '@', c == '+':
		default:
			return ""
		}
	}
	return s
}

// InfraAttempt is one infrastructure failure of a command.
type InfraAttempt struct {
	SensorID      string       `json:"sensor_id"`
	Class         FailureClass `json:"class"`
	Tool          string       `json:"tool,omitempty"`
	ToolDigest    string       `json:"tool_digest,omitempty"`
	ContentDigest string       `json:"content_digest,omitempty"`
	At            time.Time    `json:"at"`
}

// FleetKey identifies a tool and content version for the fleet stop rule.
type FleetKey struct {
	Tool          string
	ToolDigest    string
	ContentDigest string
}

// Valid reports whether the key names a tool.
func (k FleetKey) Valid() bool { return k.Tool != "" }

// String is the key as a short, stable text (hashed for storage).
func (k FleetKey) String() string {
	return k.Tool + "|" + k.ToolDigest + "|" + k.ContentDigest
}

// Label is the key as a person reads it: tool and, when known, versions.
func (k FleetKey) Label() string {
	out := k.Tool
	if k.ToolDigest != "" {
		out += " " + shortDigest(k.ToolDigest)
	}
	if k.ContentDigest != "" {
		out += " with content " + shortDigest(k.ContentDigest)
	}
	return out
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// FleetBreakerWindow is how long failures on different sensors are
// counted together; FleetBreakerSensors how many different sensors trip
// the rule; FleetBreakerHold how long moves for the key stay stopped.
const (
	FleetBreakerWindow  = 30 * time.Minute
	FleetBreakerSensors = 2
	FleetBreakerHold    = 30 * time.Minute
)

// InfraStore keeps a command's infrastructure failures, re-queues it and
// holds the fleet stop rule. Implemented by the postgres command
// repository; every method is tenant-scoped.
type InfraStore interface {
	// CommandAttempts returns the failures recorded on the command.
	CommandAttempts(ctx context.Context, tenantID, commandID shared.ID) ([]InfraAttempt, error)
	// RequeueFailed puts the command back to pending, unpinned (its zone
	// kept), with att appended and its sensor excluded from later claims,
	// only while the command is still held under fence. One dispatch
	// attempt is counted. Reports whether it applied.
	RequeueFailed(ctx context.Context, tenantID, commandID shared.ID, fence Fence, att InfraAttempt, message string) (bool, error)
	// RecordFailedAttempt records att and the class on a command the
	// fenced sensor holds and is about to fail: the sensor joins failed_on
	// and the failure event carries the class. Reports nothing when the
	// fence no longer holds (the failing write then reports the lost
	// lease).
	RecordFailedAttempt(ctx context.Context, tenantID, commandID shared.ID, fence Fence, att InfraAttempt) error
	// RecordFleetFailure notes that sensorID failed key with class and
	// reports whether the fleet stop rule is in force for key (this
	// failure tripped it, or it was already tripped).
	RecordFleetFailure(ctx context.Context, tenantID shared.ID, key FleetKey, sensorID shared.ID, class FailureClass, now time.Time) (tripped bool, err error)
}

// AggregateInfraCauses is the failure reason of a command that ran out of
// attempts or sensors: every cause in order, the latest first in the text
// so readers that parse its prefix see the final one.
func AggregateInfraCauses(all []InfraAttempt) string {
	if len(all) == 0 {
		return ""
	}
	parts := make([]string, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		a := all[i]
		p := fmt.Sprintf("sensor %s: %s", shortSensor(a.SensorID), a.Class.Describe(a.Tool))
		parts = append(parts, p)
	}
	return fmt.Sprintf("Failed on %d sensor attempt(s) for infrastructure reasons, none about the target (%s)",
		len(all), strings.Join(parts, "; "))
}

func shortSensor(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// Describe is a short English phrase for the class (the API text; the
// console renders its own translated sentence from the timeline code).
func (c FailureClass) Describe(tool string) string {
	t := tool
	if t == "" {
		t = "the tool"
	}
	switch c {
	case ClassToolUnavailable:
		return t + " is not available"
	case ClassToolCrashed:
		return t + " crashed"
	case ClassResourceMemory:
		return "ran out of memory"
	case ClassResourceDisk:
		return "ran out of disk space"
	case ClassContentUnavailable:
		return "its content for " + t + " is not available"
	case ClassSensorOffline:
		return "the sensor stopped answering while it ran the task"
	case ClassSensorNetwork:
		return "its own network failed"
	case ClassDNSResolver:
		return "its DNS resolver failed"
	}
	return string(c)
}

// MovedMessage is the sentence stored on a command moved to another
// sensor.
func MovedMessage(a InfraAttempt, attempt, max int) string {
	return fmt.Sprintf("Moved to another sensor: sensor %s: %s (attempt %d of %d)",
		shortSensor(a.SensorID), a.Class.Describe(a.Tool), attempt, max)
}

// InfraClassFromText recovers an infrastructure class from a sensor's free
// failure text when it sent no class (a sensor that predates the field).
// The patterns are the messages the sensor runtime and the tool host
// produce; anything else is not classified (ok false), and the command
// fails as before.
func InfraClassFromText(msg string) (FailureClass, bool) {
	l := strings.ToLower(msg)
	has := func(needles ...string) bool {
		for _, n := range needles {
			if strings.Contains(l, n) {
				return true
			}
		}
		return false
	}
	switch {
	case has("executable file not found", "tool not installed", "binary not found", "digest mismatch", "tool is not available"):
		return ClassToolUnavailable, true
	case has("no space left on device", "disk full", "enospc"):
		return ClassResourceDisk, true
	case has("out of memory", "oom-kill", "oom kill", "oomkilled", "cannot allocate memory"):
		return ClassResourceMemory, true
	case has("tool crashed", "tool_crashed", "signal: segmentation fault", "signal: aborted", "exited without a result"):
		return ClassToolCrashed, true
	case has("content pack", "template pack", "content unavailable", "failed to fetch content"):
		return ClassContentUnavailable, true
	}
	return "", false
}
