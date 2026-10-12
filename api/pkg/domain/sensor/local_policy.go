package sensor

// The sensor-local policy report (RFC-040 §5.7): what a sensor says about
// the read-only policy its network owner installed. The policy is enforced
// on the sensor; the platform only shows this report (state, digest,
// summary) and uses it for the tenant's "private targets need a local
// policy" switch. Everything here comes from an untrusted process: it is
// reduced to bounded, safe values before it is stored, and it never widens
// what the platform dispatches.

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Local policy states a sensor reports.
const (
	// LocalPolicyEnforced: a policy is loaded and every job is checked.
	LocalPolicyEnforced = "enforced"
	// LocalPolicyAbsent: no policy; the sensor accepts any target outside
	// its built-in deny list.
	LocalPolicyAbsent = "absent"
	// LocalPolicyPaused is the display state of an enforced or absent
	// policy whose kill switch is engaged: the sensor runs no job.
	LocalPolicyPaused = "paused"
	// LocalPolicyUnknown is the display state of a sensor that never
	// reported a policy (an SDK before RFC-040, or protocol v1).
	LocalPolicyUnknown = "unknown"
)

// Limits on a reported local policy.
const (
	maxLocalPolicyWarnings   = 10
	maxLocalPolicyWarningLen = 300
	maxLocalPolicyNames      = 64
	maxLocalPolicyNameLen    = 64
	maxLocalPolicyPortsLen   = 200
	maxLocalPolicyCount      = 1 << 20
)

var (
	localPolicyDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	localPolicyNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	localPolicyPortsRE  = regexp.MustCompile(`^[0-9,-]+$`)
)

// LocalPolicyReport is a sensor's local policy report (heartbeat member
// and manifest member "local_policy").
type LocalPolicyReport struct {
	// State is LocalPolicyEnforced or LocalPolicyAbsent.
	State string `json:"state"`
	// Required is true when the sensor requires a local policy (new
	// installs): absent and required, it refuses every job with a network
	// target. Absent and not required is a legacy install that admits them.
	// Display and alert data only.
	Required bool `json:"required"`
	// Source is "file" or "env" (shorthand settings); "" when absent.
	Source string `json:"source,omitempty"`
	// Digest is "sha256:<hex>" of the policy; "" when absent.
	Digest string `json:"digest,omitempty"`
	// KillSwitch is true while the sensor owner stopped every job.
	KillSwitch bool `json:"kill_switch,omitempty"`
	// Summary is the shape of an enforced policy (never the ranges).
	Summary *LocalPolicySummary `json:"summary,omitempty"`
	// Warnings are the sensor's operator warnings.
	Warnings []string `json:"warnings,omitempty"`
}

// LocalPolicySummary is an enforced policy's shape.
type LocalPolicySummary struct {
	// TargetsAllow is the number of allow entries; -1 = no allow list.
	TargetsAllow int `json:"targets_allow"`
	// TargetsDeny is the number of deny entries.
	TargetsDeny int `json:"targets_deny"`
	// AllowPrivate: private ranges may be scanned.
	AllowPrivate bool `json:"allow_private"`
	// Ports is the allowed port list ("" = any).
	Ports string `json:"ports,omitempty"`
	// Tools and Checks are the allowed tools and job types (nil = any).
	Tools  []string `json:"tools,omitempty"`
	Checks []string `json:"checks,omitempty"`
	// AllowCustomTemplates and AllowInteractsh are the policy's switches.
	AllowCustomTemplates bool `json:"allow_custom_templates"`
	AllowInteractsh      bool `json:"allow_interactsh"`
	// MaxRPS and MaxJobSeconds are the caps (0 = not set).
	MaxRPS        int `json:"max_rps,omitempty"`
	MaxJobSeconds int `json:"max_job_seconds,omitempty"`
}

// SanitizeLocalPolicyReport returns r reduced to safe, bounded values, or
// nil when r is nil or its state is not one a sensor reports. Unknown
// values are dropped, never stored.
func SanitizeLocalPolicyReport(r *LocalPolicyReport) *LocalPolicyReport {
	if r == nil {
		return nil
	}
	state := strings.ToLower(strings.TrimSpace(r.State))
	if state != LocalPolicyEnforced && state != LocalPolicyAbsent {
		return nil
	}
	out := &LocalPolicyReport{State: state, Required: r.Required, KillSwitch: r.KillSwitch}
	if state == LocalPolicyEnforced {
		switch src := strings.ToLower(strings.TrimSpace(r.Source)); src {
		case "file", "env":
			out.Source = src
		}
		if d := strings.ToLower(strings.TrimSpace(r.Digest)); localPolicyDigestRE.MatchString(d) {
			out.Digest = d
		}
		out.Summary = sanitizeLocalPolicySummary(r.Summary)
	}
	for _, w := range r.Warnings {
		if len(out.Warnings) == maxLocalPolicyWarnings {
			break
		}
		if w = sanitizeWarning(w); w != "" {
			out.Warnings = append(out.Warnings, w)
		}
	}
	return out
}

func sanitizeLocalPolicySummary(s *LocalPolicySummary) *LocalPolicySummary {
	if s == nil {
		return nil
	}
	out := &LocalPolicySummary{
		TargetsAllow:         clampCount(s.TargetsAllow, -1),
		TargetsDeny:          clampCount(s.TargetsDeny, 0),
		AllowPrivate:         s.AllowPrivate,
		AllowCustomTemplates: s.AllowCustomTemplates,
		AllowInteractsh:      s.AllowInteractsh,
		MaxRPS:               clampCount(s.MaxRPS, 0),
		MaxJobSeconds:        clampCount(s.MaxJobSeconds, 0),
		Tools:                sanitizeNames(s.Tools),
		Checks:               sanitizeNames(s.Checks),
	}
	if p := strings.TrimSpace(s.Ports); len(p) <= maxLocalPolicyPortsLen && localPolicyPortsRE.MatchString(p) {
		out.Ports = p
	}
	return out
}

func clampCount(n, minimum int) int {
	if n < minimum {
		return minimum
	}
	return min(n, maxLocalPolicyCount)
}

// sanitizeNames keeps well-formed tool or job-type names; nil stays nil
// ("any"), an empty list stays empty ("none").
func sanitizeNames(names []string) []string {
	if names == nil {
		return nil
	}
	out := make([]string, 0, min(len(names), maxLocalPolicyNames))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if len(out) == maxLocalPolicyNames {
			break
		}
		if len(n) <= maxLocalPolicyNameLen && localPolicyNameRE.MatchString(n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// sanitizeWarning keeps printable text without control or bidi characters,
// at most maxLocalPolicyWarningLen runes.
func sanitizeWarning(w string) string {
	var b strings.Builder
	n := 0
	for _, r := range w {
		if n == maxLocalPolicyWarningLen {
			break
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x200e && r <= 0x200f) ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// DisplayState is the state the console shows: paused while the kill
// switch is engaged, else the reported state; unknown without a report.
func (r *LocalPolicyReport) DisplayState() string {
	switch {
	case r == nil:
		return LocalPolicyUnknown
	case r.KillSwitch:
		return LocalPolicyPaused
	default:
		return r.State
	}
}

// Enforced reports whether the sensor enforces a local policy.
func (r *LocalPolicyReport) Enforced() bool {
	return r != nil && r.State == LocalPolicyEnforced
}

// MergeLocalPolicyReport combines a new report with the stored one: a slim
// heartbeat carries the state, digest and kill switch only, so the stored
// summary and warnings of the same policy (same state and digest) are kept.
func MergeLocalPolicyReport(stored, next *LocalPolicyReport) *LocalPolicyReport {
	if next == nil {
		return stored
	}
	if stored == nil || next.Summary != nil || next.State != stored.State || next.Digest != stored.Digest {
		return next
	}
	merged := *next
	if merged.Summary == nil {
		merged.Summary = stored.Summary
	}
	if merged.Warnings == nil {
		merged.Warnings = stored.Warnings
	}
	return &merged
}

// LocalPolicyEvent is the timeline entry for a change of the reported local
// policy: its display state (enforced, absent, paused) or its digest. The
// first report of a sensor is recorded too. ok is false when nothing
// changed or the sensor has no tenant.
func LocalPolicyEvent(prev *Sensor, next *LocalPolicyReport, at time.Time) (Event, bool) {
	if prev == nil || prev.TenantID == nil || next == nil {
		return Event{}, false
	}
	old := prev.LocalPolicy
	from, to := old.DisplayState(), next.DisplayState()
	oldDigest := ""
	if old != nil {
		oldDigest = old.Digest
	}
	if from == to && oldDigest == next.Digest {
		return Event{}, false
	}
	var summary string
	switch {
	case to == LocalPolicyPaused:
		summary = "Paused by the local kill switch"
	case from == LocalPolicyPaused:
		summary = "Local kill switch released"
	case to == LocalPolicyEnforced && from == LocalPolicyEnforced:
		summary = "Local policy changed"
	case to == LocalPolicyEnforced:
		summary = "Local policy enforced"
	default:
		summary = "No local policy"
	}
	details := map[string]any{"from": from, "to": to}
	if oldDigest != "" {
		details["digest_from"] = oldDigest
	}
	if next.Digest != "" {
		details["digest_to"] = next.Digest
	}
	return NewEvent(*prev.TenantID, prev.ID, EventLocalPolicyChanged, at, summary, details), true
}

// LocalPolicyRefusalPrefix starts the failure reason of every job a sensor
// refused under its local policy (sdk-go core.LocalPolicyError).
const LocalPolicyRefusalPrefix = "refused by local policy: "

// LocalPolicyRefusal parses a command's failure reason: the policy rule
// that refused it ("targets.deny", "kill_switch", …) and ok when the
// reason is a local-policy refusal.
func LocalPolicyRefusal(errorMessage string) (rule string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(errorMessage), LocalPolicyRefusalPrefix)
	if !found {
		return "", false
	}
	rule, _, _ = strings.Cut(rest, ":")
	rule = strings.TrimSpace(rule)
	if len(rule) > maxLocalPolicyNameLen || !localPolicyRuleRE.MatchString(rule) {
		rule = "unknown"
	}
	return rule, true
}

var localPolicyRuleRE = regexp.MustCompile(`^[a-z][a-z_.]*$`)

// LocalPolicyRefusalEvent is the timeline entry of a job the sensor refused
// under its local policy (RFC-040 detection A11). Identical refusals (same
// rule) within the coalescing window fold into one entry.
func LocalPolicyRefusalEvent(tenantID, sensorID shared.ID, commandID, rule, reason string, at time.Time) Event {
	return NewEvent(tenantID, sensorID, EventJobRefusedByLocalPolicy, at, "Refused a job under the local policy ("+rule+")",
		map[string]any{"command_id": commandID, "rule": rule, "reason": sanitizeWarning(reason)})
}
