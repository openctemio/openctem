package command

// A completed command's result can still describe a run that did not finish:
// the tool exited non-zero, was killed by the job's time budget or a signal,
// or the sensor says it stopped the run. Older sensors deliver such a run as
// "completed", coverage "full", every target "done" (research/467 F6). Every
// path that settles coverage or closes something by absence reads the result
// through RunStopped and treats a stopped run as proving nothing.

import (
	"encoding/json"
	"strings"
)

// Reasons RunStopped gives (stable: metric labels and log values).
const (
	StopNonZeroExit   = "nonzero_exit"
	StopStatus        = "status_not_completed"
	StopSensorStopped = "sensor_stopped"
	StopUnreadable    = "result_unreadable"
)

// completedResultStatuses are the result `status` values of a run that ended
// by itself. Any other value (partial, timeout, failed, canceled, stopped,
// killed, ...) is a stop.
var completedResultStatuses = map[string]bool{"": true, "completed": true, "success": true, "succeeded": true}

// RunStopped reports whether a command result says the run did not finish
// by itself, and why. The result is the sensor's, untrusted: it can only
// withhold coverage this way, never add any. A run is stopped when:
//   - the result is not a JSON object;
//   - `exit_code` is present and not 0 (a legacy scanner killed by the job
//     budget reports -1, a semgrep-style tool that gave up reports 1);
//   - `status` is present and is not a completed status;
//   - the sensor says it stopped the run (`stopped: true` or a
//     `stop_reason`, top level or in metadata), or reports a `failure`.
//
// An empty result is not stopped: the command's own status decides.
func RunStopped(raw json.RawMessage) (bool, string) {
	if len(raw) == 0 || string(raw) == "null" {
		return false, ""
	}
	var r struct {
		ExitCode   *json.Number    `json:"exit_code"`
		Status     *string         `json:"status"`
		Stopped    bool            `json:"stopped"`
		StopReason string          `json:"stop_reason"`
		Failure    json.RawMessage `json:"failure"`
		Metadata   struct {
			Stopped    bool   `json:"stopped"`
			StopReason string `json:"stop_reason"`
		} `json:"metadata"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return true, StopUnreadable
	}
	if r.ExitCode != nil {
		if n, err := r.ExitCode.Int64(); err != nil || n != 0 {
			return true, StopNonZeroExit
		}
	}
	if r.Status != nil && !completedResultStatuses[strings.ToLower(strings.TrimSpace(*r.Status))] {
		return true, StopStatus
	}
	if r.Stopped || r.Metadata.Stopped || strings.TrimSpace(r.StopReason) != "" ||
		strings.TrimSpace(r.Metadata.StopReason) != "" || hasValue(r.Failure) {
		return true, StopSensorStopped
	}
	return false, ""
}

// hasValue reports whether a raw JSON member is set to something other than
// null.
func hasValue(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}
