package command

// A task result cut short (a deadline, the sensor's disk or output cap, a
// cancel after partial work) says so with `truncated: true` in the result
// metadata. A truncated result is partial by definition: it never proves
// that a target was covered and never proves that something absent from it
// is gone (the coverage settlement, the findings auto-resolve and the run's
// unfinished targets all read it through ResultTruncated).

import "encoding/json"

// ResultTruncated reports whether a command's result declares itself
// truncated, as `metadata.truncated` or a top-level `truncated`. Only the
// JSON value true counts. The result is the sensor's, untrusted: a sensor
// can only withhold coverage this way, never add any.
func ResultTruncated(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var r struct {
		Truncated bool `json:"truncated"`
		Metadata  struct {
			Truncated bool `json:"truncated"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return false
	}
	return r.Truncated || r.Metadata.Truncated
}

// TruncatedTargets are the targets of a completed scan or connector scan
// whose result is truncated: all of them, since a truncated result cannot
// say which ones it finished. Nil when the result is complete.
func TruncatedTargets(cmd *Command) []string {
	if cmd == nil || cmd.IsPlatformJob || len(cmd.Result) == 0 || !ResultTruncated(cmd.Result) {
		return nil
	}
	if cmd.Type != CommandTypeScan && cmd.Type != CommandTypeConnectorScan {
		return nil
	}
	return PayloadTargets(cmd.Payload)
}
