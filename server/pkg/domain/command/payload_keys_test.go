package command

import (
	"encoding/json"
	"testing"
)

func TestPayloadScanRunID(t *testing.T) {
	for payload, want := range map[string]string{
		`{"scan_run_id":"a","run_id":"b"}`: "a",
		`{"run_id":" b "}`:                 "b",
		`{}`:                               "",
		`not json`:                         "",
	} {
		if got := PayloadScanRunID(json.RawMessage(payload)); got != want {
			t.Errorf("%s: %q, want %q", payload, got, want)
		}
	}
}

// A path discovery job's request budget is read bounded.
func TestPayloadDiscoveryMaxRequests_Bounded(t *testing.T) {
	for payload, want := range map[string]int{
		`{"scanner_config":{"max_requests":250}}`:      250,
		`{"scanner_config":{"max_requests":99999999}}`: MaxDiscoveryRequests,
		`{"scanner_config":{"max_requests":-5}}`:       0,
		`{"config":{"max_requests":1000000000000}}`:    MaxDiscoveryRequests,
		`{}`: 0,
	} {
		if got := PayloadDiscoveryMaxRequests(json.RawMessage(payload)); got != want {
			t.Errorf("%s: %d, want %d", payload, got, want)
		}
	}
}
