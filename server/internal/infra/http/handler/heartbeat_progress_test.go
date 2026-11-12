package handler

import (
	"encoding/json"
	"reflect"
	"strconv"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
)

// The heartbeat's progress reaches the sensor service as sent (untrusted;
// the repository bounds it), at most MaxProgressEntries entries.
func TestHeartbeatProgress(t *testing.T) {
	var req HeartbeatRequest
	if err := json.Unmarshal([]byte(`{"status":"ok","running":["c1"],"progress":{"c1":{"done":3,"total":72,"released_keys":["a.example.com"]}}}`), &req); err != nil {
		t.Fatal(err)
	}
	got := req.commandProgress()
	if len(got) != 1 || !reflect.DeepEqual(got["c1"], commanddom.Progress{Done: 3, Total: 72, ReleasedKeys: []string{"a.example.com"}}) {
		t.Fatalf("progress = %+v", got)
	}
	if (&HeartbeatRequest{}).commandProgress() != nil {
		t.Fatal("no progress must be nil")
	}
	big := HeartbeatRequest{Progress: map[string]HeartbeatProgress{}}
	for i := range commanddom.MaxProgressEntries + 50 {
		big.Progress[strconv.Itoa(i)] = HeartbeatProgress{Done: 1, Total: 2}
	}
	if n := len(big.commandProgress()); n != commanddom.MaxProgressEntries {
		t.Fatalf("entries = %d, want %d", n, commanddom.MaxProgressEntries)
	}
}
