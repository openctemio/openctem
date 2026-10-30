package command

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResultTruncated(t *testing.T) {
	for raw, want := range map[string]bool{
		``:                                   false,
		`not json`:                           false,
		`{}`:                                 false,
		`{"truncated": true}`:                true,
		`{"metadata": {"truncated": true}}`:  true,
		`{"metadata": {"truncated": false}}`: false,
		`{"truncated": "true"}`:              false, // only the JSON value true counts
		`{"metadata": {"truncated": 1}}`:     false,
	} {
		if got := ResultTruncated(json.RawMessage(raw)); got != want {
			t.Errorf("ResultTruncated(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestTruncatedTargets(t *testing.T) {
	payload := json.RawMessage(`{"targets": ["a.example.test", "b.example.test"]}`)
	cut := json.RawMessage(`{"metadata": {"truncated": true}}`)
	if got := TruncatedTargets(&Command{Type: CommandTypeScan, Payload: payload, Result: cut}); !reflect.DeepEqual(got, []string{"a.example.test", "b.example.test"}) {
		t.Errorf("scan = %v", got)
	}
	if got := TruncatedTargets(&Command{Type: CommandTypeConnectorScan, Payload: payload, Result: cut}); len(got) != 2 {
		t.Errorf("connector scan = %v", got)
	}
	for name, c := range map[string]*Command{
		"complete":     {Type: CommandTypeScan, Payload: payload, Result: json.RawMessage(`{}`)},
		"platform job": {Type: CommandTypeScan, Payload: payload, Result: cut, IsPlatformJob: true},
		"nil":          nil,
	} {
		if got := TruncatedTargets(c); got != nil {
			t.Errorf("%s = %v, want nil", name, got)
		}
	}
}
