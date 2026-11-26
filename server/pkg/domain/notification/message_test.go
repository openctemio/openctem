package notification

import (
	"strings"
	"testing"
)

func TestMessageValidate(t *testing.T) {
	ok := []*Message{
		nil,
		Msg("coverage.gap", "capability", "capture.screenshot", "count", 3),
		Msg("team.added"),
		Lines("coverage.digest", []*Message{Msg("coverage.gap"), nil}, "count", 1),
	}
	for _, m := range ok {
		if err := m.Validate(); err != nil {
			t.Fatalf("%+v: %v", m, err)
		}
	}
	bad := []*Message{
		{Code: ""},
		{Code: "Coverage.Gap"},
		{Code: "coverage..gap"},
		{Code: ".gap"},
		{Code: "coverage.gap<script>"},
		{Code: strings.Repeat("a", 97)},
		Msg("big", "v", strings.Repeat("x", MaxMessageParamsBytes)),
		Msg("bad.value", "ch", make(chan int)),
	}
	for _, m := range bad {
		if err := m.Validate(); err == nil {
			t.Fatalf("%q validated", m.Code)
		}
	}
}

// Msg ignores a key that is not a string and a trailing key without a value.
func TestMsgPairs(t *testing.T) {
	m := Msg("a.b", "n", 1, 2, "x", "tail")
	if len(m.Params) != 1 || m.Params["n"] != 1 {
		t.Fatalf("params %+v", m.Params)
	}
}

// A stored message round-trips; values that do not decode keep the code.
func TestParseMessage(t *testing.T) {
	if ParseMessage("", []byte(`{"a":1}`)) != nil {
		t.Fatal("no code must mean no message")
	}
	m := Msg("coverage.gap", "count", 2, "action", Msg("coverage.action.open_assets"))
	b, err := m.ParamsJSON()
	if err != nil {
		t.Fatal(err)
	}
	got := ParseMessage(m.Code, b)
	if got.Code != "coverage.gap" || got.Params["count"] != float64(2) {
		t.Fatalf("got %+v", got)
	}
	if a, _ := got.Params["action"].(map[string]any); a["code"] != "coverage.action.open_assets" {
		t.Fatalf("nested %+v", got.Params["action"])
	}
	if p := ParseMessage("x.y", []byte(`[1,2]`)); p.Code != "x.y" || p.Params != nil {
		t.Fatalf("bad values %+v", p)
	}
}

func TestNewNotificationKeepsMessage(t *testing.T) {
	m := Msg("team.added", "team", "Blue")
	n := NewNotification(NotificationParams{Title: "t", Message: m})
	if n.Message() != m {
		t.Fatal("message lost")
	}
}
