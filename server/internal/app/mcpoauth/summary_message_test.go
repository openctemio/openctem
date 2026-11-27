package mcpoauth

import (
	"strings"
	"testing"
)

// A summary message is stored only with a dotted lower-case code and values
// within the size limit; anything else is dropped and the English summary
// alone is kept.
func TestSummaryMessageValid(t *testing.T) {
	ok := &SummaryMessage{Code: "mcp.add_finding_comment", Params: map[string]any{"content": "x", "client_visible": true}}
	if !ok.valid() {
		t.Fatal("a well-formed message was refused")
	}
	for _, m := range []*SummaryMessage{
		nil,
		{Code: ""},
		{Code: "MCP.Add"},
		{Code: "mcp..add"},
		{Code: strings.Repeat("a", 97)},
		{Code: "mcp.add", Params: map[string]any{"content": strings.Repeat("x", maxSummaryParamsBytes)}},
		{Code: "mcp.add", Params: map[string]any{"bad": make(chan int)}},
	} {
		if m.valid() {
			t.Fatalf("%+v was accepted", m)
		}
	}
}
