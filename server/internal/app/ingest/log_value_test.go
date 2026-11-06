package ingest

import (
	"strings"
	"testing"
)

func TestLogValue(t *testing.T) {
	if got := logValue("a\nb\r\nc"); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("line break kept: %q", got)
	}
	if got := logValue(strings.Repeat("x", 1000)); len(got) != maxLogValue {
		t.Fatalf("length %d", len(got))
	}
}
