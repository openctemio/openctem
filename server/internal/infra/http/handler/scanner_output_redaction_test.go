package handler

import (
	"strings"
	"testing"
)

// Rows stored before ingest redaction existed are masked when read.
func TestScannerOutputResponse_MasksLegacyRows(t *testing.T) {
	legacy := "GET / HTTP/1.1\nAuthorization: Bearer abcdef1234567890abcdef\nHTTP/1.1 200\nSet-Cookie: sid=LEGACYSESSION; HttpOnly"
	got := scannerOutputResponse(legacy, nil)
	if got == nil {
		t.Fatal("nil response")
	}
	for _, leak := range []string{"abcdef1234567890abcdef", "LEGACYSESSION"} {
		if strings.Contains(got.Text, leak) {
			t.Fatalf("%q served: %s", leak, got.Text)
		}
	}
	if scannerOutputResponse("", nil) != nil {
		t.Fatal("empty output must give no block")
	}
}
