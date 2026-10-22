package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Handlers must read the request id from the context (validated by the
// request-id middleware), never from the raw header: a raw read lets a client
// write arbitrary strings into audit rows.
func TestHandlersDoNotReadRawRequestIDHeader(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `Header.Get("X-Request-ID")`) {
			t.Errorf("%s reads the raw X-Request-ID header; use middleware.GetRequestID(r.Context())", f)
		}
	}
}
