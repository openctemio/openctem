package handler

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Code must read the request id from the context (validated by the
// request-id middleware), never from the raw header: a raw read lets a client
// write arbitrary strings into audit rows and logs. The middleware itself is
// the one place that reads the header, to validate it.
func TestNoRawRequestIDHeaderReads(t *testing.T) {
	apiRoot := filepath.Join("..", "..", "..", "..")
	allowed := filepath.Join("internal", "infra", "http", "middleware", "middleware.go")
	scanned := 0
	for _, dir := range []string{"internal", "pkg", "cmd"} {
		root := filepath.Join(apiRoot, dir)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(apiRoot, path)
			if rel == allowed {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			if strings.Contains(string(b), `Header.Get("X-Request-ID")`) {
				t.Errorf("%s reads the raw X-Request-ID header; use middleware.GetRequestID(r.Context())", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files; the walk root is wrong", scanned)
	}
}
