package scanpolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SharedSensorsAccessLayers skips the rollout gate (RFC-100 §11) so database
// tests can run the real access layers while shared sensors are not ready.
// No production code may call it: everything outside tests must go through
// SharedSensorsAllowed. This walks the module's non-test Go files and fails
// on any other reference.
func TestSharedSensorsAccessLayers_NotUsedOutsideTests(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, _ := filepath.Abs("shared_sensors.go")
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == self {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "SharedSensorsAccessLayers") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("SharedSensorsAccessLayers (no rollout gate) used outside tests: %v; use SharedSensorsAllowed", offenders)
	}
}
