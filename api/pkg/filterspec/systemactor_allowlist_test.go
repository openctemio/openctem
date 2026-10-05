package filterspec

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// systemActorAllowlist names the only files (relative to api/) that may
// build a SystemActor, which compiles a filter without the data-scope
// predicate. Add a file only for background work whose output only
// administrators see, and say why in a comment here.
var systemActorAllowlist = map[string]string{
	// (none yet)
}

// TestSystemActorCallSitesAreAllowlisted fails when non-test code outside
// this package calls filterspec.SystemActor from a file not in the list.
func TestSystemActorCallSitesAreAllowlisted(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "pkg/filterspec/") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "filterspec.SystemActor(") {
			if _, ok := systemActorAllowlist[rel]; !ok {
				offenders = append(offenders, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("filterspec.SystemActor skips the data scope; these files are not allowlisted (systemactor_allowlist_test.go): %v", offenders)
	}
}
