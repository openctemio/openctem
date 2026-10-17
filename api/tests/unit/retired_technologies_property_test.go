package unit

// The technologies detected on an asset live in asset_technologies
// (docs/rfcs/RFC-112-asset-technologies.md). assets.properties.technologies
// is retired: no code may read it. This test fails on any read in the API
// (Go, SQL) or the web console. Report input (a CTIS asset's
// properties.technologies, which sensors still send) is read through a key
// list in internal/app/ingest and does not match these patterns.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var retiredTechReads = []*regexp.Regexp{
	regexp.MustCompile(`properties\s*->>?\s*'technolog(y|ies)'`),
	regexp.MustCompile(`properties\s*#>>?\s*'\{technologies`),
	regexp.MustCompile(`properties\s*\?\s*'technologies'`),
	regexp.MustCompile(`(?i)(props|properties|existing|merged|metadata)(\(\))?\s*\[\s*"technolog(y|ies)"\s*\]`),
	regexp.MustCompile(`GetProperty\(\s*"technolog(y|ies)"`),
	// web console
	regexp.MustCompile(`prop\(\s*\w+\s*,\s*['"]technologies['"]`),
	regexp.MustCompile(`(metadata|properties)\??\.technologies\b`),
	regexp.MustCompile(`(metadata|properties)\??\.\[\s*['"]technologies['"]\s*\]`),
	regexp.MustCompile(`keys:\s*\[\s*['"]technologies['"]`),
	regexp.MustCompile(`tech:\s*\[\s*['"]technologies['"]`),
}

// retiredTechAllowed are the files that remove the retired key.
var retiredTechAllowed = map[string]bool{
	"internal/infra/postgres/asset_technology_repository.go":          true,
	"internal/infra/postgres/asset_technology_backfill_repository.go": true,
}

func TestRetiredTechnologiesPropertyIsNeverRead(t *testing.T) {
	apiRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	roots := []struct {
		dir  string
		exts []string
	}{
		{filepath.Join(apiRoot, "internal"), []string{".go"}},
		{filepath.Join(apiRoot, "pkg"), []string{".go"}},
		{filepath.Join(apiRoot, "cmd"), []string{".go"}},
		{filepath.Join(apiRoot, "..", "web", "src"), []string{".ts", ".tsx"}},
	}
	scanned := 0
	for _, root := range roots {
		if _, err := os.Stat(root.dir); err != nil {
			continue // the web tree is absent in an api-only checkout
		}
		err := filepath.WalkDir(root.dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if n := d.Name(); n == "node_modules" || n == ".next" || n == "__tests__" || n == "__fixtures__" {
					return filepath.SkipDir
				}
				return nil
			}
			if !hasExt(path, root.exts) || strings.HasSuffix(path, "_test.go") ||
				strings.Contains(path, ".test.") || strings.Contains(path, ".spec.") {
				return nil
			}
			rel, _ := filepath.Rel(apiRoot, path)
			if retiredTechAllowed[filepath.ToSlash(rel)] {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			for i, line := range strings.Split(string(b), "\n") {
				if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
					strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "--") {
					continue // a comment names the key, it does not read it
				}
				for _, re := range retiredTechReads {
					if re.MatchString(line) {
						t.Errorf("%s:%d reads the retired properties.technologies (use asset_technologies / asset.technologies): %s",
							rel, i+1, strings.TrimSpace(line))
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no files")
	}
}

func hasExt(path string, exts []string) bool {
	for _, e := range exts {
		if strings.HasSuffix(path, e) {
			return true
		}
	}
	return false
}
