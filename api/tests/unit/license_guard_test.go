package unit

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

// Grant keys (what a license can add) are registered, described, documented
// and distinct from every limit key and deniable feature, so a license can
// never name a Community feature or a limit (RFC-145 §5).
func TestGrantKeysAreRegisteredAndDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/architecture/limits.md")
	if err != nil {
		t.Fatal(err)
	}
	keys := limits.GrantKeys()
	if len(keys) != len(limits.Grants) {
		t.Fatalf("GrantKeys() lists %d keys, the registry has %d", len(keys), len(limits.Grants))
	}
	limitKeys := map[string]bool{}
	for _, k := range limits.Keys {
		limitKeys[string(k)] = true
	}
	for _, k := range keys {
		info := limits.Grants[k]
		if strings.TrimSpace(info.Description) == "" || strings.TrimSpace(info.OnExpiry) == "" {
			t.Errorf("grant key %q needs a description and what stops on expiry", k)
		}
		if info.Kind != limits.GrantKindInstance && info.Kind != limits.GrantKindTenant {
			t.Errorf("grant key %q has kind %q", k, info.Kind)
		}
		if !strings.Contains(string(doc), "`"+string(k)+"`") {
			t.Errorf("docs/architecture/limits.md does not list grant key `%s`", k)
		}
		if limitKeys[string(k)] || limits.IsFeature(string(k)) {
			t.Errorf("grant key %q is also a limit key or a deniable feature", k)
		}
		if _, ok := moduledom.Lookup(string(k)); ok {
			t.Errorf("grant key %q is also a module id", k)
		}
	}
}

// Production code trusts only the license roots compiled into
// pkg/licensekey: it never builds a verifier with other roots and never
// imports the public test keys.
func TestLicenseRootsOnlyFromTheBuild(t *testing.T) {
	scanned := 0
	for _, root := range []string{"../../internal", "../../pkg", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if strings.HasSuffix(filepath.ToSlash(path), "pkg/licensekey/licensekeytest") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			src := string(raw)
			if strings.Contains(src, "licensekey/licensekeytest") {
				t.Errorf("%s imports the public license test keys", path)
			}
			if strings.Contains(src, "licensekey.NewVerifier(") {
				t.Errorf("%s builds a license verifier with its own roots; use licensekey.Default()", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files: wrong working directory?", scanned)
	}
}
