package rekey

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A console setting that stores a secret encrypted inside its platform_settings
// value declares the field with a json tag ending in "_encrypted" and the row
// with `const SettingKey = "..."` in the same package. Every such field must
// be in the rekey registry, or a key rotation leaves it sealed under the old
// key and the feature stops working.
func TestRegistryCoversEveryEncryptedConsoleSetting(t *testing.T) {
	tagRE := regexp.MustCompile("json:\"([a-z_]+_encrypted)[,\"]")
	keyRE := regexp.MustCompile(`(?m)^const SettingKey\s*=\s*"([^"]+)"`)

	covered := map[string]bool{}
	for _, loc := range registry {
		if j, ok := loc.(jsonField); ok && j.table == "platform_settings" && len(j.path) == 1 {
			covered[j.where+"|"+j.path[0]] = true
		}
	}

	root := filepath.Join("..", "..", "..", "internal", "app")
	dirs, err := filepath.Glob(filepath.Join(root, "platform*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no console setting packages found: %v", err)
	}
	found := 0
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		var tags []string
		var key string
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f) //nolint:gosec // G304: fixed source tree walked by the test
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range tagRE.FindAllStringSubmatch(string(b), -1) {
				tags = append(tags, m[1])
			}
			if m := keyRE.FindStringSubmatch(string(b)); m != nil {
				key = m[1]
			}
		}
		for _, tag := range tags {
			found++
			if key == "" {
				t.Errorf("%s: encrypted field %q but no `const SettingKey`", dir, tag)
				continue
			}
			if !covered["key = '"+key+"'|"+tag] {
				t.Errorf("platform_settings %q field %q is encrypted but not in the rekey registry", key, tag)
			}
		}
	}
	if found < 5 {
		t.Fatalf("scan found %d encrypted console fields, expected at least 5: the scan is broken", found)
	}
}
