package routes

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// chi panics at start-up ("routing pattern must begin with '/'") on an empty
// pattern inside a Group, so the whole API refuses to start. A list route
// at a group's root is "/", never "". (develop 2026-10-12: scm_app.go.)
func TestNoEmptyRoutePatterns(t *testing.T) {
	empty := regexp.MustCompile(`\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\(""\s*,`)
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
		for i, line := range strings.Split(string(b), "\n") {
			if empty.MatchString(line) {
				t.Errorf("%s:%d: empty route pattern; use \"/\" for a group's root", f, i+1)
			}
		}
	}
}
