package metrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// WithLabelValues panics at runtime when it gets a different number of values
// than the metric declares labels, and the compiler cannot see it. This test
// reads every metric's declared labels and checks every
// <pkg>.<Metric>.WithLabelValues(...) call in the API source against them,
// so a branch written against an older label set fails here, not in
// production.
func TestEveryWithLabelValuesCallMatchesTheDeclaredLabels(t *testing.T) {
	declared := map[string]int{}
	def := regexp.MustCompile(`(?s)\n\t(\w+) = promauto\.New\w+\((.*?)\n\t\)`)
	labels := regexp.MustCompile(`\[\]string\{([^}]*)\}`)
	for _, f := range []string{"metrics.go", "security_defenses.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range def.FindAllStringSubmatch(string(raw), -1) {
			lm := labels.FindStringSubmatch(m[2])
			if lm == nil {
				continue // not a Vec
			}
			n := 0
			for _, l := range strings.Split(lm[1], ",") {
				if strings.TrimSpace(l) != "" {
					n++
				}
			}
			declared[m[1]] = n
		}
	}
	if len(declared) == 0 {
		t.Fatal("no metric definitions found")
	}

	call := regexp.MustCompile(`\b(?:metrics|app)\.(\w+)\.WithLabelValues\(`)
	root := filepath.Join("..", "..")
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			if name := d.Name(); name == "node_modules" || name == "vendor" || name == "testdata" || name == "migrations" || name == "docs" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(raw)
		for _, loc := range call.FindAllStringSubmatchIndex(src, -1) {
			name := src[loc[2]:loc[3]]
			want, ok := declared[name]
			if !ok {
				continue
			}
			args, spread := callArgs(src[loc[1]:])
			if spread {
				continue
			}
			checked++
			if args != want {
				line := strings.Count(src[:loc[0]], "\n") + 1
				t.Errorf("%s:%d: %s.WithLabelValues has %d value(s), the metric declares %d label(s)",
					path, line, name, args, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no WithLabelValues call found; the scan is broken")
	}
}

// callArgs counts the top-level arguments of a call whose opening paren was
// just consumed, and reports a variadic spread (args...).
func callArgs(s string) (int, bool) {
	depth, n, any := 0, 0, false
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr != 0 {
			if c == '\\' && inStr != '`' {
				i++
			} else if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			inStr = c
			any = true
		case '(', '[', '{':
			depth++
			any = true
		case ')', ']', '}':
			if depth == 0 {
				if strings.HasSuffix(strings.TrimSpace(s[:i]), "...") {
					return 0, true
				}
				if any {
					n++
				}
				return n, false
			}
			depth--
		case ',':
			if depth == 0 {
				n++
				any = false
			}
		case ' ', '\t', '\n':
		default:
			any = true
		}
	}
	return n, false
}
