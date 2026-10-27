// Package internalrefs keeps internal design references (RFC numbers,
// research notes, decision and question ids) out of everything a user or
// operator reads: API responses, error and log text, metric help, sensor
// warnings, the generated API reference, shipped data files. Go comments
// may keep them, except the swagger annotation blocks, which become the
// published API reference. Test files and docs/ are exempt.
package internalrefs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var internalRef = regexp.MustCompile(`RFC-\d+|research/\d+|\((?:Q|D)\d+\b[^)]*\)|\bQ\d+ \([a-z]\)|[Oo]wner decision|phase P\d`)

func apiRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..", "..")
}

func skipDir(rel, name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "testdata", "docs", "migrations":
		return true
	}
	return rel == filepath.Join("tools", "lint", "internalrefs")
}

// dataFile reports whether a non-Go file ships to users: schemas, the sensor
// protocol spec and the config templates operators download.
func dataFile(rel string) bool {
	// The seccomp profile is pinned by digest to the sensor release's copy,
	// so its comment can only change together with a sensor release.
	if strings.HasSuffix(rel, "seccomp/sensor.json") {
		return false
	}
	ext := filepath.Ext(rel)
	if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".tmpl" {
		return false
	}
	for _, dir := range []string{"api", "pkg", "internal", "configs"} {
		if strings.HasPrefix(rel, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// swaggerGroup reports whether a comment group is an API annotation block.
func swaggerGroup(g *ast.CommentGroup) bool {
	for _, c := range g.List {
		txt := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if strings.HasPrefix(txt, "@Summary") || strings.HasPrefix(txt, "@Router") {
			return true
		}
	}
	return false
}

func TestNoInternalReferencesInUserFacingText(t *testing.T) {
	root := apiRoot(t)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel != "." && skipDir(rel, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"):
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
			if perr != nil {
				t.Errorf("parse %s: %v", rel, perr)
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING && internalRef.MatchString(l.Value) {
					t.Errorf("%s:%d: string cites an internal reference (%q); say it plainly",
						rel, fset.Position(l.Pos()).Line, internalRef.FindString(l.Value))
				}
				return true
			})
			for _, g := range f.Comments {
				if !swaggerGroup(g) {
					continue
				}
				for _, c := range g.List {
					if internalRef.MatchString(c.Text) {
						t.Errorf("%s:%d: API annotation cites an internal reference (%q); it is published in the API reference",
							rel, fset.Position(c.Pos()).Line, internalRef.FindString(c.Text))
					}
				}
			}
		case dataFile(rel):
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				if m := internalRef.FindString(line); m != "" {
					t.Errorf("%s:%d: cites an internal reference (%q)", rel, i+1, m)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPattern(t *testing.T) {
	for _, s := range []string{"(RFC-040 P2)", "see research/134", "(D7)", "(Q4 (a))", "owner decision", "phase P0"} {
		if !internalRef.MatchString(s) {
			t.Errorf("pattern misses %q", s)
		}
	}
	for _, s := range []string{"RFC3339", "RFC 7644", "expected RFC 9110", "Q&A", "(T2)"} {
		if internalRef.MatchString(s) {
			t.Errorf("pattern flags %q", s)
		}
	}
}
