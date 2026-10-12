// Package sensorvocab is the CI guard for the agent → sensor rename
// (RFC-023 §9.5). The API speaks sensor vocabulary everywhere except the
// places that must keep the old name because something already deployed, or
// already written, depends on it. The test in this package fails on any Go
// identifier, package name or Go file path that says "agent" outside that
// allow-list, so the old vocabulary cannot creep back in.
//
// To rename code written on a branch that predates the rename, run
// scripts/rename/sensor-rename.sh. If an identifier genuinely means something
// other than a sensor (an LLM agent, the HTTP User-Agent), add it to
// AllowedIdents with the reason.
package sensorvocab

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// AllowedPaths are repo-relative path prefixes whose code may use the old
// vocabulary.
var AllowedPaths = map[string]string{
	"scripts/rename/":         "the rename tooling names the old vocabulary to find it",
	"tools/lint/sensorvocab/": "this guard",
}

// AllowedIdents are identifiers that contain "agent" but do not mean a sensor.
var AllowedIdents = map[string]string{
	"AIModeAgent":                        "AI triage mode backed by a self-hosted LLM agent",
	"ModuleAITriageAgent":                "module for that AI agent mode",
	"TestAITriage_GetAIConfig_AgentMode": "tests that AI agent mode",
	"ScannerAgentID":                     "a third-party scanner's own endpoint agent id (CTIS identity_hints.agent_id), not a sensor",
}

// The HTTP User-Agent is not a sensor.
var userAgent = regexp.MustCompile(`(?i)user_?agent`)

// Violation is one place the old vocabulary appears where it should not.
type Violation struct {
	Pos  string
	Name string
}

func (v Violation) String() string { return v.Pos + ": " + v.Name }

func mentionsAgent(name string) bool {
	return strings.Contains(strings.ToLower(userAgent.ReplaceAllString(name, "")), "agent")
}

func allowedPath(rel string) bool {
	for p := range AllowedPaths {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// Scan walks every Go file under root and returns the violations, sorted.
func Scan(root string) ([]Violation, error) {
	var out []Violation
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if allowedPath(rel + "/") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if mentionsAgent(rel) {
			out = append(out, Violation{Pos: rel, Name: "file path"})
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if mentionsAgent(x.Name) {
					if _, ok := AllowedIdents[x.Name]; !ok {
						p := fset.Position(x.Pos())
						out = append(out, Violation{Pos: fmt.Sprintf("%s:%d", rel, p.Line), Name: x.Name})
					}
				}
			case *ast.ImportSpec:
				if p := strings.Trim(x.Path.Value, `"`); strings.HasPrefix(p, "github.com/openctemio/openctem/api/") && mentionsAgent(p) {
					out = append(out, Violation{Pos: fmt.Sprintf("%s:%d", rel, fset.Position(x.Pos()).Line), Name: "import " + p})
				}
			}
			return true
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, err
}
