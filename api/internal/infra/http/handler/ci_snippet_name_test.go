package handler

import (
	"strings"
	"testing"
)

// A scan name is written into the generated pipeline file. A newline in it
// must not end the comment line it sits on and add YAML keys or Groovy code.
func TestCISnippets_ScanNameStaysOnTheCommentLine(t *testing.T) {
	hostile := "x\njobs:\n  evil:\n    runs-on: ubuntu-latest\n// }\r\npipeline { agent any }"
	for name, gen := range map[string]func(string, string, string) string{
		"github":  generateGitHubActionsSnippet,
		"gitlab":  generateGitLabCISnippet,
		"jenkins": generateJenkinsfileSnippet,
	} {
		t.Run(name, func(t *testing.T) {
			out := gen(hostile, "00000000-0000-0000-0000-000000000001", "")
			first, _, _ := strings.Cut(out, "\n")
			if !strings.Contains(first, "x jobs:") || !strings.Contains(first, "pipeline { agent any }") {
				t.Fatalf("the name must stay on the first (comment) line: %q", first)
			}
			for _, line := range strings.Split(out, "\n")[1:] {
				if strings.Contains(line, "evil") {
					t.Fatalf("the name escaped its comment line: %q", line)
				}
			}
		})
	}
}
