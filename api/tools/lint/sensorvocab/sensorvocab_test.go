package sensorvocab

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNoAgentVocabularyOutsideAllowList(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	violations, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) == 0 {
		return
	}
	lines := make([]string, len(violations))
	for i, v := range violations {
		lines[i] = v.String()
	}
	t.Fatalf("%d identifier(s) use the pre-sensor 'agent' vocabulary (RFC-023 §9.5):\n  %s\n\n"+
		"Rename them (scripts/rename/sensor-rename.sh does it type-safely), or — only if the word "+
		"means something other than "+
		"a sensor — add the identifier to AllowedIdents with the reason.",
		len(violations), strings.Join(lines, "\n  "))
}

func TestGuardCatchesTheOldVocabulary(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"agentID", true}, {"AgentService", true}, {"platform_agent_id", true},
		{"UserAgent", false}, {"userAgent", false}, {"actorUserAgent", false}, {"sensorID", false},
	} {
		if got := mentionsAgent(c.name); got != c.want {
			t.Errorf("mentionsAgent(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
