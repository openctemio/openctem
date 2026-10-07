package scanrun

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func editStep(t *testing.T, pid shared.ID, key, tool string) *scanworkflow.Step {
	t.Helper()
	s, err := scanworkflow.NewStep(pid, key, key, 1, []string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	s.SetTool(tool)
	return s
}

func TestMatchSteps(t *testing.T) {
	pid := shared.NewID()
	toolID := shared.NewID()
	discover := editStep(t, pid, "discover", "subfinder")
	discover.ToolID = &toolID
	probe := editStep(t, pid, "probe", "httpx")
	scan := editStep(t, pid, "scan", "nuclei")
	current := []*scanworkflow.Step{discover, probe, scan}

	foreign := shared.NewID()
	inputs := []AddStepInput{
		{ID: discover.ID.String(), StepKey: "recon"}, // renamed, matched by id
		{StepKey: "probe"},                           // matched by key
		{ID: "temp-abc123", StepKey: "crawl"},        // client temp id: new
		{ID: foreign.String(), StepKey: "fuzz"},      // foreign id: ignored, new
	}
	built := []*scanworkflow.Step{
		editStep(t, pid, "recon", "subfinder"),
		editStep(t, pid, "probe", "naabu"),
		editStep(t, pid, "crawl", "katana"),
		editStep(t, pid, "fuzz", "ffuf"),
	}
	newIDs := []shared.ID{built[2].ID, built[3].ID}

	added, updated, removed := matchSteps(current, inputs, built)

	if built[0].ID != discover.ID || built[1].ID != probe.ID {
		t.Fatalf("matched steps lost their ids: %s %s", built[0].ID, built[1].ID)
	}
	if built[0].ToolID == nil || *built[0].ToolID != toolID {
		t.Fatal("same tool: tool_id must be kept")
	}
	if built[1].ToolID != nil {
		t.Fatal("tool changed: tool_id must not be carried over")
	}
	if built[2].ID != newIDs[0] || built[3].ID != newIDs[1] || built[3].ID == foreign {
		t.Fatal("unmatched entries must keep their fresh server ids")
	}
	if len(added) != 2 || len(updated) != 2 || len(removed) != 1 || removed[0].ID != scan.ID {
		t.Fatalf("added=%d updated=%d removed=%v", len(added), len(updated), removed)
	}
}

// An id claimed explicitly by a later entry wins over an earlier key match.
func TestMatchSteps_IDBeatsKey(t *testing.T) {
	pid := shared.NewID()
	a := editStep(t, pid, "a", "subfinder")
	b := editStep(t, pid, "b", "httpx")
	current := []*scanworkflow.Step{a, b}

	inputs := []AddStepInput{
		{StepKey: "b"},                    // would match b by key...
		{ID: b.ID.String(), StepKey: "a"}, // ...but b is named by id here
	}
	built := []*scanworkflow.Step{editStep(t, pid, "b", "x"), editStep(t, pid, "a", "y")}
	added, updated, removed := matchSteps(current, inputs, built)

	if built[1].ID != b.ID {
		t.Fatal("the entry naming b by id must get b")
	}
	if built[0].ID == b.ID {
		t.Fatal("a key match took a step another entry named by id")
	}
	if len(added) != 1 || len(updated) != 1 || len(removed) != 1 || removed[0].ID != a.ID {
		t.Fatalf("added=%d updated=%d removed=%d", len(added), len(updated), len(removed))
	}
}

func TestSanitizeLogValue(t *testing.T) {
	got := sanitizeLogValue("a\nb\r\x1bc")
	if got != "abc" {
		t.Fatalf("sanitizeLogValue = %q", got)
	}
	long := sanitizeLogValue(strings.Repeat("x", 300))
	if len(long) != 128 {
		t.Fatalf("not capped: %d", len(long))
	}
}
