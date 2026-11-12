package remediation

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMoveWarnings(t *testing.T) {
	a, b, u, g := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	src := &Task{ActionID: a, AssigneeUserID: &u, State: TaskStateOpen, Counts: TaskCounts{Total: 3}}
	same := &Task{ActionID: a, AssigneeUserID: &u, State: TaskStateInProgress}
	if w := MoveWarnings(src, same, 1); len(w) != 0 {
		t.Fatalf("same fix and owner: no warning, got %v", w)
	}
	other := &Task{ActionID: b, AssigneeGroupID: &g, State: TaskStateVerifying}
	got := map[MoveWarning]bool{}
	for _, w := range MoveWarnings(src, other, 3) {
		got[w] = true
	}
	for _, want := range []MoveWarning{MoveWarnDifferentFix, MoveWarnDifferentOwner, MoveWarnTargetVerifying, MoveWarnEmptiesSource} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	src.State = TaskStateVerifying
	if w := MoveWarnings(src, nil, 1); len(w) != 1 || w[0] != MoveWarnSourceVerifying {
		t.Fatalf("detach from a verifying task: %v", w)
	}
}

func TestTaskMoveEventComments(t *testing.T) {
	from, to := shared.NewID(), shared.NewID()
	cases := []struct {
		name     string
		ev       TaskMoveEvent
		src, dst string
	}{
		{"move", TaskMoveEvent{Kind: MoveKindMove, FromTaskID: from, FromTitle: "A", ToTaskID: &to, ToTitle: "B", Findings: 3},
			`3 findings moved to task "B".`, `3 findings moved in from task "A".`},
		{"move empties the source", TaskMoveEvent{Kind: MoveKindMove, FromTaskID: from, FromTitle: "A", ToTaskID: &to, ToTitle: "B", Findings: 1, SourceArchived: true},
			`1 finding moved to task "B". The task has no findings left and is archived.`, `1 finding moved in from task "A".`},
		{"detach", TaskMoveEvent{Kind: MoveKindDetach, FromTaskID: from, FromTitle: "A", Findings: 2},
			`2 findings taken out of this task.`, ""},
		{"split", TaskMoveEvent{Kind: MoveKindSplit, FromTaskID: from, FromTitle: "A", ToTaskID: &to, ToTitle: "A (team)", Findings: 2},
			`2 findings split off into a new task "A (team)".`, `Created from 2 findings split off task "A".`},
		{"merge", TaskMoveEvent{Kind: MoveKindMerge, FromTaskID: from, FromTitle: "A", ToTaskID: &to, ToTitle: "B", Findings: 4, SourceArchived: true},
			`This task was merged into "B" (4 findings).`, `Task "A" was merged into this one (4 findings).`},
	}
	for _, c := range cases {
		got := c.ev.Comments()
		want := 1
		if c.dst != "" {
			want = 2
		}
		if len(got) != want {
			t.Fatalf("%s: %d comments, want %d", c.name, len(got), want)
		}
		if got[0].TaskID != from || got[0].Body != c.src {
			t.Errorf("%s: source comment %q", c.name, got[0].Body)
		}
		if c.dst != "" && (got[1].TaskID != to || got[1].Body != c.dst) {
			t.Errorf("%s: target comment %q", c.name, got[1].Body)
		}
	}
	if got := (TaskMoveEvent{Kind: MoveKindMove, FromTaskID: from, ToTaskID: &to}).Comments(); got != nil {
		t.Errorf("nothing moved: no comment, got %v", got)
	}
}
