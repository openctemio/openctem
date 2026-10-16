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
