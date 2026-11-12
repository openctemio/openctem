package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The 409 body names each conflicting finding; the holding task's title and
// owner are null when the service found the task unreadable.
func TestRemediationHandleError_FindingsInOtherTask(t *testing.T) {
	title := "Patch the gateway"
	group := shared.NewID()
	f1, f2, t1, t2 := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	err := &remediation.FindingsInOtherTaskError{Conflicts: []remediation.FindingConflict{
		{FindingID: f1, FindingTitle: "a", TaskID: t1, TaskTitle: &title, AssigneeGroupID: &group, CanMove: true},
		{FindingID: f2, FindingTitle: "b", TaskID: t2},
	}}
	w := httptest.NewRecorder()
	(&RemediationTaskHandler{}).handleError(w, err)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Code    string `json:"code"`
		Details struct {
			Conflicts []map[string]any `json:"conflicts"`
		} `json:"details"`
	}
	if jerr := json.Unmarshal(w.Body.Bytes(), &body); jerr != nil {
		t.Fatal(jerr)
	}
	if body.Code != "FINDINGS_IN_OTHER_TASK" || len(body.Details.Conflicts) != 2 {
		t.Fatalf("body %s", w.Body.String())
	}
	c0, c1 := body.Details.Conflicts[0], body.Details.Conflicts[1]
	if c0["finding_id"] != f1.String() || c0["task_title"] != title || c0["assignee_group_id"] != group.String() || c0["can_move"] != true {
		t.Fatalf("readable conflict %v", c0)
	}
	if v, ok := c1["task_title"]; !ok || v != nil {
		t.Fatalf("task_title must be present and null: %v", c1)
	}
	if c1["assignee_user_id"] != nil || c1["assignee_group_id"] != nil || c1["can_move"] != false {
		t.Fatalf("unreadable conflict %v", c1)
	}
}

func TestParseConflicts(t *testing.T) {
	if r, err := parseConflicts(nil); err != nil || r.Resolves() {
		t.Fatalf("nil: %v %v", r, err)
	}
	id := shared.NewID()
	r, err := parseConflicts(&RemediationConflictsInput{Move: []string{id.String()}, MoveReason: "x"})
	if err != nil || len(r.Move) != 1 || r.Move[0] != id || r.MovableFrom != nil {
		t.Fatalf("move: %+v %v", r, err)
	}
	if _, err := parseConflicts(&RemediationConflictsInput{Move: []string{"nope"}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad id: %v", err)
	}
}
