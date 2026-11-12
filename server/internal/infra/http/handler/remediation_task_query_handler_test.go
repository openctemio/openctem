package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	queryapp "github.com/openctemio/openctem/api/internal/app/query"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The conflict answer has the shared shape: 409 FINDINGS_IN_OTHER_TASK with
// details.conflicts; a task the caller may not read shows null title and
// owner (count-only).
func TestQueryTaskConflictShape(t *testing.T) {
	h := &RemediationTaskHandler{logger: logger.NewNop()}
	title := "Patch openssl"
	user := shared.NewID()
	rec := httptest.NewRecorder()
	h.handleQueryError(rec, &remediation.FindingsInOtherTaskError{Conflicts: []remediation.FindingConflict{
		{FindingID: shared.NewID(), FindingTitle: "CVE-1", TaskID: shared.NewID(), TaskTitle: &title, AssigneeUserID: &user, CanMove: true},
		{FindingID: shared.NewID(), FindingTitle: "CVE-2", TaskID: shared.NewID()},
	}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Code    string `json:"code"`
		Details struct {
			Conflicts []map[string]any `json:"conflicts"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "FINDINGS_IN_OTHER_TASK" || len(body.Details.Conflicts) != 2 {
		t.Fatalf("body = %s", rec.Body)
	}
	c0, c1 := body.Details.Conflicts[0], body.Details.Conflicts[1]
	if c0["task_title"] != title || c0["can_move"] != true || c0["assignee_user_id"] != user.String() {
		t.Errorf("visible conflict = %v", c0)
	}
	for _, k := range []string{"task_title", "assignee_user_id", "assignee_group_id"} {
		v, present := c1[k]
		if !present || v != nil {
			t.Errorf("hidden conflict %s = %v (present %v), want null", k, v, present)
		}
	}
	if c1["can_move"] != false {
		t.Errorf("hidden conflict can_move = %v", c1["can_move"])
	}
}

func TestQueryTaskErrorCodes(t *testing.T) {
	h := &RemediationTaskHandler{logger: logger.NewNop()}
	for _, tc := range []struct {
		err  error
		code int
		want string
	}{
		{remediation.ErrTooManyMatches, http.StatusBadRequest, "QUERY_TOO_MANY_MATCHES"},
		{queryapp.ErrNotFindingFilter, http.StatusBadRequest, "QUERY_NOT_FINDING_FILTER"},
		{queryapp.ErrBusy, http.StatusTooManyRequests, ""},
		{remediation.ErrAutoSuspended, http.StatusConflict, ""},
	} {
		rec := httptest.NewRecorder()
		h.handleQueryError(rec, tc.err)
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%v = %d %s", tc.err, rec.Code, rec.Body)
		}
	}
}
