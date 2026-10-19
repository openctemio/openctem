package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func rawBody(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseTaskUpdate(t *testing.T) {
	in, err := parseTaskUpdate(rawBody(t, `{"version":3,"title":"x","assignee_user_id":null,"deadline":"2026-11-01","hold":true,"note":"freeze"}`))
	if err != nil {
		t.Fatal(err)
	}
	if in.Version != 3 || *in.Title != "x" || in.AssigneeUserID == nil || *in.AssigneeUserID != nil {
		t.Fatalf("parsed %+v", in)
	}
	if in.Deadline == nil || *in.Deadline == nil || (*in.Deadline).Format("2006-01-02T15:04:05") != "2026-11-01T23:59:59" {
		t.Fatalf("a date deadline is the end of that day: %v", in.Deadline)
	}
	if in.Hold == nil || !*in.Hold || in.StateNote != "freeze" || in.AssigneeGroupID != nil {
		t.Fatalf("parsed %+v", in)
	}
	in, err = parseTaskUpdate(rawBody(t, `{"version":1,"deadline":null}`))
	if err != nil || in.Deadline == nil || *in.Deadline != nil {
		t.Fatalf("null clears the deadline: %+v %v", in, err)
	}

	for _, bad := range []string{
		`{"version":1,"tenant_id":"x"}`,           // unknown field: the tenant never comes from the body
		`{"version":"1"}`,                         // wrong type
		`{"version":1,"assignee_user_id":"nope"}`, // not an id
		`{"version":1,"deadline":"tomorrow"}`,
		`{"version":1,"hold":true,"cancel":true}`,
	} {
		if _, err := parseTaskUpdate(rawBody(t, bad)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", bad, err)
		}
	}
}

// overdue is a boolean: anything else is a 400 before the service is asked.
func TestRemediationTaskList_OverdueMustBeBoolean(t *testing.T) {
	h := NewRemediationTaskHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/remediation/tasks?overdue=soon", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("overdue=soon: status %d, want 400", rec.Code)
	}
}
