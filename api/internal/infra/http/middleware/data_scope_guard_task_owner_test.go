package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFixWorkRoute(t *testing.T) {
	id := shared.NewID().String()
	base := "/api/v1/findings/" + id
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", base, true},
		{"GET", base + "/transitions", true},
		{"GET", base + "/comments", true},
		{"POST", base + "/comments", true},
		{"PUT", base + "/comments/" + id, true},
		{"DELETE", base + "/comments/" + id, true},
		{"PATCH", base + "/status", true},
		{"POST", base + "/evidence", true},
		{"POST", base + "/validate", true},
		{"POST", base + "/retests", true},
		// everything else keeps the finding's real scope
		{"POST", base + "/assign", false},
		{"POST", base + "/unassign", false},
		{"PATCH", base + "/severity", false},
		{"PATCH", base + "/classify", false},
		{"PUT", base + "/tags", false},
		{"PATCH", base + "/remediation", false},
		{"POST", base + "/approvals", false},
		{"POST", base + "/duplicates", false},
		{"POST", base + "/create-ticket", false},
		{"POST", base + "/evidence-items/" + id + "/reveal", false},
		{"DELETE", base, false},
		{"PATCH", base, false},
		{"DELETE", base + "/evidence/notes/" + id, false},
		{"PUT", base + "/comments/" + id + "/x", false},
		{"GET", "/api/v1/compliance/findings/" + id + "/controls", false},
		{"PUT", "/api/v1/verification-checklists/" + id, false},
	}
	for _, tc := range cases {
		if got := fixWorkRoute(tc.method, tc.path); got != tc.want {
			t.Errorf("fixWorkRoute(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// taskAsserter denies every finding by scope and admits the ones in owned
// through the task relation.
type taskAsserter struct{ owned map[shared.ID]bool }

func (taskAsserter) AssertAsset(context.Context, shared.ID, shared.ID) error {
	return shared.ErrNotFound
}
func (taskAsserter) AssertFinding(context.Context, shared.ID, shared.ID) error {
	return shared.ErrNotFound
}

func (a taskAsserter) AssertFindingForFixWork(_ context.Context, _, id shared.ID) (bool, error) {
	if a.owned[id] {
		return true, nil
	}
	return false, shared.ErrNotFound
}

func TestDataScopeGuard_TaskOwnerOnlyForFixWork(t *testing.T) {
	owned, other := shared.NewID(), shared.NewID()
	var sawFlag bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawFlag = shared.TaskOwnerView(r.Context())
		w.WriteHeader(http.StatusTeapot)
	})
	h := DataScopeGuard(taskAsserter{owned: map[shared.ID]bool{owned: true}})(next)
	run := func(method, path string) (int, bool) {
		sawFlag = false
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(context.WithValue(req.Context(), TenantIDKey, shared.NewID().String()))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, sawFlag
	}
	base := func(id shared.ID) string { return "/api/v1/findings/" + id.String() }

	if code, flag := run("GET", base(owned)); code != http.StatusTeapot || !flag {
		t.Errorf("read of the task's finding: code %d flag %v, want passed with the flag", code, flag)
	}
	if code, flag := run("PATCH", base(owned)+"/status"); code != http.StatusTeapot || !flag {
		t.Errorf("status of the task's finding: code %d flag %v", code, flag)
	}
	if code, _ := run("GET", base(other)); code != http.StatusNotFound {
		t.Errorf("read of a finding outside the task: code %d, want 404", code)
	}
	for _, c := range [][2]string{{"POST", "/assign"}, {"PATCH", "/severity"}, {"POST", "/approvals"}, {"DELETE", ""}} {
		if code, flag := run(c[0], base(owned)+c[1]); code != http.StatusNotFound || flag {
			t.Errorf("%s %s on the task's finding: code %d, want 404 (real scope)", c[0], c[1], code)
		}
	}
	// A compliance route is never a fix-workflow route.
	if code, _ := run("GET", "/api/v1/compliance/findings/"+owned.String()+"/controls"); code != http.StatusNotFound {
		t.Errorf("compliance route: code %d, want 404", code)
	}
}
