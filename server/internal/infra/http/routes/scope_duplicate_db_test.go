package routes

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Adding an entry or exclusion the organization already has answers 409
// with the existing row's id and status; another organization adding the
// same pattern is not refused and never learns of the first one.
func TestScopeDuplicateNamesExistingRow_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	admin, otherAdmin := h.member(org, "admin"), h.member(other, "admin")

	type created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	type conflict struct {
		Code    string `json:"code"`
		Details struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"details"`
	}
	decode := func(body string, v any) {
		t.Helper()
		if err := json.Unmarshal([]byte(body), v); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
	}
	for _, tc := range []struct{ path, body, code string }{
		{"/api/v1/scope/targets", `{"target_type":"domain","pattern":"*.dup-route.example"}`, "SCOPE_ENTRY_EXISTS"},
		{"/api/v1/scope/exclusions", `{"exclusion_type":"domain","pattern":"prod.dup-route.example","reason":"prod"}`, "SCOPE_EXCLUSION_EXISTS"},
	} {
		var first created
		decode(h.expect(admin, http.MethodPost, tc.path, tc.body, http.StatusCreated), &first)
		var c conflict
		decode(h.expect(admin, http.MethodPost, tc.path, tc.body, http.StatusConflict), &c)
		if c.Code != tc.code || c.Details.ID != first.ID || c.Details.Status != first.Status {
			t.Fatalf("%s duplicate: %+v, want %s naming %+v", tc.path, c, tc.code, first)
		}
		var theirs created
		decode(h.expect(otherAdmin, http.MethodPost, tc.path, tc.body, http.StatusCreated), &theirs)
		if theirs.ID == first.ID {
			t.Fatalf("%s: another organization got the first row", tc.path)
		}
	}
}
