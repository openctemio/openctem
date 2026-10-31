package routes

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Through the real routes and database: GET /scope/targets and
// /scope/exclusions with include=status_counts count every entry of the
// caller's organization per status, whatever the list's own filters, and
// never another organization's; without include the answer is as before.
func TestScopeStatusCounts_Routes_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	org := h.tenant()
	owner := h.member(org, "owner")
	for _, p := range []string{"counts-a.example.com", "counts-b.example.com"} {
		h.expect(owner, http.MethodPost, "/api/v1/scope/targets",
			`{"target_type":"domain","pattern":"`+p+`"}`, http.StatusCreated)
	}
	h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"domain","pattern":"skip.counts-a.example.com","reason":"out of the test"}`, http.StatusCreated)

	other := h.tenant()
	stranger := h.member(other, "owner")
	h.expect(stranger, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"counts-other.example.com"}`, http.StatusCreated)

	type listed struct {
		Total        int              `json:"total"`
		StatusCounts map[string]int64 `json:"status_counts"`
	}
	get := func(user policyUser, path string) (listed, map[string]json.RawMessage) {
		t.Helper()
		body := h.expect(user, http.MethodGet, path, "", http.StatusOK)
		var out listed
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(body), &raw)
		return out, raw
	}

	// The counts ignore the status filter of the page they come with.
	tg, _ := get(owner, "/api/v1/scope/targets?statuses=pending&per_page=1&include=status_counts")
	if tg.Total != 0 || tg.StatusCounts["active"] != 2 || len(tg.StatusCounts) != 1 {
		t.Errorf("targets: total=%d counts=%v, want 0 listed and {active:2}", tg.Total, tg.StatusCounts)
	}
	ex, _ := get(owner, "/api/v1/scope/exclusions?per_page=20&include=status_counts")
	if ex.Total != 1 || ex.StatusCounts["active"]+ex.StatusCounts["pending"] != 1 || len(ex.StatusCounts) != 1 {
		t.Errorf("exclusions: total=%d counts=%v", ex.Total, ex.StatusCounts)
	}

	// Another organization counts only its own entries.
	st, _ := get(stranger, "/api/v1/scope/targets?per_page=1&include=status_counts")
	if st.StatusCounts["active"] != 1 {
		t.Errorf("other organization's target counts = %v, want {active:1}", st.StatusCounts)
	}
	se, _ := get(stranger, "/api/v1/scope/exclusions?per_page=1&include=status_counts")
	if se.StatusCounts == nil || len(se.StatusCounts) != 0 {
		t.Errorf("other organization's exclusion counts = %v, want {}", se.StatusCounts)
	}

	// Without include: no counts.
	for _, p := range []string{"/api/v1/scope/targets?per_page=1", "/api/v1/scope/exclusions?per_page=1"} {
		if _, raw := get(owner, p); raw["status_counts"] != nil {
			t.Errorf("%s answered status_counts without include", p)
		}
	}
}
