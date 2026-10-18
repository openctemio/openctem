package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The CTEM loop's Prioritize stage shows the tenant's own exposure to the KEV
// catalog (open findings in it, past due or not), never the catalog's size.
// It follows the viewer's scope and the pentest member-visibility rule, and
// never counts another tenant's findings.
func TestThreatIntelStats_TenantOpenKEV_DB(t *testing.T) {
	e := newGapEnv(t)
	h := e.h
	// A second KEV entry that is not yet due: the ordinary finding moves to it.
	future := "CVE-2098-" + e.cve[len(e.cve)-8:]
	h.exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, due_date) VALUES ($1, 'future', CURRENT_DATE, CURRENT_DATE + 30)`, future)
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM kev_catalog WHERE cve_id = $1`, future) })
	h.exec(`UPDATE findings SET cve_id = $1 WHERE title = $2 AND tenant_id = $3`, future, ptSca, h.tenant.String())

	for _, tc := range []struct {
		name          string
		user          shared.ID
		admin         bool
		open, pastDue int
	}{
		{"scoped non-member", h.memberA, false, 1, 0}, // the ordinary finding, not yet due
		{"campaign tester", e.tester, false, 2, 1},    // + the published pentest finding, past due
		{"administrator", h.owner, true, 2, 1},        // drafts and in-review findings are not open
		{"full-data non-member", h.memberFull, false, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.as(tc.user, tc.admin, nil, "/api/v1/threat-intel/stats")
			if code != http.StatusOK {
				t.Fatalf("stats = %d %s", code, body)
			}
			var st struct {
				KEV struct {
					Total   int `json:"total_entries"`
					Open    int `json:"tenant_open_count"`
					PastDue int `json:"past_due_count"`
				} `json:"kev"`
			}
			if err := json.Unmarshal([]byte(body), &st); err != nil {
				t.Fatal(err)
			}
			if st.KEV.Open != tc.open || st.KEV.PastDue != tc.pastDue {
				t.Errorf("tenant open KEV = %d (past due %d), want %d (%d)", st.KEV.Open, st.KEV.PastDue, tc.open, tc.pastDue)
			}
		})
	}
}
