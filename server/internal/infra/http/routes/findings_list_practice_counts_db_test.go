package routes

// GET /findings?include=practice_counts: each practice's count equals the
// total of GET /findings with that practice for the same caller, the
// request's own practice condition is left out, and nothing outside the
// caller's tenant or data scope is counted.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type practiceCountsResponse struct {
	Total           int64 `json:"total"`
	Vulnerabilities int64 `json:"vulnerabilities"`
	Practices       []struct {
		Practice string `json:"practice"`
		Count    int64  `json:"count"`
	} `json:"practices"`
}

type listWithPracticeCounts struct {
	Total          int64                   `json:"total"`
	PracticeCounts *practiceCountsResponse `json:"practice_counts"`
}

func TestFindingPracticeCounts_EqualTheirListsInScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	tid := h.tenant.String()
	ins := func(tenant, asset, practice string) {
		id := shared.NewID().String()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, practice, practice_reason)
			VALUES ($1::uuid, $2, $3, 'va', 'nessus', 'practice count', 'high', $1::text, 'new', $4, 'test')`, id, tenant, asset, practice)
	}
	ins(tid, h.assetA.String(), "compliance")
	ins(tid, h.assetA.String(), "compliance")
	ins(tid, h.assetA.String(), "infra")
	ins(tid, h.assetB.String(), "compliance")
	ins(tid, h.assetB.String(), "aspm")

	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "pc-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'pc-other.example.com', 'host')`, otherAsset.String(), other.String())
	ins(other.String(), otherAsset.String(), "compliance")

	for _, c := range []flCaller{{"owner", h.owner, true}, {"memberA", h.memberA, false}} {
		// The request's own practice condition is left out of the counts.
		status, _, body := h.listFindingsPath(t, c, "/api/v1/findings?practice_not=compliance&tool_name=nessus&include=practice_counts")
		if status != http.StatusOK {
			t.Fatalf("%s list with practice counts = %d: %.300s", c.name, status, body)
		}
		var page listWithPracticeCounts
		if err := json.Unmarshal([]byte(body), &page); err != nil {
			t.Fatal(err)
		}
		if page.PracticeCounts == nil {
			t.Fatalf("%s: no practice_counts in %.300s", c.name, body)
		}
		got := *page.PracticeCounts
		// The page itself keeps the request's practice condition.
		if _, vulns, _ := h.listIDs(t, c, "tool_name=nessus&practice_not=compliance"); page.Total != vulns {
			t.Errorf("%s page total = %d, want %d (practice_not applied to the rows)", c.name, page.Total, vulns)
		}
		if len(got.Practices) != 9 {
			t.Fatalf("%s practices = %+v", c.name, got.Practices)
		}
		var sum int64
		for _, p := range got.Practices {
			_, total, _ := h.listIDs(t, c, "tool_name=nessus&practice="+p.Practice)
			if p.Count != total {
				t.Errorf("%s %s count = %d, list total = %d", c.name, p.Practice, p.Count, total)
			}
			sum += p.Count
		}
		_, all, _ := h.listIDs(t, c, "tool_name=nessus")
		_, vulns, _ := h.listIDs(t, c, "tool_name=nessus&practice_not=compliance")
		if got.Total != all || sum != all || got.Vulnerabilities != vulns {
			t.Errorf("%s total %d, sum %d, vulnerabilities %d; list %d / %d", c.name, got.Total, sum, got.Vulnerabilities, all, vulns)
		}
		want := map[string]int64{"owner": 3, "memberA": 2}[c.name]
		for _, p := range got.Practices {
			if p.Practice == "compliance" && p.Count != want {
				t.Errorf("%s compliance = %d, want %d (own scope, own tenant)", c.name, p.Count, want)
			}
		}
	}
}

// Without include the list carries no counts, and an unknown include value is
// refused rather than ignored.
func TestFindingPracticeCounts_OnlyOnRequest(t *testing.T) {
	h := newGroupScopeHarness(t)
	c := flCaller{"owner", h.owner, true}
	status, _, body := h.listFindingsPath(t, c, "/api/v1/findings?tool_name=nessus")
	if status != http.StatusOK || strings.Contains(body, "practice_counts") {
		t.Fatalf("plain list = %d, practice_counts present: %.300s", status, body)
	}
	status, _, body = h.listFindingsPath(t, c, "/api/v1/findings?include=practice_count")
	if status != http.StatusBadRequest || !strings.Contains(body, "include") {
		t.Fatalf("unknown include = %d: %.300s", status, body)
	}
}
