package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// Dashboard counts follow the viewer (owner decision D6, research doc 15
// P1-4): a restricted member counts only their own assets and findings; with
// dashboard:aggregate they see organization totals, with breakdowns under 5
// left out; owners and unrestricted members see the organization.
func TestDashboardStats_FollowTheViewer_DB(t *testing.T) {
	h := newDSHarness(t)
	type wire struct {
		Assets struct {
			Total  int            `json:"total"`
			ByType map[string]int `json:"by_type"`
		} `json:"assets"`
		Findings struct {
			Total      int            `json:"total"`
			BySeverity map[string]int `json:"by_severity"`
		} `json:"findings"`
	}
	type stats struct {
		AssetCount, FindingCount         int
		FindingsBySeverity, AssetsByType map[string]int
	}
	get := func(req *http.Request) stats {
		t.Helper()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /dashboard/stats = %d", resp.StatusCode)
		}
		var w wire
		if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
			t.Fatal(err)
		}
		return stats{w.Assets.Total, w.Findings.Total, w.Findings.BySeverity, w.Assets.ByType}
	}
	req := func(user string, admin bool, perms []string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/dashboard/stats", nil)
		r.Header.Set("X-Test-User", user)
		if admin {
			r.Header.Set("X-Test-Admin", "1")
		}
		if perms != nil {
			r.Header.Set("X-Test-Perms", strings.Join(perms, ","))
		}
		return r
	}

	// memberA is restricted to asset A1 (one finding).
	if s := get(req(h.memberA.String(), false, nil)); s.AssetCount != 1 || s.FindingCount != 1 || s.FindingsBySeverity["high"] != 1 {
		t.Errorf("restricted member counts = %+v, want 1 asset and 1 finding", s)
	}
	// The organization has 2 assets and 2 findings.
	for _, who := range []struct {
		name  string
		user  string
		admin bool
	}{{"owner", h.owner.String(), true}, {"full-data role", h.memberFull.String(), false}} {
		if s := get(req(who.user, who.admin, nil)); s.AssetCount != 2 || s.FindingCount != 2 {
			t.Errorf("%s counts = %+v, want 2 assets and 2 findings", who.name, s)
		}
	}
	// With dashboard:aggregate the restricted member sees the totals, and
	// the breakdowns under 5 are left out (both are 2 here).
	perms := append(append([]string{}, dsMemberPerms...), permission.DashboardAggregate.String())
	s := get(req(h.memberA.String(), false, perms))
	if s.AssetCount != 2 || s.FindingCount != 2 {
		t.Errorf("restricted member with dashboard:aggregate = %+v, want the organization totals", s)
	}
	if len(s.FindingsBySeverity) != 0 || len(s.AssetsByType) != 0 {
		t.Errorf("breakdowns under the k-floor shown to a restricted viewer: %+v", s)
	}

	// Fail-closed organization: a member without a group counts nothing.
	if s := get(req(h.memberStrict.String(), false, nil)); s.AssetCount != 0 || s.FindingCount != 0 {
		t.Errorf("fail-closed member without group counts = %+v, want 0", s)
	}
}
