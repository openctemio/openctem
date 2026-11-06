package routes

// Informational findings (info and none) in the findings list and its work
// views (docs/architecture/findings-work-views.md): a severity=info filter
// matches both stored values everywhere, the work views leave them out unless
// the caller's preference (else the organization's default) includes them,
// Needs triage always leaves them out, and every view's count equals the
// total of the list its params open.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type orgViewDefault struct{ include bool }

func (o orgViewDefault) GetFindingViewSettings(context.Context, string) (*tenantdom.FindingViewSettings, error) {
	return &tenantdom.FindingViewSettings{IncludeInformational: o.include}, nil
}

// seedInformational adds, on A1 (memberA's scope): info new, none new, none
// confirmed, info resolved, and one medium new; plus a none finding of
// another tenant.
func (h *gsHarness) seedInformational(t *testing.T) map[string]shared.ID {
	t.Helper()
	ins := func(tenant, asset, severity, status string) shared.ID {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'dast', 'inf-tool', 'inf finding', $4, $1::text, $5)`, id.String(), tenant, asset, severity, status)
		return id
	}
	tid, a := h.tenant.String(), h.assetA.String()
	ids := map[string]shared.ID{
		"info_new":       ins(tid, a, "info", "new"),
		"none_new":       ins(tid, a, "none", "new"),
		"none_confirmed": ins(tid, a, "none", "confirmed"),
		"info_resolved":  ins(tid, a, "info", "resolved"),
		"medium_new":     ins(tid, a, "medium", "new"),
	}
	other, otherAsset := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "inf-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'inf-other.example', 'domain')`, otherAsset.String(), other.String())
	ids["other_tenant_none"] = ins(other.String(), otherAsset.String(), "none", "new")
	return ids
}

// quickViewsAs reads the quick views with an optional work-view preference.
func (h *gsHarness) quickViewsAs(t *testing.T, c flCaller, pref string) (map[string]int64, map[string]string, bool) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/findings/quick-views", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", c.user.String())
	if c.admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if pref != "" {
		req.Header.Set("X-Test-Findings-Informational", pref)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s quick-views = %d: %.300s", c.name, resp.StatusCode, body)
	}
	var out struct {
		Views []struct {
			Key                 string `json:"key"`
			Count               int64  `json:"count"`
			Params              string `json:"params"`
			InformationalHidden *int64 `json:"informational_hidden"`
		} `json:"views"`
		IncludeInformational bool `json:"include_informational"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	counts, params := map[string]int64{}, map[string]string{}
	for _, v := range out.Views {
		counts[v.Key], params[v.Key] = v.Count, v.Params
		// The count is the total of the list the params open.
		if _, total, _ := h.listIDs(t, c, v.Params); total != v.Count {
			t.Errorf("%s pref=%q %s count = %d, GET /findings?%s total = %d", c.name, pref, v.Key, v.Count, v.Params, total)
		}
		// A view that leaves informational findings out says how many: the
		// total of the same params with informational=true.
		hides := strings.Contains(v.Params, "informational=false")
		if hides != (v.InformationalHidden != nil) {
			t.Errorf("%s %s params %q informational_hidden = %v", c.name, v.Key, v.Params, v.InformationalHidden)
		}
		if hides && v.InformationalHidden != nil {
			shown := strings.Replace(v.Params, "informational=false", "informational=true", 1)
			if _, n, _ := h.listIDs(t, c, shown); n != *v.InformationalHidden {
				t.Errorf("%s %s informational_hidden = %d, GET /findings?%s total = %d", c.name, v.Key, *v.InformationalHidden, shown, n)
			}
			if v.Key == "active" {
				counts["active_hidden"] = *v.InformationalHidden
			}
		}
	}
	return counts, params, out.IncludeInformational
}

func TestFindingsSeverityInfoMatchesNone(t *testing.T) {
	h := newGroupScopeHarness(t)
	ids := h.seedInformational(t)
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	wantInfo := []string{ids["info_new"].String(), ids["none_new"].String(), ids["none_confirmed"].String(), ids["info_resolved"].String()}
	slices.Sort(wantInfo)

	for _, c := range []flCaller{admin, memberA} {
		got, total, _ := h.listIDs(t, c, "state=all&severity=info&per_page=100")
		slices.Sort(got)
		if !slices.Equal(got, wantInfo) || total != 4 {
			t.Errorf("%s severity=info = %v (total %d), want %v", c.name, got, total, wantInfo)
		}
		// The pre-RFC-048 alias and the new boolean agree.
		if _, n, _ := h.listIDs(t, c, "state=all&severities=info"); n != 4 {
			t.Errorf("%s severities=info total = %d, want 4", c.name, n)
		}
		if _, n, _ := h.listIDs(t, c, "state=all&informational=true"); n != 4 {
			t.Errorf("%s informational=true total = %d, want 4", c.name, n)
		}
		_, all, _ := h.listIDs(t, c, "state=all")
		if _, n, _ := h.listIDs(t, c, "state=all&informational=false"); n != all-4 {
			t.Errorf("%s informational=false total = %d, want %d", c.name, n, all-4)
		}
		if _, n, _ := h.listIDs(t, c, "state=all&severity_not=info"); n != all-4 {
			t.Errorf("%s severity_not=info total = %d, want %d", c.name, n, all-4)
		}
	}
	// Out of scope: memberA cannot see B1, and nobody counts the other tenant's none finding.
	if _, n, _ := h.listIDs(t, admin, "state=all&severity=none"); n != 2 {
		t.Errorf("severity=none = %d, want 2 (this tenant only)", n)
	}

	// The legacy list path (MCP and older callers) expands info too.
	res, err := h.vuln.ListFindings(context.Background(), finding.ListFindingsInput{
		TenantID: h.tenant.String(), ActingUserID: h.owner.String(), IsAdmin: true,
		Severities: []string{"info"}, Page: 1, PerPage: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 4 {
		t.Errorf("ListFindings severities=[info] total = %d, want 4", res.Total)
	}

	// The by-severity stats fold none into info, and filter the same way.
	status, _, body := h.listFindingsPath(t, admin, "/api/v1/findings/stats?state=all&severity=info")
	if status != http.StatusOK {
		t.Fatalf("stats = %d: %.300s", status, body)
	}
	var stats struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 {
		t.Errorf("stats severity=info total = %d, want 4", stats.Total)
	}
}

func TestFindingQuickViewsInformational(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.seedInformational(t)
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}

	for _, c := range []flCaller{admin, memberA} {
		// Default (nothing chosen, no organization default): left out.
		hidden, params, include := h.quickViewsAs(t, c, "")
		if include {
			t.Errorf("%s include_informational = true by default", c.name)
		}
		if params["active"] != "state=open&informational=false" {
			t.Errorf("%s active params = %q", c.name, params["active"])
		}
		// The member's own "include" shows them in the work views.
		shown, params, include := h.quickViewsAs(t, c, "include")
		if !include || params["active"] != "state=open" {
			t.Errorf("%s include: include_informational=%v active params %q", c.name, include, params["active"])
		}
		// Three open informational findings: info new, none new, none confirmed.
		if hidden["active_hidden"] != 3 {
			t.Errorf("%s active informational_hidden = %d, want 3", c.name, hidden["active_hidden"])
		}
		if shown["active"]-hidden["active"] != 3 {
			t.Errorf("%s active shown %d - hidden %d, want 3", c.name, shown["active"], hidden["active"])
		}
		// Needs triage leaves them out either way; Closed always counts them.
		if shown["needs_triage"] != hidden["needs_triage"] {
			t.Errorf("%s needs_triage include %d != exclude %d", c.name, shown["needs_triage"], hidden["needs_triage"])
		}
		if shown["closed"] != hidden["closed"] {
			t.Errorf("%s closed include %d != exclude %d", c.name, shown["closed"], hidden["closed"])
		}
	}

	// The organization's default applies to a member with no choice of their
	// own, and the member's "exclude" overrides it.
	h.vuln.SetFindingViewSettings(orgViewDefault{include: true})
	t.Cleanup(func() { h.vuln.SetFindingViewSettings(nil) })
	if _, params, include := h.quickViewsAs(t, memberA, ""); !include || params["active"] != "state=open" {
		t.Errorf("org default include: include_informational=%v active %q", include, params["active"])
	}
	if _, params, include := h.quickViewsAs(t, memberA, "exclude"); include || params["active"] != "state=open&informational=false" {
		t.Errorf("member exclude over org include: include_informational=%v active %q", include, params["active"])
	}
	if _, params, _ := h.quickViewsAs(t, memberA, "default"); params["needs_triage"] != "status=new&informational=false" {
		t.Errorf("needs_triage params = %q", params["needs_triage"])
	}
}
