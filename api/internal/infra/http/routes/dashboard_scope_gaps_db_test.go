package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The threat-intel exposure counts, the validation coverage, a CTEM cycle's
// charter evaluation and the program metrics follow the same rules as the
// dashboards: the viewer's data scope, the pentest member-visibility rule of
// the findings list (no draft or in-review finding for anyone), and
// organization figures only with dashboard:aggregate or full data access.
// Viewers: a scoped non-member, a full-data non-member, a campaign tester
// and client, an administrator, a scoped aggregate viewer, and another
// organization.

// gapEnv adds, on top of the pentest fixtures, findings that carry a CVE with
// an exploit-probability score and a KEV entry, and validation evidence.
type gapEnv struct {
	*ptEnv
	cve string
}

func newGapEnv(t *testing.T) *gapEnv {
	t.Helper()
	e := &gapEnv{ptEnv: newPtEnv(t)}
	h := e.h
	e.cve = "CVE-2099-" + strings.ToUpper(shared.NewID().String()[:8])
	h.exec(`INSERT INTO epss_scores (cve_id, epss_score, score_date) VALUES ($1, 0.97, CURRENT_DATE)`, e.cve)
	h.exec(`INSERT INTO kev_catalog (cve_id, vulnerability_name, date_added, due_date) VALUES ($1, 'gap', CURRENT_DATE - 30, CURRENT_DATE - 1)`, e.cve)
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM epss_scores WHERE cve_id = $1`, e.cve)
		_, _ = h.db.Exec(`DELETE FROM kev_catalog WHERE cve_id = $1`, e.cve)
	})
	// Every finding of the pentest fixtures gets the CVE and conclusive
	// validation evidence; the published pentest finding is also downgraded.
	h.exec(`UPDATE findings SET cve_id = $1 WHERE title LIKE 'PT-%' AND (tenant_id = $2 OR tenant_id = $3)`, e.cve, h.tenant.String(), e.otherTenant.String())
	h.exec(`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome)
		SELECT tenant_id, id, 'manual', 'detected' FROM findings WHERE title LIKE 'PT-%'`)
	h.exec(`UPDATE findings SET downgraded_at = now() WHERE title IN ($1, $2)`, ptPub, ptReview)
	// Closed work: an ordinary and a published pentest finding, both resolved,
	// both with evidence (validation coverage by priority covers closed work).
	camp := e.campaign()
	for i, src := range []string{"sast", "pentest"} {
		id := shared.NewID()
		var c any
		if src == "pentest" {
			c = camp
		}
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, title, message, severity, fingerprint, status, priority_class, pentest_campaign_id, resolved_at)
			VALUES ($1::uuid, $2, $3, $4, 'pt', 'closed', $5::text, $5::text, 'high', $1::text, 'resolved', 'P0', $6, now())`,
			id.String(), h.tenant.String(), h.assetA.String(), src, []string{"PT-CLOSED-ord", "PT-CLOSED-pen"}[i], c)
		h.exec(`INSERT INTO validation_evidence (tenant_id, finding_id, executor_kind, outcome) VALUES ($1, $2, 'manual', 'detected')`, h.tenant.String(), id.String())
	}
	return e
}

func (e *gapEnv) campaign() string {
	var id string
	if err := e.h.db.QueryRow(`SELECT id::text FROM pentest_campaigns WHERE tenant_id = $1 AND name = 'ptc'`, e.h.tenant.String()).Scan(&id); err != nil {
		e.h.t.Fatal(err)
	}
	return id
}

// as sends a GET as user with the given permissions ("" = the member default).
func (e *gapEnv) as(user shared.ID, admin bool, perms []string, path string) (int, string) {
	e.h.t.Helper()
	if perms == nil {
		return e.h.do(user, admin, http.MethodGet, path, nil)
	}
	req, _ := http.NewRequestWithContext(e.h.t.Context(), http.MethodGet, e.h.srv.URL+path, nil)
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("Authorization", "Test "+user.String())
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		b.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	return resp.StatusCode, b.String()
}

func gapAggregatePerms() []string {
	return append(append([]string{}, dsMemberPerms...), permission.DashboardAggregate.String())
}

func TestThreatIntelCounts_PentestVisibility_DB(t *testing.T) {
	e := newGapEnv(t)
	h := e.h
	// The ordinary finding and the published pentest finding are open and
	// carry the CVE; drafts and in-review findings are not open at all.
	for _, tc := range []struct {
		name  string
		user  shared.ID
		admin bool
		perms []string
		want  int
	}{
		{"scoped non-member", h.memberA, false, nil, 1},
		{"full-data non-member", h.memberFull, false, nil, 1},
		{"campaign tester", e.tester, false, nil, 2},
		{"campaign client", e.client, false, nil, 2},
		{"administrator", h.owner, true, nil, 2},
		// An aggregate viewer is counted over the organization, but never
		// over a campaign they are not on.
		{"scoped aggregate non-member", h.memberA, false, gapAggregatePerms(), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.as(tc.user, tc.admin, tc.perms, "/api/v1/threat-intel/stats")
			if code != http.StatusOK {
				t.Fatalf("stats = %d %s", code, body)
			}
			var st struct {
				EPSS struct {
					High int `json:"high_risk_count"`
				} `json:"epss"`
				KEV struct {
					PastDue int `json:"past_due_count"`
				} `json:"kev"`
			}
			if err := json.Unmarshal([]byte(body), &st); err != nil {
				t.Fatal(err)
			}
			if st.EPSS.High != tc.want {
				t.Errorf("EPSS high-risk = %d, want %d", st.EPSS.High, tc.want)
			}
			if st.KEV.PastDue != tc.want {
				t.Errorf("KEV past due = %d, want %d", st.KEV.PastDue, tc.want)
			}
		})
	}
}

func TestValidationCoverage_PentestVisibility_DB(t *testing.T) {
	e := newGapEnv(t)
	h := e.h
	type cov struct {
		Total, Validated int
		Downgraded       int
		P0               int
	}
	read := func(user shared.ID, admin bool, perms []string) cov {
		code, body := e.as(user, admin, perms, "/api/v1/validation/coverage")
		if code != http.StatusOK {
			t.Fatalf("coverage = %d %s", code, body)
		}
		var r struct {
			Total      int `json:"total"`
			Validated  int `json:"validated"`
			Downgraded int `json:"downgraded"`
			ByPriority []struct {
				Priority string `json:"priority"`
				Total    int    `json:"total"`
			} `json:"by_priority"`
		}
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		c := cov{Total: r.Total, Validated: r.Validated, Downgraded: r.Downgraded}
		for _, p := range r.ByPriority {
			if p.Priority == "P0" {
				c.P0 = p.Total
			}
		}
		return c
	}
	base := read(h.memberA, false, nil)
	// Open: the harness findings and the ordinary one are visible to all in
	// scope; the published pentest finding only to its campaign. Closed P0:
	// the ordinary resolved finding for all, the pentest one for members.
	if base.Downgraded != 0 {
		t.Errorf("scoped non-member sees %d downgraded findings, want 0 (the published pentest finding is not theirs)", base.Downgraded)
	}
	for _, m := range []struct {
		name  string
		user  shared.ID
		admin bool
		perms []string
		// extra over the scoped non-member: the published pentest finding
		extra bool
	}{
		{"campaign tester", e.tester, false, nil, true},
		{"campaign client", e.client, false, nil, true},
		{"scoped aggregate non-member", h.memberA, false, gapAggregatePerms(), false},
	} {
		got := read(m.user, m.admin, m.perms)
		d := 0
		if m.extra {
			d = 1
		}
		if m.name == "scoped aggregate non-member" {
			// Organization totals (assetB's findings too) but no campaign
			// they are not on: compare against the full-data non-member.
			if want := read(h.memberFull, false, nil); got != want {
				t.Errorf("%s = %+v, want the full-data non-member's %+v", m.name, got, want)
			}
			continue
		}
		if got.Total != base.Total+d || got.P0 != base.P0+d || got.Downgraded != d {
			t.Errorf("%s = %+v, want total %d, closed P0 %d, downgraded %d (scoped non-member %+v)",
				m.name, got, base.Total+d, base.P0+d, d, base)
		}
	}
	// The unpublished findings count for nobody, not even an administrator:
	// the downgraded in-review finding is not part of any figure.
	adm := read(h.owner, true, nil)
	if adm.Downgraded != 1 {
		t.Errorf("administrator sees %d downgraded findings, want 1 (published only)", adm.Downgraded)
	}
}

func TestProgramMetrics_PentestVisibility_DB(t *testing.T) {
	e := newGapEnv(t)
	h := e.h
	mttv := func(user shared.ID, admin bool, perms []string) int {
		code, body := e.as(user, admin, perms, "/api/v1/dashboard/program-metrics?days=30")
		if code != http.StatusOK {
			t.Fatalf("program metrics = %d %s", code, body)
		}
		var r struct {
			MTTV struct {
				N int `json:"sample_size"`
			} `json:"mttv"`
		}
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		return r.MTTV.N
	}
	// P0 findings with conclusive evidence: ordinary, published pentest,
	// pentest in review, pentest draft (the last two count for nobody), plus
	// the two resolved ones.
	if code, _ := e.as(h.memberA, false, nil, "/api/v1/dashboard/program-metrics"); code != http.StatusForbidden {
		t.Errorf("scoped viewer without dashboard:aggregate = %d, want 403", code)
	}
	for _, tc := range []struct {
		name  string
		user  shared.ID
		admin bool
		perms []string
		want  int
	}{
		{"scoped aggregate non-member", h.memberA, false, gapAggregatePerms(), 2},
		{"full-data non-member", h.memberFull, false, nil, 2},
		{"campaign tester with aggregate", e.tester, false, gapAggregatePerms(), 4},
		{"administrator", h.owner, true, nil, 4},
	} {
		if got := mttv(tc.user, tc.admin, tc.perms); got != tc.want {
			t.Errorf("%s: mttv sample = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// A cycle's charter evaluation is computed from organization-wide metrics: a
// scoped viewer without dashboard:aggregate still reads the cycle, without the
// evaluation, on the single read and in the list.
func TestCTEMCycleCharterEvaluation_OrgViewersOnly_DB(t *testing.T) {
	e := newGapEnv(t)
	h := e.h
	cycle, otherCycle := shared.NewID(), shared.NewID()
	const ev = `{"evaluated_at":"2026-01-01T00:00:00Z","criteria":[],"met":7,"unmet":0,"not_measurable":0}`
	h.exec(`INSERT INTO ctem_cycles (id, tenant_id, name, status, created_by, charter_evaluation) VALUES ($1, $2, 'gap-cycle', 'closed', $3, $4::jsonb)`,
		cycle.String(), h.tenant.String(), h.owner.String(), ev)
	h.exec(`INSERT INTO ctem_cycles (id, tenant_id, name, status, created_by, charter_evaluation) VALUES ($1, $2, 'other-cycle', 'closed', $3, $4::jsonb)`,
		otherCycle.String(), e.otherTenant.String(), h.owner.String(), ev)
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM ctem_cycles WHERE id IN ($1, $2)`, cycle.String(), otherCycle.String())
	})
	for _, tc := range []struct {
		name  string
		user  shared.ID
		admin bool
		perms []string
		want  bool
	}{
		{"scoped member", h.memberA, false, nil, false},
		{"scoped aggregate viewer", h.memberA, false, append(gapAggregatePerms(), permission.CTEMCyclesRead.String()), true},
		{"full-data member", h.memberFull, false, nil, true},
		{"administrator", h.owner, true, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.as(tc.user, tc.admin, tc.perms, "/api/v1/ctem-cycles/"+cycle.String())
			if code != http.StatusOK || !strings.Contains(body, "gap-cycle") {
				t.Fatalf("cycle = %d %s, want the cycle to stay readable", code, body)
			}
			if got := strings.Contains(body, "charter_evaluation"); got != tc.want {
				t.Errorf("single read shows charter_evaluation = %v, want %v: %s", got, tc.want, body)
			}
			code, body = e.as(tc.user, tc.admin, tc.perms, "/api/v1/ctem-cycles")
			if code != http.StatusOK || !strings.Contains(body, "gap-cycle") {
				t.Fatalf("list = %d %s", code, body)
			}
			if got := strings.Contains(body, "charter_evaluation"); got != tc.want {
				t.Errorf("list shows charter_evaluation = %v, want %v", got, tc.want)
			}
		})
	}
	// Another organization's cycle is not there at all.
	if code, _ := e.as(h.owner, true, nil, "/api/v1/ctem-cycles/"+otherCycle.String()); code != http.StatusNotFound {
		t.Errorf("other tenant cycle = %d, want 404", code)
	}
}
