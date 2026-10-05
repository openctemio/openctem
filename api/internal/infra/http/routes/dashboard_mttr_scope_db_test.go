package routes

// Dashboard MTTR follows the viewer (research 24 §5.1, owner decision D6):
// a restricted member's mean time to remediate comes from findings on their
// own assets only; with dashboard:aggregate they see the organization figure;
// owners and unrestricted members see the organization. It used to average
// the whole tenant for everyone.

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func TestDashboardMTTR_FollowsTheViewer_DB(t *testing.T) {
	h := newDSHarness(t)
	// FA (A1, memberA's scope): fixed 10 h after detection. FB (B1): 1000 h.
	h.exec(`UPDATE findings SET status = 'resolved', first_detected_at = now() - interval '20 hours',
		resolved_at = now() - interval '10 hours' WHERE id = $1`, h.findingA.String())
	h.exec(`UPDATE findings SET status = 'resolved', first_detected_at = now() - interval '1010 hours',
		resolved_at = now() - interval '10 hours' WHERE id = $1`, h.findingB.String())

	get := func(path, user string, admin bool, perms []string, out any) {
		t.Helper()
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
		r.Header.Set("X-Test-User", user)
		if admin {
			r.Header.Set("X-Test-Admin", "1")
		}
		if perms != nil {
			r.Header.Set("X-Test-Perms", strings.Join(perms, ","))
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	type analytics struct {
		BySeverity map[string]float64 `json:"by_severity"`
		Overall    float64            `json:"overall_hours"`
		SampleSize int                `json:"sample_size"`
	}
	near := func(a, b float64) bool { return math.Abs(a-b) < 0.5 }

	aggPerms := append(append([]string{}, dsMemberPerms...), permission.DashboardAggregate.String())
	cases := []struct {
		name    string
		user    string
		admin   bool
		perms   []string
		hours   float64
		samples int
	}{
		{"restricted member", h.memberA.String(), false, nil, 10, 1},
		{"owner", h.owner.String(), true, nil, 505, 2},
		{"full-data role", h.memberFull.String(), false, nil, 505, 2},
		{"restricted member with dashboard:aggregate", h.memberA.String(), false, aggPerms, 505, 2},
		{"member without a group", h.memberStrict.String(), false, nil, 0, 0},
	}
	for _, c := range cases {
		var m map[string]float64
		get("/api/v1/dashboard/mttr", c.user, c.admin, c.perms, &m)
		if !near(m["high"], c.hours) {
			t.Errorf("%s /dashboard/mttr high = %.1f h, want %.0f", c.name, m["high"], c.hours)
		}
		var a analytics
		get("/api/v1/dashboard/mttr-analytics", c.user, c.admin, c.perms, &a)
		if !near(a.Overall, c.hours) || a.SampleSize != c.samples || !near(a.BySeverity["high"], c.hours) {
			t.Errorf("%s /dashboard/mttr-analytics = %+v, want overall %.0f h over %d", c.name, a, c.hours, c.samples)
		}
	}
}
