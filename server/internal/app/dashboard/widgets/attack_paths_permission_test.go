package widgets

import (
	"context"
	"testing"

	dashboardapp "github.com/openctemio/openctem/server/internal/app/dashboard"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

// The attack-paths widget lists computed routes to crown jewels: it needs
// attack_surface:paths:read, not assets:read, on a personal dashboard and on
// an organization dashboard alike.
func TestAttackPathsWidget_NeedsPathsRead(t *testing.T) {
	data := func() *DashboardData {
		return &DashboardData{Widgets: []WidgetValue{{ID: "w1", Metric: "attack_paths.to_crown_jewels", State: StateReady,
			Paths: &PathsValue{Designated: 1, Reachable: 1, Rows: []PathRow{{AssetID: "a1", Name: "db.example.com"}}}}}}
	}
	has := func(perms ...permission.Permission) func(string) bool {
		return func(p string) bool {
			for _, x := range perms {
				if x.String() == p {
					return true
				}
			}
			return false
		}
	}
	masked := func(d *DashboardData) bool {
		w := d.Widgets[0]
		return w.Paths == nil && w.State == StateUnsupported && w.Reason == ReasonForbidden
	}

	// Personal read: assets:read alone is not enough.
	d := data()
	maskForbidden(d, dashboardapp.Caller{Has: has(permission.AssetsRead, permission.FindingsRead)})
	if !masked(d) {
		t.Errorf("personal read with assets:read only kept the routes: %+v", d.Widgets[0])
	}
	d = data()
	maskForbidden(d, dashboardapp.Caller{Has: has(permission.AttackPathsRead)})
	if masked(d) {
		t.Error("personal read masked for a holder of attack_surface:paths:read")
	}

	// Every exit (organization dashboards included) masks the routes for a
	// reader without the permission.
	s := NewService(nil, nil, nil, nil)
	d, err := s.forViewer(context.Background(), data(), dashboardapp.Caller{Has: has(permission.AssetsRead, permission.DashboardsOrgView)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !masked(d) {
		t.Errorf("organization read with assets:read kept the routes: %+v", d.Widgets[0])
	}
	d, err = s.forViewer(context.Background(), data(), dashboardapp.Caller{Has: has(permission.AttackPathsRead)}, nil)
	if err != nil || masked(d) {
		t.Errorf("organization read masked for a holder: %v", err)
	}
}
