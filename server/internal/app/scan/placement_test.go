package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// placementGate answers like the production gate does for ownership
// confirmation: "found.example" is a discovered asset nobody confirmed and
// "rejected.example" one the tenant said is not theirs. Confirmation applies
// only on the hosted service to a job that is not on the tenant's own sensor.
type placementGate struct {
	*stubGate
	managed bool
	asked   []attribution.Placement
}

func (g *placementGate) OwnershipConfirmationManaged() bool { return g.managed }

func (g *placementGate) BlockedTargets(ctx context.Context, _ shared.ID, targets []string) (map[string]attribution.State, error) {
	p := attribution.PlacementOf(ctx)
	g.asked = append(g.asked, p)
	strict := g.managed && p != attribution.PlacementTenant
	out := map[string]attribution.State{}
	for _, t := range targets {
		switch {
		case t == "rejected.example":
			out[t] = attribution.StateRejected
		case t == "found.example" && strict:
			out[t] = attribution.StateDiscovered
		case t == "guess.example" && strict:
			out[t] = attribution.StateWildcardOnly
		}
	}
	return out, nil
}

func placementService(managed bool, sel SensorSelector) (*Service, *placementGate) {
	gate := &placementGate{stubGate: &stubGate{}, managed: managed}
	svc := allowAllChecks(&Service{attributionGate: gate, sensorSelector: sel, sharedLimits: noLimits{}, logger: logger.NewNop()})
	return svc, gate
}

// Where a job runs decides whether ownership confirmation applies: only on
// the hosted service, and only for platform sensors. A job routed to the
// tenant's own sensor (an explicit choice, or auto placement choosing one)
// is not refused; a job routed to a platform sensor is checked.
func TestResolveScanTargets_ConfirmationByPlacement(t *testing.T) {
	own := &sensor.Sensor{ID: shared.NewID(), Name: "own"}
	cases := []struct {
		name    string
		managed bool
		pref    scan.SensorPreference
		sel     ownSelector
		scanned bool
	}{
		{"managed, tenant sensors", true, scan.SensorPreferenceTenant, ownSelector{sensor: own, canUse: true}, true},
		{"managed, platform sensors", true, scan.SensorPreferencePlatform, ownSelector{canUse: true}, false},
		{"managed, auto chooses a tenant sensor", true, scan.SensorPreferenceAuto, ownSelector{sensor: own, canUse: true}, true},
		{"managed, auto chooses a platform sensor", true, scan.SensorPreferenceAuto, ownSelector{canUse: true}, false},
		{"managed, auto, platform not available to the tenant", true, scan.SensorPreferenceAuto, ownSelector{canUse: false}, true},
		{"self-hosted, tenant sensors", false, scan.SensorPreferenceTenant, ownSelector{sensor: own, canUse: true}, true},
		{"self-hosted, platform sensors", false, scan.SensorPreferencePlatform, ownSelector{canUse: true}, true},
		{"self-hosted, auto", false, scan.SensorPreferenceAuto, ownSelector{canUse: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _ := placementService(c.managed, c.sel)
			sc := testScan("nuclei", "found.example", "rejected.example", "plain.example")
			sc.SensorPreference = c.pref
			got, err := svc.resolveScanTargets(context.Background(), sc)
			if err != nil {
				t.Fatal(err)
			}
			has := func(n string) bool {
				for _, t := range got.Targets {
					if t == n {
						return true
					}
				}
				return false
			}
			if has("found.example") != c.scanned {
				t.Errorf("discovered, unconfirmed target scanned=%v, want %v (targets %v)", has("found.example"), c.scanned, got.Targets)
			}
			if has("rejected.example") {
				t.Errorf("a rejected target must be refused on every placement: %v", got.Targets)
			}
			if !has("plain.example") {
				t.Errorf("an authorized target was dropped: %v", got.Targets)
			}
		})
	}
}

// A scan saved for tenant sensors, and a workflow whose steps all find a
// tenant sensor, are judged as tenant jobs; an asset group never goes to
// shared sensors, so it is judged as a tenant job too.
func TestPlacementFor(t *testing.T) {
	own := &sensor.Sensor{ID: shared.NewID(), Name: "own"}
	ctx := context.Background()
	tenant := shared.NewID()
	cases := []struct {
		name       string
		managed    bool
		sel        SensorSelector
		pref       scan.SensorPreference
		tenantOnly bool
		group      bool
		tools      []string
		want       attribution.Placement
	}{
		{"tenant preference", true, ownSelector{canUse: true}, scan.SensorPreferenceTenant, false, false, []string{"nuclei"}, attribution.PlacementTenant},
		{"run on tenant runner", true, ownSelector{canUse: true}, scan.SensorPreferenceAuto, true, false, []string{"nuclei"}, attribution.PlacementTenant},
		{"asset group", true, ownSelector{canUse: true}, scan.SensorPreferencePlatform, false, true, []string{"nuclei"}, attribution.PlacementTenant},
		{"platform preference", true, ownSelector{sensor: own, canUse: true}, scan.SensorPreferencePlatform, false, false, []string{"nuclei"}, attribution.PlacementPlatform},
		{"auto with a tenant sensor", true, ownSelector{sensor: own, canUse: true}, scan.SensorPreferenceAuto, false, false, []string{"nuclei"}, attribution.PlacementTenant},
		{"auto without a tenant sensor", true, ownSelector{canUse: true}, scan.SensorPreferenceAuto, false, false, []string{"nuclei"}, attribution.PlacementPlatform},
		{"auto, workflow with unknown steps", true, ownSelector{canUse: true}, scan.SensorPreferenceAuto, false, false, nil, attribution.PlacementPlatform},
		{"auto, tenant not allowed on shared", true, ownSelector{canUse: false}, scan.SensorPreferenceAuto, false, false, []string{"nuclei"}, attribution.PlacementTenant},
		{"self-hosted never needs confirmation", false, ownSelector{canUse: true}, scan.SensorPreferencePlatform, false, false, []string{"nuclei"}, attribution.PlacementTenant},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _ := placementService(c.managed, c.sel)
			if got := svc.placementFor(ctx, tenant, c.pref, c.tenantOnly, c.group, c.tools...); got != c.want {
				t.Errorf("placement = %d, want %d", got, c.want)
			}
		})
	}
}

// The preflight the UI shows answers like the run: the same job is allowed
// on the tenant's own sensor and refused on a platform sensor of the hosted
// service, and a self-hosted install refuses neither.
func TestDryRun_ConfirmationByPlacement(t *testing.T) {
	own := &sensor.Sensor{ID: shared.NewID(), Name: "own"}
	cases := []struct {
		name    string
		managed bool
		pref    string
		sel     ownSelector
		allowed bool
		code    string
	}{
		{"managed, tenant", true, "tenant", ownSelector{sensor: own, canUse: true}, true, ""},
		{"managed, platform", true, "platform", ownSelector{canUse: true}, false, scopedom.RefusalNoEntry},
		{"managed, auto with a tenant sensor", true, "auto", ownSelector{sensor: own, canUse: true}, true, ""},
		{"managed, auto without", true, "auto", ownSelector{canUse: true}, false, scopedom.RefusalNoEntry},
		{"self-hosted, platform", false, "platform", ownSelector{canUse: true}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _ := placementService(c.managed, c.sel)
			svc.proofPolicy = StaticProofPolicy(false)
			out, err := svc.DryRun(context.Background(), DryRunInput{
				TenantID: shared.NewID(), Targets: []string{"found.example", "rejected.example"},
				SensorPreference: c.pref, Tier: 1, Tool: "nuclei",
			})
			if err != nil {
				t.Fatal(err)
			}
			byTarget := map[string]DryRunResult{}
			for _, r := range out.Results {
				byTarget[r.Target] = r
			}
			f := byTarget["found.example"]
			if f.Allowed != c.allowed || f.Code != c.code {
				t.Errorf("unconfirmed: allowed=%v code=%q, want allowed=%v code=%q", f.Allowed, f.Code, c.allowed, c.code)
			}
			if r := byTarget["rejected.example"]; r.Allowed || r.Code != scopedom.RefusalRejected {
				t.Errorf("rejected: allowed=%v code=%q", r.Allowed, r.Code)
			}
		})
	}
}

// The dispatch gate carries the placement of the caller to the ownership
// gate; a caller that does not know it is judged as a platform job.
func TestResolveDispatchTargets_PlacementReachesTheGate(t *testing.T) {
	cases := []struct {
		name    string
		in      attribution.Placement
		scanned bool
	}{
		{"tenant", attribution.PlacementTenant, true},
		{"platform", attribution.PlacementPlatform, false},
		{"unknown", attribution.PlacementUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, _ := placementService(true, ownSelector{})
			d, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
				TenantID: shared.NewID(), Targets: []string{"found.example"}, Placement: c.in, AllowNonNetworkTargets: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(d.Allowed) == 1; got != c.scanned {
				t.Errorf("allowed=%v, want %v (refused %v)", d.Allowed, c.scanned, d.Refused)
			}
		})
	}
}
