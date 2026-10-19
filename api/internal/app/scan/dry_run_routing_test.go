package scan

import (
	"context"
	"errors"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ownSelector has (or has not) one online tenant sensor that takes the job.
type ownSelector struct {
	sensor *sensor.Sensor
	canUse bool
	err    error
}

func (s ownSelector) CheckSensorAvailability(context.Context, shared.ID, string, bool) *SensorAvailability {
	return &SensorAvailability{}
}

func (s ownSelector) CanUsePlatformSensors(context.Context, shared.ID) (bool, string) {
	return s.canUse, "not enabled"
}

func (s ownSelector) SelectSensor(context.Context, SelectSensorRequest) (*SelectSensorResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.sensor != nil {
		return &SelectSensorResult{Sensor: s.sensor}, nil
	}
	return &SelectSensorResult{}, nil
}

func plannerService(proof bool, sel SensorSelector) *Service {
	return &Service{scopeExclusions: &stubExclusions{}, attributionGate: proofGate{}, sensorSelector: sel, logger: logger.NewNop(), proofPolicy: StaticProofPolicy(proof)}
}

// The preflight decides like the trigger (RFC-054 §6.4, §8.1): with the
// platform's proof setting on, auto runs a job with unverified targets on
// the organization's own sensor and says so; only without one do those
// targets need proof. Off, nothing needs proof.
func TestDryRun_RoutingAndProof(t *testing.T) {
	ctx := context.Background()
	own := &sensor.Sensor{ID: shared.NewID(), Name: "sensor-docker-01"}
	targets := []string{"app.verified.example", "portal.customer.example"}
	cases := []struct {
		name       string
		proof      bool
		sel        ownSelector
		pref       string
		tier       int
		refused    []string
		runsOn     string
		reason     string
		sensorName string
	}{
		{"off: auto, no own sensor: platform, nothing refused", false, ownSelector{canUse: true}, "auto", 1, nil, RoutingPlatform, RoutingReasonPlatform, ""},
		{"off: auto with own sensor: tenant first", false, ownSelector{sensor: own, canUse: true}, "auto", 1, nil, RoutingTenant, RoutingReasonTenantFirst, "sensor-docker-01"},
		{"off: intrusive on platform needs no proof", false, ownSelector{canUse: true}, "platform", 2, nil, RoutingPlatform, RoutingReasonPlatform, ""},
		{"on: auto with own sensor: unverified run there", true, ownSelector{sensor: own, canUse: true}, "auto", 1, nil, RoutingTenant, RoutingReasonProof, "sensor-docker-01"},
		{"on: auto without own sensor: unverified need proof", true, ownSelector{canUse: true}, "auto", 1, []string{"portal.customer.example"}, RoutingWaits, RoutingReasonNoTenantSensor, ""},
		{"on: explicit platform: unverified refused", true, ownSelector{sensor: own, canUse: true}, "platform", 1, []string{"portal.customer.example"}, RoutingPlatform, RoutingReasonPlatform, ""},
		{"on: own sensors, safe active: no proof", true, ownSelector{sensor: own}, "tenant", 1, nil, RoutingTenant, RoutingReasonTenantFirst, "sensor-docker-01"},
		{"on: own sensors, intrusive: proof needed", true, ownSelector{sensor: own}, "tenant", 2, []string{"portal.customer.example"}, RoutingTenant, RoutingReasonTenantFirst, "sensor-docker-01"},
		{"on: sensor lookup fails: waits, unverified refused", true, ownSelector{err: errors.New("db down")}, "auto", 1, []string{"portal.customer.example"}, RoutingWaits, RoutingReasonNoTenantSensor, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := plannerService(c.proof, c.sel).DryRun(ctx, DryRunInput{TenantID: shared.NewID(), Targets: targets, SensorPreference: c.pref, Tier: c.tier, Tool: "nuclei"})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]bool{}
			for _, r := range c.refused {
				want[r] = true
			}
			for _, r := range out.Results {
				if want[r.Target] != !r.Allowed {
					t.Fatalf("%s: allowed=%v code=%q", r.Target, r.Allowed, r.Code)
				}
				if !r.Allowed && r.Code != scopedom.RefusalProofRequired {
					t.Fatalf("%s: code %q, want proof_required", r.Target, r.Code)
				}
			}
			if out.Routing.RunsOn != c.runsOn || out.Routing.Reason != c.reason || out.Routing.SensorName != c.sensorName {
				t.Fatalf("routing = %+v, want %s/%s/%q", out.Routing, c.runsOn, c.reason, c.sensorName)
			}
		})
	}
}

// Internal targets never route to platform sensors in the preflight.
func TestDryRun_RoutingInternalWaits(t *testing.T) {
	out, err := plannerService(false, ownSelector{canUse: true}).DryRun(context.Background(),
		DryRunInput{TenantID: shared.NewID(), Targets: []string{"10.1.2.3"}, SensorPreference: "auto", Tier: 1})
	if err != nil {
		t.Fatal(err)
	}
	if out.Routing.RunsOn == RoutingPlatform {
		t.Fatalf("an internal target was routed to platform sensors: %+v", out.Routing)
	}
}

// "Scan the allowed targets, skip the rest": the refused targets are left
// out with their codes, the rest go on; nothing left is refused.
func TestPartitionRefused(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := plannerService(true, ownSelector{canUse: true})
	in := CreateScanInput{ScanType: "single", ScannerName: "nuclei", SensorPreference: "platform",
		Targets: []string{"app.verified.example", "portal.customer.example", "www.customer.example"}}
	kept, skipped, err := svc.partitionRefused(ctx, tenant, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0] != "app.verified.example" || len(skipped) != 2 || skipped[0].Code != scopedom.RefusalProofRequired {
		t.Fatalf("kept %v skipped %+v", kept, skipped)
	}
	in.Targets = []string{"portal.customer.example"}
	_, _, err = svc.partitionRefused(ctx, tenant, in)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != codeNothingAllowed {
		t.Fatalf("nothing allowed: %v", err)
	}
	// Setting off: nothing is skipped.
	kept, skipped, err = plannerService(false, ownSelector{canUse: true}).partitionRefused(ctx, tenant,
		CreateScanInput{ScanType: "single", ScannerName: "nuclei", SensorPreference: "platform", Targets: []string{"portal.customer.example"}})
	if err != nil || len(kept) != 1 || len(skipped) != 0 {
		t.Fatalf("proof off: kept %v skipped %v err %v", kept, skipped, err)
	}
}

func TestCreateTier(t *testing.T) {
	cases := []struct {
		in   CreateScanInput
		want int
	}{
		{CreateScanInput{ScanType: "single", ScannerName: "zap"}, 2},
		{CreateScanInput{ScanType: "single", ScannerName: "zap", Intensity: "active"}, 1},
		{CreateScanInput{ScanType: "single", ScannerName: "nuclei"}, 1},
		{CreateScanInput{ScanType: "workflow", Intensity: "intrusive"}, 2},
		{CreateScanInput{ScanType: "workflow"}, 1},
		{CreateScanInput{ScanType: "workflow", Intensity: "passive"}, 0},
	}
	for _, c := range cases {
		if got := createTier(c.in); got != c.want {
			t.Errorf("%+v: tier %d, want %d", c.in, got, c.want)
		}
	}
}
