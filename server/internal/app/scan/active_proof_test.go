package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// proofGate is an ownership gate that blocks nothing and proves the names
// under verified.example.
type proofGate struct{ err error }

func (proofGate) ActiveCheckBlocked(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return nil, nil
}

func (proofGate) BlockedTargets(context.Context, shared.ID, []string) (map[string]attribution.State, error) {
	return nil, nil
}

func (proofGate) TierExceeded(context.Context, shared.ID, []string, scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	return nil, nil
}

func (g proofGate) UnverifiedTargets(_ context.Context, _ shared.ID, targets []string) ([]string, error) {
	if g.err != nil {
		return nil, g.err
	}
	var out []string
	for _, t := range targets {
		if !strings.Contains(t, "verified.example") {
			out = append(out, t)
		}
	}
	return out, nil
}

// Platform sensors probe from the platform's addresses: with the platform
// setting on, every target must be verified (RFC-054 §8.1). A malicious
// tenant cannot point them at a third party. Off (the default), the scope
// entry is the authorization.
func TestShouldUsePlatformSensor_ProofRequired(t *testing.T) {
	ctx := context.Background()
	allowed := stubSelector{false, true}
	cases := []struct {
		name    string
		on      bool
		gate    AttributionGate
		pref    scan.SensorPreference
		targets []string
		want    bool
		code    string
	}{
		{"off: unverified goes to platform", false, proofGate{}, scan.SensorPreferencePlatform, []string{"bigbank.example"}, true, ""},
		{"platform_sensors: verified goes to platform", true, proofGate{}, scan.SensorPreferencePlatform, []string{"app.verified.example"}, true, ""},
		{"platform_sensors: explicit platform, unverified refused", true, proofGate{}, scan.SensorPreferencePlatform, []string{"app.verified.example", "bigbank.example"}, false, codeProofRequired},
		{"platform_sensors: auto, unverified waits for tenant sensors", true, proofGate{}, scan.SensorPreferenceAuto, []string{"bigbank.example"}, false, ""},
		{"on: an address needs proof too", true, proofGate{}, scan.SensorPreferencePlatform, []string{"203.0.113.9"}, false, codeProofRequired},
		{"off: auto keeps tenant-first selection", false, proofGate{}, scan.SensorPreferenceAuto, []string{"bigbank.example"}, true, ""},
		{"no verifier: fail closed", true, nil, scan.SensorPreferencePlatform, []string{"app.verified.example"}, false, codeProofRequired},
	}
	for _, tc := range cases {
		svc := &Service{sensorSelector: allowed, logger: logger.NewNop(), zoneResolver: publicResolver{}, sharedLimits: noLimits{}, proofPolicy: StaticProofPolicy(tc.on), attributionGate: tc.gate}
		sc := testScan("nuclei")
		sc.SensorPreference = tc.pref
		got, err := svc.shouldUsePlatformSensor(ctx, sc, tc.targets)
		var de *shared.DomainError
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.code != "" && (!errors.As(err, &de) || de.Code != tc.code):
			t.Errorf("%s: err %v, want %s", tc.name, err, tc.code)
		case got != tc.want:
			t.Errorf("%s: platform = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A failed proof lookup fails the explicit-platform decision.
	svc := &Service{sensorSelector: allowed, logger: logger.NewNop(), zoneResolver: publicResolver{}, sharedLimits: noLimits{}, proofPolicy: StaticProofPolicy(true), attributionGate: proofGate{err: errors.New("db down")}}
	sc := testScan("nuclei")
	sc.SensorPreference = scan.SensorPreferencePlatform
	if _, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"app.verified.example"}); err == nil {
		t.Fatal("a failed proof lookup did not fail")
	}
}

// Proof is for jobs on platform sensors. An intrusive (T2) scan of an
// unverified target is not refused for lack of proof: in auto mode it never
// goes to platform sensors (it waits for the organization's own sensor), and
// an explicit platform preference is refused.
func TestIntrusiveUnverified_NeverReachesPlatformSensors(t *testing.T) {
	ctx := context.Background()
	svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(), zoneResolver: publicResolver{}, sharedLimits: noLimits{}, proofPolicy: StaticProofPolicy(true), attributionGate: proofGate{}}
	sc := testScan("zap")
	sc.SensorPreference = scan.SensorPreferenceAuto
	if onPlatform, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"bigbank.example"}); err != nil || onPlatform {
		t.Fatalf("auto, intrusive, unverified: platform=%v err=%v, want the job to wait for the own sensor", onPlatform, err)
	}
	sc.SensorPreference = scan.SensorPreferencePlatform
	var de *shared.DomainError
	if _, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"bigbank.example"}); !errors.As(err, &de) || de.Code != codeProofRequired {
		t.Fatalf("platform, intrusive, unverified: %v, want %s", err, codeProofRequired)
	}
	sc.SensorPreference = scan.SensorPreferenceTenant
	if onPlatform, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"bigbank.example"}); err != nil || onPlatform {
		t.Fatalf("tenant, intrusive, unverified: platform=%v err=%v", onPlatform, err)
	}
}

func (proofGate) UncoveredTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}
