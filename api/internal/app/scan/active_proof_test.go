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
		svc := &Service{sensorSelector: allowed, logger: logger.NewNop(), zoneResolver: publicResolver{}, proofPolicy: StaticProofPolicy(tc.on), attributionGate: tc.gate}
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
	svc := &Service{sensorSelector: allowed, logger: logger.NewNop(), zoneResolver: publicResolver{}, proofPolicy: StaticProofPolicy(true), attributionGate: proofGate{err: errors.New("db down")}}
	sc := testScan("nuclei")
	sc.SensorPreference = scan.SensorPreferencePlatform
	if _, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"app.verified.example"}); err == nil {
		t.Fatal("a failed proof lookup did not fail")
	}
}

// With the setting on, intrusive (T2) scans need a verified domain on any
// sensor; off, they need none.
func TestRefuseUnprovenIntrusive(t *testing.T) {
	ctx := context.Background()
	off := &Service{logger: logger.NewNop(), proofPolicy: StaticProofPolicy(false), attributionGate: proofGate{}}
	if err := off.refuseUnprovenIntrusive(ctx, shared.NewID(), "zap", []string{"https://bigbank.example/"}); err != nil {
		t.Fatalf("setting off: intrusive scan refused: %v", err)
	}
	unwired := &Service{logger: logger.NewNop(), attributionGate: proofGate{}}
	if err := unwired.refuseUnprovenIntrusive(ctx, shared.NewID(), "zap", []string{"https://bigbank.example/"}); err != nil {
		t.Fatalf("no policy (default off): intrusive scan refused: %v", err)
	}
	svc := &Service{logger: logger.NewNop(), proofPolicy: StaticProofPolicy(true), attributionGate: proofGate{}}
	tenant := shared.NewID()
	var de *shared.DomainError
	if err := svc.refuseUnprovenIntrusive(ctx, tenant, "zap", []string{"https://bigbank.example/"}); !errors.As(err, &de) || de.Code != codeProofRequired {
		t.Fatalf("intrusive scan of an unverified target: %v", err)
	}
	if err := svc.refuseUnprovenIntrusive(ctx, tenant, "zap", []string{"https://app.verified.example/"}); err != nil {
		t.Fatalf("intrusive scan of a verified target: %v", err)
	}
	if err := svc.refuseUnprovenIntrusive(ctx, tenant, "nuclei", []string{"bigbank.example"}); err != nil {
		t.Fatalf("a safe-active scan needs no proof on tenant sensors: %v", err)
	}
}

func (proofGate) UncoveredTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}
