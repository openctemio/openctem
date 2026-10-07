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

// Platform sensors probe from the platform's addresses: with
// SCOPE_ACTIVE_PROOF=platform_sensors every target must be verified
// (RFC-054 §8.1). A malicious tenant cannot point them at a third party.
func TestShouldUsePlatformSensor_ProofRequired(t *testing.T) {
	ctx := context.Background()
	allowed := stubSelector{false, true}
	cases := []struct {
		name    string
		mode    string
		gate    AttributionGate
		pref    scan.SensorPreference
		targets []string
		want    bool
		code    string
	}{
		{"off: unverified goes to platform", ActiveProofOff, proofGate{}, scan.SensorPreferencePlatform, []string{"bigbank.example"}, true, ""},
		{"platform_sensors: verified goes to platform", ActiveProofPlatformSensors, proofGate{}, scan.SensorPreferencePlatform, []string{"app.verified.example"}, true, ""},
		{"platform_sensors: explicit platform, unverified refused", ActiveProofPlatformSensors, proofGate{}, scan.SensorPreferencePlatform, []string{"app.verified.example", "bigbank.example"}, false, codeProofRequired},
		{"platform_sensors: auto, unverified waits for tenant sensors", ActiveProofPlatformSensors, proofGate{}, scan.SensorPreferenceAuto, []string{"bigbank.example"}, false, ""},
		{"all: same on platform sensors", ActiveProofAll, proofGate{}, scan.SensorPreferencePlatform, []string{"203.0.113.9"}, false, codeProofRequired},
		{"no verifier: fail closed", ActiveProofPlatformSensors, nil, scan.SensorPreferencePlatform, []string{"app.verified.example"}, false, codeProofRequired},
	}
	for _, tc := range cases {
		svc := &Service{sensorSelector: allowed, logger: logger.NewNop(), activeProof: tc.mode, attributionGate: tc.gate}
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
	svc := &Service{sensorSelector: allowed, logger: logger.NewNop(), activeProof: ActiveProofPlatformSensors, attributionGate: proofGate{err: errors.New("db down")}}
	sc := testScan("nuclei")
	sc.SensorPreference = scan.SensorPreferencePlatform
	if _, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"app.verified.example"}); err == nil {
		t.Fatal("a failed proof lookup did not fail")
	}
}

// Intrusive (T2) scans need a verified domain whatever the mode.
func TestRefuseUnprovenIntrusive(t *testing.T) {
	ctx := context.Background()
	svc := &Service{logger: logger.NewNop(), activeProof: ActiveProofOff, attributionGate: proofGate{}}
	tenant := shared.NewID()
	var de *shared.DomainError
	if err := svc.refuseUnprovenIntrusive(ctx, tenant, "zap", []string{"https://bigbank.example/"}); !errors.As(err, &de) || de.Code != codeProofRequired {
		t.Fatalf("intrusive scan of an unverified target: %v", err)
	}
	if err := svc.refuseUnprovenIntrusive(ctx, tenant, "zap", []string{"https://app.verified.example/"}); err != nil {
		t.Fatalf("intrusive scan of a verified target: %v", err)
	}
	if err := svc.refuseUnprovenIntrusive(ctx, tenant, "nuclei", []string{"bigbank.example"}); err != nil {
		t.Fatalf("a safe-active scan needs no proof in mode off: %v", err)
	}
}
