package scan

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// programGate answers which targets only program entries cover.
type programGate struct {
	AttributionGate
	only []string
	err  error
}

func (g programGate) ProgramOnlyTargets(_ context.Context, _ shared.ID, targets []string) ([]string, error) {
	if g.err != nil {
		return nil, g.err
	}
	var out []string
	for _, t := range targets {
		if slices.Contains(g.only, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// Bug-bounty program targets never go to platform sensors, whatever the
// proof mode (RFC-065 §8): an explicit platform preference is refused, auto
// stays on the tenant's sensors; a target an ownership entry also covers is
// unaffected.
func TestPlatformSensors_ProgramTargets(t *testing.T) {
	ctx := context.Background()
	gate := programGate{only: []string{"www.acme.example"}}
	for _, mode := range []string{ActiveProofOff, ActiveProofPlatformSensors} {
		svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(), attributionGate: gate, activeProof: mode}
		if mode != ActiveProofOff {
			// Proof is not what refuses here: mark everything proven.
			svc.attributionGate = provenProgramGate{gate}
		}
		sc := testScan("nuclei")

		sc.SensorPreference = scan.SensorPreferencePlatform
		_, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"www.acme.example"})
		var de *shared.DomainError
		if !errors.As(err, &de) || de.Code != codePlatformRefused {
			t.Fatalf("%s: explicit platform with a program target: %v", mode, err)
		}
		if ok, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"owned.example"}); err != nil || !ok {
			t.Fatalf("%s: an owned target may use platform sensors: %v %v", mode, ok, err)
		}

		sc.SensorPreference = scan.SensorPreferenceAuto
		if ok, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"owned.example", "www.acme.example"}); err != nil || ok {
			t.Fatalf("%s: auto with a program target must stay on tenant sensors: %v %v", mode, ok, err)
		}
		r, err := svc.decideWorkflowRouting(ctx, sc, []string{"www.acme.example"})
		if err != nil || r.Routing != sensorRoutingTenant {
			t.Fatalf("%s: workflow auto with a program target: %+v %v", mode, r, err)
		}
		sc.SensorPreference = scan.SensorPreferencePlatform
		if _, err := svc.decideWorkflowRouting(ctx, sc, []string{"www.acme.example"}); !errors.As(err, &de) || de.Code != codePlatformRefused {
			t.Fatalf("%s: workflow explicit platform with a program target: %v", mode, err)
		}
	}

	// A failed lookup keeps an auto job on tenant sensors and refuses an
	// explicit platform preference.
	svc := &Service{sensorSelector: stubSelector{false, true}, logger: logger.NewNop(), attributionGate: programGate{err: errors.New("db down")}}
	sc := testScan("nuclei")
	sc.SensorPreference = scan.SensorPreferencePlatform
	if _, err := svc.shouldUsePlatformSensor(ctx, sc, []string{"x.example"}); err == nil {
		t.Fatal("a failed lookup must refuse platform sensors")
	}
	sc.SensorPreference = scan.SensorPreferenceAuto
	r, err := svc.decideWorkflowRouting(ctx, sc, []string{"x.example"})
	if err != nil || r.Routing != sensorRoutingTenant {
		t.Fatalf("failed lookup, workflow auto: %+v %v", r, err)
	}
}

// provenProgramGate also says every target is at or under a verified domain.
type provenProgramGate struct{ programGate }

func (provenProgramGate) UnverifiedTargets(context.Context, shared.ID, []string) ([]string, error) {
	return nil, nil
}
