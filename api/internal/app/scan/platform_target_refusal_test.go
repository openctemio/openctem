package scan

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sharedCheckGate answers proof and program lookups for the shared-sensor
// target check.
type sharedCheckGate struct {
	AttributionGate
	unproven, program []string
	err               error
}

func (g sharedCheckGate) UnverifiedTargets(_ context.Context, _ shared.ID, targets []string) ([]string, error) {
	if g.err != nil {
		return nil, g.err
	}
	var out []string
	for _, t := range targets {
		if slices.Contains(g.unproven, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

func (g sharedCheckGate) ProgramOnlyTargets(_ context.Context, _ shared.ID, targets []string) ([]string, error) {
	var out []string
	for _, t := range targets {
		if slices.Contains(g.program, t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// PlatformTargetRefusal is the one shared-sensor target check, exported for
// workflow step dispatch: internal targets and asset groups, unproven
// targets when the operator requires proof, and program targets are
// refused; a failed lookup is an error (fail closed).
func TestPlatformTargetRefusal(t *testing.T) {
	ctx := context.Background()
	gate := sharedCheckGate{unproven: []string{"new.example"}, program: []string{"bounty.example"}}
	cases := []struct {
		name    string
		proof   bool
		gate    sharedCheckGate
		targets []string
		group   bool
		code    string // "" = allowed, "error" = lookup failure
	}{
		{"public, proven", true, gate, []string{"owned.example"}, false, ""},
		{"internal literal", false, gate, []string{"owned.example", "10.0.0.5"}, false, codePlatformRefused},
		{"metadata address", false, gate, []string{"169.254.169.254"}, false, codePlatformRefused},
		{"asset group", false, gate, []string{"owned.example"}, true, codePlatformRefused},
		{"unproven with proof on", true, gate, []string{"new.example"}, false, codeProofRequired},
		{"unproven with proof off", false, gate, []string{"new.example"}, false, ""},
		{"program target", false, gate, []string{"bounty.example"}, false, codePlatformRefused},
		{"proof lookup fails", true, sharedCheckGate{err: errors.New("db down")}, []string{"owned.example"}, false, "error"},
	}
	for _, tc := range cases {
		svc := &Service{logger: logger.NewNop(), attributionGate: tc.gate, proofPolicy: StaticProofPolicy(tc.proof)}
		err := svc.PlatformTargetRefusal(ctx, shared.NewID(), tc.targets, tc.group)
		var de *shared.DomainError
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.code == "error" && (err == nil || errors.As(err, &de)):
			t.Errorf("%s: want a lookup error, got %v", tc.name, err)
		case tc.code != "" && tc.code != "error" && (!errors.As(err, &de) || de.Code != tc.code):
			t.Errorf("%s: want %s, got %v", tc.name, tc.code, err)
		}
	}
}
