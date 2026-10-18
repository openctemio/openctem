package attack

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A chain is shown to a restricted member only when every hop is in scope,
// so no out-of-scope asset name or id leaks along the path.
func TestChainInScope(t *testing.T) {
	in1, in2, out := shared.NewID(), shared.NewID(), shared.NewID()
	keep := func(id shared.ID) bool { return id == in1 || id == in2 }
	hop := func(id shared.ID) ChainHop { return ChainHop{AssetID: id.String()} }

	cases := []struct {
		name string
		hops []ChainHop
		want bool
	}{
		{"all hops in scope", []ChainHop{hop(in1), hop(in2)}, true},
		{"directly exposed in-scope target", []ChainHop{hop(in1)}, true},
		{"out-of-scope entry point", []ChainHop{hop(out), hop(in1)}, false},
		{"out-of-scope intermediate hop", []ChainHop{hop(in1), hop(out), hop(in2)}, false},
		{"out-of-scope target", []ChainHop{hop(in1), hop(out)}, false},
		{"unparseable hop", []ChainHop{hop(in1), {AssetID: "x"}}, false},
		{"empty chain", nil, false},
	}
	for _, tc := range cases {
		if got := chainInScope(ExposureChain{Hops: tc.hops}, keep); got != tc.want {
			t.Errorf("%s: chainInScope = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A caller-facing attack-surface read refuses when the data-scope enforcer is
// not wired, instead of returning the organization's full result.
func TestCallerReads_UnwiredEnforcer_FailClosed(t *testing.T) {
	svc := NewSurfaceService(nil, nil, logger.NewNop())
	if _, err := svc.AttackPathScoresForCaller(context.Background(), shared.NewID()); !errors.Is(err, datascope.ErrNotConfigured) {
		t.Fatalf("AttackPathScoresForCaller err = %v, want datascope.ErrNotConfigured", err)
	}
	if _, err := svc.ExposureChainsForCaller(context.Background(), shared.NewID()); !errors.Is(err, datascope.ErrNotConfigured) {
		t.Fatalf("ExposureChainsForCaller err = %v, want datascope.ErrNotConfigured", err)
	}
}
