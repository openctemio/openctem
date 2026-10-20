package command

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingGate struct {
	got []scanapp.DispatchTargetsInput
}

func (g *recordingGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	g.got = append(g.got, in)
	return &scanapp.DispatchTargets{Allowed: in.Targets}, nil
}

// The claim re-check applies the gate with the recorded authority: a user's
// act scope, or a platform policy's explicit system authority. A job that
// asks for an act scope and records neither is withheld, never read as the
// unrestricted system.
func TestRecheckBatch_ActorAuthority(t *testing.T) {
	tenant, actor := shared.NewID(), shared.NewID()
	cases := []struct {
		name       string
		gate       commanddom.DispatchGate
		wantCalled bool
		wantOutput recheckOutcome
	}{
		{"actor", commanddom.DispatchGate{Tier: 1, ActScope: true, Actor: actor.String()}, true, recheckKeep},
		{"policy", commanddom.DispatchGate{Tier: 1, ActScope: true, SystemPolicy: "coverage"}, true, recheckKeep},
		{"neither", commanddom.DispatchGate{Tier: 1, ActScope: true}, false, recheckWithheld},
		{"no act scope asked", commanddom.DispatchGate{Tier: 1}, true, recheckKeep},
	}
	for _, tc := range cases {
		g := &recordingGate{}
		s := &Service{scopeGate: g, logger: logger.NewNop()}
		cmd := &commanddom.Command{ID: shared.NewID(), TenantID: tenant}
		outcomes := map[shared.ID]recheckOutcome{}
		s.recheckBatch(context.Background(), tenant, nil,
			[]recheckJob{{cmd: cmd, targets: []string{"a.example.com"}, gate: tc.gate}}, outcomes, map[shared.ID]*commanddom.Command{})
		assert.Equal(t, tc.wantOutput, outcomes[cmd.ID], tc.name)
		require.Equal(t, tc.wantCalled, len(g.got) == 1, tc.name)
		if !tc.wantCalled {
			continue
		}
		in := g.got[0]
		assert.Equal(t, tc.gate.SystemPolicy, in.SystemPolicy, tc.name)
		if tc.gate.Actor != "" {
			require.NotNil(t, in.FallbackUser, tc.name)
			assert.Equal(t, tc.gate.Actor, in.FallbackUser.String(), tc.name)
		} else {
			assert.Nil(t, in.FallbackUser, tc.name)
		}
	}
}
