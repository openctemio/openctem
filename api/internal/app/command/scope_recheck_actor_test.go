package command

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
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

// The claim re-check judges ownership confirmation by the sensor that takes
// the job: a job queued for platform sensors, or claimed by a shared sensor,
// is checked as a platform job (confirmation applies on the hosted service);
// a job for the organization's own sensors is not. A platform job and a
// tenant job never share one gate call.
func TestRecheck_PlacementOfTheClaimingSensor(t *testing.T) {
	tenant := shared.NewID()
	payload := []byte(`{"targets":["found.example"]}`)
	mk := func(platform bool) *commanddom.Command {
		return &commanddom.Command{ID: shared.NewID(), TenantID: tenant, Type: commanddom.CommandTypeScan, Payload: payload, IsPlatformJob: platform}
	}
	cases := []struct {
		name string
		ctx  context.Context
		cmd  *commanddom.Command
		want attribution.Placement
	}{
		{"tenant job on a tenant sensor", context.Background(), mk(false), attribution.PlacementTenant},
		{"platform job", context.Background(), mk(true), attribution.PlacementPlatform},
		{"any job a shared sensor claims", attribution.WithPlacement(context.Background(), attribution.PlacementPlatform), mk(false), attribution.PlacementPlatform},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &recordingGate{}
			s := &Service{scopeGate: g, logger: logger.NewNop()}
			s.recheckScope(tc.ctx, tenant, nil, []*commanddom.Command{tc.cmd})
			require.Len(t, g.got, 1)
			assert.Equal(t, tc.want, g.got[0].Placement)
		})
	}

	t.Run("separate calls", func(t *testing.T) {
		g := &recordingGate{}
		s := &Service{scopeGate: g, logger: logger.NewNop()}
		s.recheckScope(context.Background(), tenant, nil, []*commanddom.Command{mk(false), mk(true)})
		require.Len(t, g.got, 2)
		assert.NotEqual(t, g.got[0].Placement, g.got[1].Placement)
	})
}
