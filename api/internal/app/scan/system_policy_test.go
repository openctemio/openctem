package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func actGateService(stub *stubActScope) *Service {
	return &Service{scopeExclusions: &stubExclusions{}, actScope: stub, attributionGate: &stubGate{}, logger: logger.NewNop()}
}

// Every way the dispatch gate asks for an actor: a person (context user or
// fallback owner), an explicit platform policy, or nobody. Nobody is refused;
// the policy never carries a member's act scope; an unknown policy is refused.
func TestDispatchGate_ActorAuthority(t *testing.T) {
	ctx := context.Background()
	tenant, owner := shared.NewID(), shared.NewID()
	targets := []string{"a.example.com"}

	t.Run("a person's dispatch asks for an actor", func(t *testing.T) {
		stub := &stubActScope{}
		_, err := actGateService(stub).ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets, ActScope: true, FallbackUser: &owner})
		require.NoError(t, err)
		require.Len(t, stub.got, 1)
		assert.True(t, stub.got[0].RequireActor)
		assert.False(t, stub.got[0].System)
		assert.Equal(t, &owner, stub.got[0].FallbackUser)
	})

	t.Run("a policy dispatches with the system authority and no user", func(t *testing.T) {
		for _, policy := range SystemPolicies {
			stub := &stubActScope{}
			// ActScope off, as the coverage and enrichment paths set it: the
			// policy still passes through the scope-entry check.
			_, err := actGateService(stub).ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets, SystemPolicy: policy})
			require.NoError(t, err, policy)
			require.Len(t, stub.got, 1, policy)
			assert.True(t, stub.got[0].System, policy)
			assert.Nil(t, stub.got[0].FallbackUser, policy)
		}
	})

	t.Run("no actor, no policy: not asked, not checked (system paths of other kinds)", func(t *testing.T) {
		stub := &stubActScope{}
		_, err := actGateService(stub).ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets})
		require.NoError(t, err)
		assert.Empty(t, stub.got)
	})

	t.Run("an unknown policy and a policy with a user are refused", func(t *testing.T) {
		_, err := actGateService(&stubActScope{}).ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets, SystemPolicy: "anything"})
		assert.ErrorIs(t, err, shared.ErrValidation)
		_, err = actGateService(&stubActScope{}).ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets, SystemPolicy: "coverage", FallbackUser: &owner})
		assert.ErrorIs(t, err, shared.ErrValidation)
	})
}

// Coverage dispatches as the coverage policy: its gate input names the system
// policy and no user.
func TestStartCoverage_UsesTheSystemPolicy(t *testing.T) {
	stub := &stubActScope{err: errors.New("stop after the gate")}
	svc := actGateService(stub)
	_, err := svc.StartCoverage(context.Background(), CoverageInput{TenantID: shared.NewID(), Capability: "probe.http", Targets: []string{"a.example.com"}})
	require.Error(t, err)
	require.Len(t, stub.got, 1)
	assert.True(t, stub.got[0].System)
	assert.Nil(t, stub.got[0].FallbackUser)
}

func TestStartEnrichment_TargetsUseTheSystemPolicy(t *testing.T) {
	stub := &stubActScope{err: errors.New("stop after the gate")}
	svc := actGateService(stub)
	res := &EnrichmentResult{}
	_, err := svc.enrichmentTargets(context.Background(), EnrichmentInput{TenantID: shared.NewID(), Targets: []string{"a.example.com"}}, res)
	require.Error(t, err)
	require.Len(t, stub.got, 1)
	assert.True(t, stub.got[0].System)
}

// A managed scan's runs record their policy and no actor, in the gate record
// of their commands; a person's scan keeps its actor chain.
func TestScanDispatchGate_ManagedScanActsAsItsPolicy(t *testing.T) {
	tenant, owner, trigger := shared.NewID(), shared.NewID(), shared.NewID()
	managed, _ := scan.NewScan(tenant, "Continuous coverage: probe.http", shared.ID{}, scan.ScanTypeSingle)
	require.NoError(t, managed.SetSingleScanner("httpx", nil, 1))
	managed.ManagedBy, managed.ManagedKey = scan.ManagedByCoverage, "probe.http"
	run := &scanrun.Run{TriggerType: scanworkflow.TriggerTypeSystem, TriggeredBy: PolicyTriggerPrefix + "coverage",
		Context: map[string]any{RunContextKeySystemPolicy: "coverage"}}
	g := scanDispatchGate(managed, run)
	assert.Equal(t, "coverage", g.SystemPolicy)
	assert.Empty(t, g.Actor)

	mine, _ := scan.NewScan(tenant, "Weekly", owner, scan.ScanTypeSingle)
	mine.SetCreatedBy(owner)
	require.NoError(t, mine.SetSingleScanner("httpx", nil, 1))
	g = scanDispatchGate(mine, &scanrun.Run{TriggeredBy: trigger.String(), Context: map[string]any{}})
	assert.Empty(t, g.SystemPolicy)
	assert.Equal(t, trigger.String(), g.Actor)
	g = scanDispatchGate(mine, &scanrun.Run{Context: map[string]any{}})
	assert.Equal(t, owner.String(), g.Actor)
}

// The policy of a run comes from the platform: an unknown value in the run
// context is no policy.
func TestRunSystemPolicy(t *testing.T) {
	for in, want := range map[string]string{"coverage": "coverage", "enrichment": "enrichment", "admin": "", "": ""} {
		run := &scanrun.Run{Context: map[string]any{RunContextKeySystemPolicy: in}}
		assert.Equal(t, want, RunSystemPolicy(run), in)
	}
	assert.Equal(t, "", RunSystemPolicy(&scanrun.Run{}))
}

// Queue class by who started the run: a person's own start is high,
// schedules, automations, retries and discovery are normal, a policy's runs
// are low. A user-id-less manual run (an API key) stays normal.
func TestCommandPriorityOf(t *testing.T) {
	user := shared.NewID().String()
	cases := []struct {
		name string
		run  *scanrun.Run
		want command.CommandPriority
	}{
		{"person's Run now", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual, TriggeredBy: user}, command.CommandPriorityHigh},
		{"manual without a user", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual}, command.CommandPriorityNormal},
		{"schedule", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeSchedule}, command.CommandPriorityNormal},
		{"automation", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeAutomation, TriggeredBy: "workflow:abc"}, command.CommandPriorityNormal},
		{"retry", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeSystem}, command.CommandPriorityNormal},
		{"coverage policy", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeSystem, TriggeredBy: "policy:coverage", Context: map[string]any{RunContextKeySystemPolicy: "coverage"}}, command.CommandPriorityLow},
		// A person's id on a policy run is still a policy run.
		{"policy run with a stray user", &scanrun.Run{TriggerType: scanworkflow.TriggerTypeManual, TriggeredBy: user, Context: map[string]any{RunContextKeySystemPolicy: "enrichment"}}, command.CommandPriorityLow},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, CommandPriorityOf(tc.run), tc.name)
	}
}

// The run context a step's command carries never holds the policy marker.
func TestStepRunContext_DropsTheSystemPolicy(t *testing.T) {
	out := StepRunContext(map[string]any{RunContextKeySystemPolicy: "coverage", "keep": 1}, nil)
	_, has := out[RunContextKeySystemPolicy]
	assert.False(t, has)
	assert.Equal(t, 1, out["keep"])
}
