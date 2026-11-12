package aitriage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type orgPolicyStub struct{ allow bool }

func (p *orgPolicyStub) OrgProviderAllowed(context.Context) bool { return p.allow }

// memBudget is an in-memory ai_triage_budgets.
type memBudget struct {
	mu    sync.Mutex
	limit int64
	used  map[shared.ID]int64
}

func (m *memBudget) GetOrCreate(_ context.Context, id shared.ID, start, end time.Time, _ int64) (*BudgetRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &BudgetRow{TenantID: id, PeriodStart: start, PeriodEnd: end, TokenLimit: m.limit, TokensUsed: m.used[id]}, nil
}

func (m *memBudget) IncrementUsed(_ context.Context, id shared.ID, _ time.Time, d int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.used[id] += d
	return m.used[id], nil
}
func (m *memBudget) UpdateLastWarnSent(context.Context, shared.ID, time.Time, int64) error {
	return nil
}
func (m *memBudget) UpdateLastBlockSent(context.Context, shared.ID, time.Time, int64) error {
	return nil
}

// An organization on its own provider is refused, at the request and in the
// worker, while the platform forbids own providers, and never falls back to
// the platform key. Once allowed it runs, and the result records the
// provider and the model.
func TestAITriage_OwnProviderPolicy(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	h.ai.s.Mode, h.ai.s.Provider, h.ai.s.APIKey = tenant.AIModeBYOK, tenant.LLMProviderOpenAI, "ciphertext"
	pol := &orgPolicyStub{allow: false}
	h.svc.SetOrgProviderPolicy(pol)
	f := h.finding(t, vulnerability.FindingSourceDAST, nil)

	_, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: h.tenantID.String(), FindingID: f.ID().String(), TriageType: "manual"})
	require.ErrorIs(t, err, ErrOwnProviderNotAllowed)

	row := h.pendingRow(t, f)
	err = h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row.ID(), h.tenantID, f.ID())
	require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
	require.Equal(t, FailNotConfigured, row.ErrorMessage())
	require.Zero(t, h.llm.calls, "a forbidden own provider never reaches the model or the platform key")

	info, err := h.svc.GetAIConfig(ctx, h.tenantID.String())
	require.NoError(t, err)
	require.False(t, info.IsEnabled)
	require.Equal(t, ConfigReasonOwnProviderNotAllowed, info.Reason)

	pol.allow = true
	resp, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: h.tenantID.String(), FindingID: f.ID().String(), TriageType: "manual"})
	require.NoError(t, err)
	rid := shared.MustIDFromString(resp.JobID)
	require.NoError(t, h.svc.ProcessTriage(ctx, rid, h.tenantID, f.ID()))
	res := h.triage.rows[rid]
	require.Equal(t, aitriagedom.TriageStatusCompleted, res.Status())
	require.Equal(t, "fake", res.LLMProvider(), "the result records the provider")
	require.Equal(t, "fake-model", res.LLMModel(), "the result records the model")
	require.Equal(t, 1, h.llm.calls)
}

// The monthly cap counts an organization's tokens whichever key pays for
// them.
func TestAITriage_MonthlyCapAppliesToOwnProvider(t *testing.T) {
	ctx := context.Background()
	for name, mode := range map[string]tenant.AIMode{"platform": tenant.AIModePlatform, "own": tenant.AIModeBYOK} {
		t.Run(name, func(t *testing.T) {
			h := newEgressHarness(t)
			h.ai.s.Mode, h.ai.s.Provider, h.ai.s.APIKey = mode, tenant.LLMProviderOpenAI, "ciphertext"
			mem := &memBudget{limit: 1000, used: map[shared.ID]int64{}}
			h.svc.SetBudgetService(NewBudgetService(mem, BudgetServiceConfig{Enabled: true, DefaultTokensPerMonth: 1000}, logger.NewNop()))
			f := h.finding(t, vulnerability.FindingSourceDAST, nil)

			resp, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: h.tenantID.String(), FindingID: f.ID().String(), TriageType: "manual"})
			require.NoError(t, err)
			rid := shared.MustIDFromString(resp.JobID)
			require.NoError(t, h.svc.ProcessTriage(ctx, rid, h.tenantID, f.ID()))
			require.Equal(t, int64(20), mem.used[h.tenantID], "tokens are counted in %s mode", name)

			// A month's allowance already used: refused before the call.
			mem.used[h.tenantID] = 5000
			calls := h.llm.calls
			row := h.pendingRow(t, f)
			err = h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row.ID(), h.tenantID, f.ID())
			require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
			require.Equal(t, FailBudgetExhausted, row.ErrorMessage())
			require.Equal(t, calls, h.llm.calls, "no call past the cap")
		})
	}
}
