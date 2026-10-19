package aitriage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- fakes --------------------------------------------------------------

// fakeLLM counts calls: the assertion that content was never sent.
type fakeLLM struct {
	mu    sync.Mutex
	calls int
	err   error
	resp  string
}

func (f *fakeLLM) Complete(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &llm.CompletionResponse{Content: f.resp, PromptTokens: 10, CompletionTokens: 10, TotalTokens: 20}, nil
}
func (f *fakeLLM) Name() string    { return "fake" }
func (f *fakeLLM) Model() string   { return "fake-model" }
func (f *fakeLLM) Validate() error { return nil }

type fakeFactory struct{ p llm.Provider }

func (f fakeFactory) CreateProviderForTenant(string, tenant.AISettings) (llm.Provider, error) {
	return f.p, nil
}

type fakeTenants struct {
	tenant.Repository
	t *tenant.Tenant
}

func (f fakeTenants) GetByID(_ context.Context, id shared.ID) (*tenant.Tenant, error) {
	if f.t == nil || f.t.ID() != id {
		return nil, shared.ErrNotFound
	}
	return f.t, nil
}

type fakeFindings struct {
	vulnerability.FindingRepository
	byID map[shared.ID]*vulnerability.Finding
}

func (f fakeFindings) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	v, ok := f.byID[id]
	if !ok || v.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return v, nil
}

func (f fakeFindings) ExistsByIDs(_ context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	for _, id := range ids {
		if v, ok := f.byID[id]; ok && v.TenantID() == tenantID {
			out[id] = true
		}
	}
	return out, nil
}

type fakeTriageRepo struct {
	aitriagedom.Repository
	mu      sync.Mutex
	rows    map[shared.ID]*aitriagedom.TriageResult
	created int
}

func newFakeTriageRepo() *fakeTriageRepo {
	return &fakeTriageRepo{rows: map[shared.ID]*aitriagedom.TriageResult{}}
}

func (f *fakeTriageRepo) Create(_ context.Context, r *aitriagedom.TriageResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created++
	f.rows[r.ID()] = r
	return nil
}

func (f *fakeTriageRepo) Update(_ context.Context, r *aitriagedom.TriageResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[r.ID()] = r
	return nil
}

func (f *fakeTriageRepo) HasPendingOrProcessing(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

func (f *fakeTriageRepo) AcquireTriageSlot(_ context.Context, tenantID, id shared.ID) (*aitriagedom.TriageContext, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.rows[id]
	if !ok || r.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	if err := r.MarkProcessing(); err != nil {
		return nil, aitriagedom.ErrAlreadyProcessing
	}
	return &aitriagedom.TriageContext{Result: r, TenantSettings: map[string]any{}}, nil
}

type fakeEnqueuer struct{ n int }

func (f *fakeEnqueuer) EnqueueAITriage(context.Context, string, string, string, time.Duration) error {
	f.n++
	return nil
}

type fakeCampaignRepo struct {
	byID map[shared.ID]*pentestdom.Campaign
}

func (f fakeCampaignRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*pentestdom.Campaign, error) {
	c, ok := f.byID[id]
	if !ok || c.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

type fakeOrgPolicy struct{ maxTLP string }

func (f fakeOrgPolicy) MCPPolicy(context.Context, shared.ID) (tenant.MCPSettings, error) {
	return tenant.MCPSettings{MaxTLP: f.maxTLP}, nil
}

// --- harness -------------------------------------------------------------

type egressHarness struct {
	svc      *AITriageService
	llm      *fakeLLM
	triage   *fakeTriageRepo
	enqueuer *fakeEnqueuer
	tenantID shared.ID
	findings map[shared.ID]*vulnerability.Finding
	camps    map[shared.ID]*pentestdom.Campaign
}

const validTriageJSON = `{"severity_assessment":"high","severity_justification":"j","risk_score":50,
"exploitability":"medium","exploitability_details":"d","business_impact":"b","false_positive_likelihood":0.1,
"false_positive_reason":"","priority_rank":50,"remediation_steps":[],"related_cves":[],"related_cwes":[],"summary":"s"}`

func newEgressHarness(t *testing.T) *egressHarness {
	t.Helper()
	tn, err := tenant.NewTenant("Org", "org-egress", "creator")
	require.NoError(t, err)
	h := &egressHarness{
		llm:      &fakeLLM{resp: validTriageJSON},
		triage:   newFakeTriageRepo(),
		enqueuer: &fakeEnqueuer{},
		tenantID: tn.ID(),
		findings: map[shared.ID]*vulnerability.Finding{},
		camps:    map[shared.ID]*pentestdom.Campaign{},
	}
	h.svc = NewAITriageService(h.triage, fakeFindings{byID: h.findings}, fakeTenants{t: tn}, nil,
		nil, config.AITriageConfig{Enabled: true, AnthropicAPIKey: "test-only", MaxTokens: 100}, logger.NewNop())
	h.svc.llmFactory = fakeFactory{p: h.llm}
	h.svc.SetJobEnqueuer(h.enqueuer)
	h.svc.SetEgressPolicy(aipolicy.New(fakeOrgPolicy{}, fakeCampaignRepo{byID: h.camps}))
	return h
}

func (h *egressHarness) campaign(t *testing.T, tlp pentestdom.TLP, aiOff bool) *pentestdom.Campaign {
	t.Helper()
	c, err := pentestdom.NewCampaign(h.tenantID, "campaign")
	require.NoError(t, err)
	c.SetProfile(nil, "", "", tlp)
	c.SetAIAssistantsDisabled(aiOff)
	h.camps[c.ID()] = c
	return c
}

func (h *egressHarness) finding(t *testing.T, src vulnerability.FindingSource, c *pentestdom.Campaign) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(h.tenantID, shared.NewID(), src, "tool", vulnerability.SeverityHigh, "msg")
	require.NoError(t, err)
	f.SetTitle("SQL injection in the login form")
	if c != nil {
		id := c.ID()
		f.SetPentestCampaignID(&id)
	}
	h.findings[f.ID()] = f
	return f
}

// pendingRow is a triage queued before the policy would refuse it (the
// campaign's TLP changed after the request, or a workflow queued it).
func (h *egressHarness) pendingRow(t *testing.T, f *vulnerability.Finding) *aitriagedom.TriageResult {
	t.Helper()
	r, err := aitriagedom.NewTriageResult(h.tenantID, f.ID(), aitriagedom.TriageTypeManual, nil)
	require.NoError(t, err)
	require.NoError(t, h.triage.Create(context.Background(), r))
	h.triage.created = 0
	return r
}

// --- tests ---------------------------------------------------------------

// A pentest finding the organization's AI policy keeps on the platform is
// never sent to the model, on any entry path: the button and the workflow
// action (RequestTriage), bulk, auto-triage and the worker.
func TestAITriage_EgressPolicy_EveryEntryPath(t *testing.T) {
	ctx := context.Background()
	for name, setup := range map[string]func(h *egressHarness) *vulnerability.Finding{
		"campaign above the TLP limit": func(h *egressHarness) *vulnerability.Finding {
			return h.finding(t, vulnerability.FindingSourcePentest, h.campaign(t, pentestdom.TLPRed, false))
		},
		"campaign with AI turned off": func(h *egressHarness) *vulnerability.Finding {
			return h.finding(t, vulnerability.FindingSourcePentest, h.campaign(t, pentestdom.TLPClear, true))
		},
		"pentest finding without a campaign": func(h *egressHarness) *vulnerability.Finding {
			return h.finding(t, vulnerability.FindingSourcePentest, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newEgressHarness(t)
			f := setup(h)
			tid := h.tenantID.String()

			// Button and workflow action.
			_, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: tid, FindingID: f.ID().String(), TriageType: "manual"})
			require.ErrorIs(t, err, ErrPolicyRestricted)

			// Bulk.
			bulk, err := h.svc.RequestBulkTriage(ctx, BulkTriageRequest{TenantID: tid, FindingIDs: []string{f.ID().String()}})
			require.NoError(t, err)
			require.Equal(t, 1, bulk.Failed)
			require.Equal(t, FailPolicyRestricted, bulk.Jobs[0].Error)

			// Auto-triage: silently not queued.
			require.NoError(t, h.svc.EnqueueAutoTriage(ctx, h.tenantID, f.ID()))

			require.Zero(t, h.triage.created, "no triage row may be created for a restricted finding")
			require.Zero(t, h.enqueuer.n, "no job may be queued for a restricted finding")

			// Worker: a row queued earlier is failed before the call.
			row := h.pendingRow(t, f)
			err = h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row.ID(), h.tenantID, f.ID())
			require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
			require.Equal(t, aitriagedom.TriageStatusFailed, row.Status())
			require.Equal(t, FailPolicyRestricted, row.ErrorMessage())

			require.Zero(t, h.llm.calls, "the model must never be called for a restricted finding")
		})
	}
}

// Without the policy wired, pentest content is refused (fail closed); other
// findings are unaffected. A finding within the limit reaches the model.
func TestAITriage_EgressPolicy_FailsClosedAndAllows(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	h.svc.SetEgressPolicy(nil)
	pentest := h.finding(t, vulnerability.FindingSourcePentest, h.campaign(t, pentestdom.TLPClear, false))
	_, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: h.tenantID.String(), FindingID: pentest.ID().String(), TriageType: "manual"})
	require.ErrorIs(t, err, ErrPolicyRestricted)

	h = newEgressHarness(t)
	for _, f := range []*vulnerability.Finding{
		h.finding(t, vulnerability.FindingSourceSAST, nil),
		h.finding(t, vulnerability.FindingSourcePentest, h.campaign(t, pentestdom.TLPAmber, false)),
	} {
		resp, err := h.svc.RequestTriage(ctx, TriageRequest{TenantID: h.tenantID.String(), FindingID: f.ID().String(), TriageType: "manual"})
		require.NoError(t, err)
		rid := shared.MustIDFromString(resp.JobID)
		require.NoError(t, h.svc.ProcessTriage(ctx, rid, h.tenantID, f.ID()))
		require.Equal(t, aitriagedom.TriageStatusCompleted, h.triage.rows[rid].Status())
	}
	require.Equal(t, 2, h.llm.calls)
}

// A transient provider failure keeps the row pending for the queue's next
// attempt; the last attempt fails it with a code, never the raw error text.
func TestAITriage_RetryContract(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	f := h.finding(t, vulnerability.FindingSourceDAST, nil)
	h.llm.err = errors.New("dial tcp 10.0.0.7:443: llm rate limited by upstream: 429 for key sk-live-secret")
	row := h.pendingRow(t, f)

	err := h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row.ID(), h.tenantID, f.ID())
	require.ErrorIs(t, err, aitriagedom.ErrTriageRetry)
	require.NotErrorIs(t, err, aitriagedom.ErrTriageFailed)
	require.Equal(t, aitriagedom.TriageStatusPending, row.Status(), "a transient failure keeps the row for the retry")

	// The retry can acquire the row again; this time it is the last attempt.
	err = h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, false), row.ID(), h.tenantID, f.ID())
	require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
	require.Equal(t, aitriagedom.TriageStatusFailed, row.Status())
	require.Equal(t, FailRateLimited, row.ErrorMessage())
	require.NotContains(t, err.Error(), "sk-live-secret")
	require.Equal(t, 2, h.llm.calls)

	// A recovered attempt completes.
	h.llm.err = nil
	row2 := h.pendingRow(t, f)
	h.llm.err = errors.New("server error: 503")
	require.ErrorIs(t, h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row2.ID(), h.tenantID, f.ID()), aitriagedom.ErrTriageRetry)
	h.llm.err = nil
	require.NoError(t, h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row2.ID(), h.tenantID, f.ID()))
	require.Equal(t, aitriagedom.TriageStatusCompleted, row2.Status())
}

// A permanent failure is final at once, even with attempts left.
func TestAITriage_PermanentFailureNotRetried(t *testing.T) {
	ctx := context.Background()
	h := newEgressHarness(t)
	f := h.finding(t, vulnerability.FindingSourceDAST, nil)
	h.llm.resp = "not json at all"
	row := h.pendingRow(t, f)
	err := h.svc.ProcessTriage(aitriagedom.WithRetriesLeft(ctx, true), row.ID(), h.tenantID, f.ID())
	require.ErrorIs(t, err, aitriagedom.ErrTriageFailed)
	require.Equal(t, FailInvalidResponse, row.ErrorMessage())
}

func TestPublicFailureCode_HidesLegacyText(t *testing.T) {
	require.Equal(t, "", PublicFailureCode(""))
	require.Equal(t, FailRateLimited, PublicFailureCode(FailRateLimited))
	require.Equal(t, FailInternal, PublicFailureCode("failed to get finding: pq: relation \"findings\" does not exist"))
}
