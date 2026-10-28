package routes

// The built-in executor acting as an AI agent, on a real database
// (docs/architecture/ai-analysis.md): the model's output becomes the
// AI agent's own finding commands, bounded by its preset, its owners and its
// scope; risk-lowering changes become requests a person decides; every row
// carries the AI provenance; the model sees masked values only.

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aimaskmap"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/aimask"
	"github.com/openctemio/openctem/api/pkg/crypto"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type aiExecSettings struct{ tenant.AISettingsRepository }

func (aiExecSettings) Get(_ context.Context, _ shared.ID, d tenant.AISettings) (tenant.AISettings, error) {
	d.SetOptIn(true, "admin", time.Now())
	d.Mode = tenant.AIModePlatform
	return d, nil
}

type aiScriptedModel struct {
	mu     sync.Mutex
	prompt string
	reply  string
	// during runs while the model "thinks" (a person's concurrent edit).
	during func()
}

func (m *aiScriptedModel) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prompt = req.SystemPrompt + "\n" + req.UserPrompt
	if m.during != nil {
		m.during()
	}
	return &llm.CompletionResponse{Content: m.reply, PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}, nil
}
func (m *aiScriptedModel) Name() string    { return "scripted" }
func (m *aiScriptedModel) Model() string   { return "scripted-1" }
func (m *aiScriptedModel) Validate() error { return nil }

type aiScriptedFactory struct{ p llm.Provider }

func (f aiScriptedFactory) CreateProviderForTenant(string, tenant.AISettings) (llm.Provider, error) {
	return f.p, nil
}

type aiFixedInputs struct{ host string }

func (i aiFixedInputs) BundleInput(_ context.Context, tenantID shared.ID, f *vulnerability.Finding, ceiling aipolicy.Class, key []byte) (aibundle.Input, error) {
	return aibundle.Input{TenantID: tenantID, Finding: f, Ceiling: ceiling, Policy: aimask.FullPolicy(), RunKey: key,
		Asset: &aibundle.Asset{Name: i.host, Type: "host", Identifiers: []string{i.host}}}, nil
}

const aiExecHost = "db01.payroll.example.com"

type aiExecHarness struct {
	*findingApprovalHarness
	org      string
	owner    policyUser
	agents   *aianalysis.Service
	executor *aianalysis.BuiltinExecutor
	model    *aiScriptedModel
}

func newAIExecHarness(t *testing.T) *aiExecHarness {
	out := &aiExecHarness{model: &aiScriptedModel{}}
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		svc.SetApprovalNotifier(actors, nil, nil, "")
		vh.SetFindingApprovalSettings(ts)
		svc.SetAIAgentChecker(postgres.NewAIAnalysisRepository(db))
		svc.SetSeverityRequestRepository(postgres.NewSeverityRequestRepository(db))
		svc.SetCommentRepository(postgres.NewFindingCommentRepository(db))
		svc.SetActivityService(activity.NewFindingActivityService(postgres.NewFindingActivityRepository(db), postgres.NewFindingRepository(db), log))
	})
	out.findingApprovalHarness = h
	db := &postgres.DB{DB: h.db}
	tenants := postgres.NewTenantRepository(db)
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil, logger.NewNop())
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenants.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})
	repo := postgres.NewAIAnalysisRepository(db)
	out.agents = aianalysis.New(repo, repo, apikey.NewHolderPermissions(tenants, aiRolePerms{postgres.NewRoleRepository(db)}),
		enforcer, nil, nil, logger.NewNop())

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	maps := aimaskmap.NewStore(postgres.NewAIMaskMapRepository(db), cipher, time.Hour)
	out.executor = aianalysis.NewBuiltinExecutor(postgres.NewFindingRepository(db), finding.AIAgentCommands{Findings: h.svc},
		aiExecSettings{}, aiScriptedFactory{p: out.model}, aiFixedInputs{host: aiExecHost},
		aibundle.NewBuilder(aipolicy.New(nil, nil)), maps, aianalysis.ExecutorConfig{MaxTokens: 500}, logger.NewNop())
	out.executor.SetAgents(out.agents)

	out.org = h.tenantWithFindings()
	out.owner = h.member(out.org, "owner")
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM ai_runs WHERE tenant_id = $1`, out.org)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM finding_comments WHERE tenant_id = $1`, out.org)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM finding_severity_requests WHERE tenant_id = $1`, out.org)
	})
	return out
}

func (h *aiExecHarness) agent(preset string) *aidom.Agent {
	h.t.Helper()
	a, err := h.agents.Create(context.Background(), aianalysis.CreateInput{
		Name: "AI " + preset + " " + uuid.NewString()[:6], Preset: preset,
		Owners: []aianalysis.OwnerInput{{Kind: "user", ID: h.owner.id}},
	}, auditapp.AuditContext{TenantID: h.org, ActorID: h.owner.id})
	if err != nil {
		h.t.Fatalf("create agent: %v", err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, a.ID.String())
	})
	return a
}

// findingFor is a new finding of severity assigned to the AI agent (its scope).
func (h *aiExecHarness) findingFor(a *aidom.Agent, severity string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status, title, description, assigned_to)
		VALUES ($1::uuid, $2, 'sast', 'ai-exec', 'm', $3, $1::text, 'new', $4, $5, $6)`, id, h.org, severity,
		"Outdated TLS on "+aiExecHost, "The service at "+aiExecHost+" accepts TLS 1.0.", a.ID.String())
	return id
}

// analyze runs the AI agent on a schedule (no person started it), so its
// risk-lowering items become requests a person decides.
func (h *aiExecHarness) analyze(a *aidom.Agent, findingID, kind string) (*aianalysis.RunDetail, error) {
	tid, _ := shared.IDFromString(h.org)
	fid, _ := shared.IDFromString(findingID)
	return h.executor.Analyze(context.Background(), aianalysis.AnalyzeRequest{
		TenantID: tid, FindingID: fid, Kind: kind, AgentID: &a.ID, Trigger: aidom.TriggerSchedule,
	})
}

// analyzeOnDemand runs the AI agent because the owner asked for it.
func (h *aiExecHarness) analyzeOnDemand(a *aidom.Agent, findingID, kind string) (*aianalysis.RunDetail, error) {
	tid, _ := shared.IDFromString(h.org)
	fid, _ := shared.IDFromString(findingID)
	owner, _ := shared.IDFromString(h.owner.id)
	return h.executor.Analyze(context.Background(), aianalysis.AnalyzeRequest{
		TenantID: tid, FindingID: fid, Kind: kind, AgentID: &a.ID, TriggeredBy: &owner,
	})
}

func outcomes(d *aianalysis.RunDetail) map[string]aianalysis.ActionOutcome {
	out := map[string]aianalysis.ActionOutcome{}
	for _, a := range d.Actions {
		out[a.Kind] = a.Outcome
	}
	return out
}

func TestAIExecutor_SuggestAgentCommentsAndRequests_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.agent("suggest")
	f := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[
 {"kind":"summary","payload":{"text":"Upgrade TLS first."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]},
 {"kind":"verdict","payload":{"verdict":"likely_false_positive","reason":"Test fixture only."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]},
 {"kind":"severity","payload":{"severity":"high","reason":"Internet facing."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	got := outcomes(d)
	if got["summary"] != aianalysis.ActionCommented || got["verdict"] != aianalysis.ActionRequested || got["severity"] != aianalysis.ActionCommented {
		t.Fatalf("suggest agent outcomes: %v %+v (severity must stay a comment without findings:severity)", got, d.Actions)
	}
	if strings.Contains(h.model.prompt, aiExecHost) {
		t.Fatal("the model saw the real host name")
	}
	// The false-positive request is the AI agent's, pending for a person.
	var status, requester string
	if err := h.db.QueryRow(`SELECT status, requested_by FROM finding_status_approvals WHERE finding_id = $1`, f).Scan(&status, &requester); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || requester != a.ID.String() {
		t.Fatalf("FP request status=%s requester=%s, want pending by the agent", status, requester)
	}
	var sev string
	if err := h.db.QueryRow(`SELECT severity FROM findings WHERE id = $1`, f).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "medium" {
		t.Fatalf("a suggest agent changed the severity to %s", sev)
	}
	// Every row the AI agent wrote is labeled AI and carries the run.
	var n, withRun int
	if err := h.db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE source_metadata->'ai'->>'run_id' = $2)
		FROM finding_activities WHERE finding_id = $1 AND actor_id = $3 AND actor_type = 'ai'`,
		f, d.Run.ID.String(), a.ID.String()).Scan(&n, &withRun); err != nil {
		t.Fatal(err)
	}
	if n == 0 || withRun == 0 {
		t.Fatalf("agent timeline rows: %d labeled, %d with the run", n, withRun)
	}
	if d.Run.Status != aidom.RunCompleted || d.Run.Actions != 3 || len(d.Run.Accountable) != 1 {
		t.Fatalf("run status=%s actions=%d accountable=%v", d.Run.Status, d.Run.Actions, d.Run.Accountable)
	}
}

func TestAIExecutor_TriageAgentActsWithinItsPreset_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.agent("triage")
	f := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"true_positive","reason":"Reproduced."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]},
 {"kind":"severity","payload":{"severity":"high","reason":"Internet facing."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d); got["verdict"] != aianalysis.ActionApplied || got["severity"] != aianalysis.ActionApplied {
		t.Fatalf("triage agent outcomes: %v", got)
	}
	var status, sev string
	if err := h.db.QueryRow(`SELECT status, severity FROM findings WHERE id = $1`, f).Scan(&status, &sev); err != nil {
		t.Fatal(err)
	}
	if status != "confirmed" || sev != "high" {
		t.Fatalf("finding status=%s severity=%s, want confirmed/high", status, sev)
	}

	// Lowering severity is always a request, even for a triage AI agent.
	f2 := h.findingFor(a, "high")
	h.model.reply = `{"suggestions":[
 {"kind":"severity","payload":{"severity":"low","reason":"Internal only."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err = h.analyze(a, f2, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d); got["severity"] != aianalysis.ActionRequested {
		t.Fatalf("severity downgrade outcome: %v, want requested", got)
	}
	if err := h.db.QueryRow(`SELECT severity FROM findings WHERE id = $1`, f2).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "high" {
		t.Fatalf("a triage agent lowered severity to %s without a person", sev)
	}
}

func TestAIExecutor_UnsafeOutputOnlyComments_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.agent("triage")
	f := h.findingFor(a, "medium")
	// No evidence, a forged placeholder and low confidence: nothing changes.
	h.model.reply = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"true_positive","reason":"Seen on HOST_ZZZZZZ9."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]},
 {"kind":"severity","payload":{"severity":"critical","reason":"Trust me."},"confidence":0.3,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, act := range d.Actions {
		if act.Outcome == aianalysis.ActionApplied || act.Outcome == aianalysis.ActionRequested {
			t.Fatalf("unsafe output acted: %+v", act)
		}
	}
	var status, sev string
	if err := h.db.QueryRow(`SELECT status, severity FROM findings WHERE id = $1`, f).Scan(&status, &sev); err != nil {
		t.Fatal(err)
	}
	if status != "new" || sev != "medium" {
		t.Fatalf("finding changed to %s/%s", status, sev)
	}
}

func TestAIExecutor_RefusesBeforeAnyRun_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.agent("triage")
	h.model.reply = `{"suggestions":[]}`
	runs := func() int {
		var n int
		if err := h.db.QueryRow(`SELECT count(*) FROM ai_runs WHERE tenant_id = $1`, h.org).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// A finding outside the AI agent's scope is not found and records nothing.
	outside := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'ai-exec', 'm', 'low', $1::text, 'new')`, outside, h.org)
	if _, err := h.analyze(a, outside, "triage.v1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("finding outside the agent's scope: %v", err)
	}
	// Another organization's finding.
	other := h.tenantWithFindings()
	foreign := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'ai-exec', 'm', 'low', $1::text, 'new')`, foreign, other)
	if _, err := h.analyze(a, foreign, "triage.v1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another organization's finding: %v", err)
	}
	// The only owner leaves: the AI agent pauses before anything runs.
	f := h.findingFor(a, "low")
	h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, h.owner.id, h.org)
	var pe *aidom.PausedError
	if _, err := h.analyze(a, f, "triage.v1"); !errors.As(err, &pe) || pe.Reason != aidom.PauseNoActiveOwner {
		t.Fatalf("analysis with no active owner: %v", err)
	}
	if n := runs(); n != 0 {
		t.Fatalf("%d runs recorded for refused requests", n)
	}
}

// A person changes the finding while the model thinks: the AI agent never
// overwrites that decision; its change becomes a comment.
func TestAIExecutor_NeverOverwritesAConcurrentChange_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.agent("triage")
	f := h.findingFor(a, "medium")
	h.model.during = func() { h.exec(`UPDATE findings SET severity = 'low' WHERE id = $1`, f) }
	h.model.reply = `{"suggestions":[
 {"kind":"severity","payload":{"severity":"critical","reason":"Internet facing."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Actions) != 1 || d.Actions[0].Outcome != aianalysis.ActionCommented || d.Actions[0].Reason != "finding_changed" {
		t.Fatalf("actions after a concurrent change: %+v", d.Actions)
	}
	var sev string
	if err := h.db.QueryRow(`SELECT severity FROM findings WHERE id = $1`, f).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "low" {
		t.Fatalf("the agent overwrote a person's change: severity %s", sev)
	}
}

// A person who starts a run could approve the risk-lowering request it files
// as the "second person" (RFC-132 D7). On demand, the AI agent therefore
// leaves a false positive or a severity downgrade as a comment; raising
// severity still goes through.
func TestAIExecutor_OnDemandRunFilesNoRiskLoweringRequest_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.agent("triage")
	f := h.findingFor(a, "high")
	h.model.reply = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"likely_false_positive","reason":"Test fixture only."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]},
 {"kind":"severity","payload":{"severity":"low","reason":"Internal only."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err := h.analyzeOnDemand(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d); got["verdict"] != aianalysis.ActionCommented || got["severity"] != aianalysis.ActionCommented {
		t.Fatalf("on-demand risk-lowering outcomes: %v, want comments only", got)
	}
	var fp, sevReq int
	if err := h.db.QueryRow(`SELECT count(*) FROM finding_status_approvals WHERE finding_id = $1`, f).Scan(&fp); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT count(*) FROM finding_severity_requests WHERE finding_id = $1`, f).Scan(&sevReq); err != nil {
		t.Fatal(err)
	}
	if fp != 0 || sevReq != 0 {
		t.Fatalf("an on-demand run filed %d false-positive and %d severity requests, want none", fp, sevReq)
	}

	// Raising severity lowers no risk: it still applies on demand.
	f2 := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[
 {"kind":"severity","payload":{"severity":"high","reason":"Internet facing."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	d, err = h.analyzeOnDemand(a, f2, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d); got["severity"] != aianalysis.ActionApplied {
		t.Fatalf("on-demand severity raise outcome: %v, want applied", got)
	}
}
