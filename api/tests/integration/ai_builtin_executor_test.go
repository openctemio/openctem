package integration

// The built-in executor against a real database (docs/architecture/ai-analysis.md):
//   - the model receives the masked bundle: no real host name, no secret;
//   - the model's placeholders are mapped back by the platform through the
//     stored mapping; a placeholder the run did not issue stays as text and
//     forces needs_review; secrets are never resolved;
//   - output outside the kind's schema fails the run and stores nothing;
//   - a pentest finding without a campaign is refused by the egress policy
//     before anything is sent;
//   - another tenant's finding id is not found and records no run;
//   - provenance (template id and digest, output schema, bundle digest,
//     fields sent, provider, model, tokens) is on the run.

import (
	"context"
	"crypto/rand"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aimaskmap"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/aimask"
	"github.com/openctemio/openctem/api/pkg/crypto"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type execSettings struct{ tenant.AISettingsRepository }

func (execSettings) Get(_ context.Context, _ shared.ID, d tenant.AISettings) (tenant.AISettings, error) {
	d.SetOptIn(true, "admin", time.Now())
	d.Mode = tenant.AIModePlatform
	return d, nil
}

type scriptedModel struct {
	mu      sync.Mutex
	prompt  string
	respond func(prompt string) string
}

func (m *scriptedModel) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prompt = req.SystemPrompt + "\n" + req.UserPrompt
	return &llm.CompletionResponse{Content: m.respond(req.UserPrompt), PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120}, nil
}
func (m *scriptedModel) Name() string    { return "scripted" }
func (m *scriptedModel) Model() string   { return "scripted-1" }
func (m *scriptedModel) Validate() error { return nil }

type scriptedFactory struct{ p llm.Provider }

func (f scriptedFactory) CreateProviderForTenant(string, tenant.AISettings) (llm.Provider, error) {
	return f.p, nil
}

// fixedInputs seeds the asset's host name the way the masking service does.
type fixedInputs struct{ host string }

func (i fixedInputs) BundleInput(_ context.Context, tenantID shared.ID, f *vulnerability.Finding, ceiling aipolicy.Class, key []byte) (aibundle.Input, error) {
	return aibundle.Input{TenantID: tenantID, Finding: f, Ceiling: ceiling, Policy: aimask.FullPolicy(), RunKey: key,
		Asset: &aibundle.Asset{Name: i.host, Type: "host", Identifiers: []string{i.host}}}, nil
}

var placeholderRE = regexp.MustCompile(`\b(?:HOST|DOMAIN)_[A-Z0-9]{6,}\b`)

const execHost = "db01.payroll.example.com"

func newExecutor(t *testing.T, h *aiGovHarness, model *scriptedModel) *aianalysis.BuiltinExecutor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	pdb := &postgres.DB{DB: h.db}
	maps := aimaskmap.NewStore(postgres.NewAIMaskMapRepository(pdb), cipher, time.Hour)
	return aianalysis.NewBuiltinExecutor(h.svc, execSettings{}, scriptedFactory{p: model}, fixedInputs{host: execHost},
		aibundle.NewBuilder(aipolicy.New(nil, nil)), maps, aianalysis.ExecutorConfig{MaxTokens: 500}, logger.NewNop())
}

func (h *aiGovHarness) describeFinding() {
	h.exec(`UPDATE findings SET title = $2, description = $3 WHERE id = $1`, h.finding.String(),
		"Outdated TLS on "+execHost,
		"The service at "+execHost+" accepts TLS 1.0. Config contains aws_secret_access_key = AKIAIOSFODNN7EXAMPLE.")
}

func TestAIBuiltinExecutor_MasksAndMapsBack(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeSuggest)
	h.describeFinding()
	model := &scriptedModel{respond: func(prompt string) string {
		host := ""
		for _, m := range placeholderRE.FindAllString(prompt, -1) {
			if !strings.HasSuffix(m, "_X2ABCD") { // the bundle header's examples
				host = m
				break
			}
		}
		return `{"suggestions":[
 {"kind":"summary","payload":{"text":"Upgrade TLS on ` + host + ` first."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title","quote":"` + host + `"}]},
 {"kind":"verdict","payload":{"verdict":"true_positive","reason":"Also seen on HOST_ZZZZZZ9."},"confidence":0.8,"evidence":[{"ref":"bundle:finding.title"}]}
]}`
	}}
	exec := newExecutor(t, h, model)
	d, err := exec.Analyze(context.Background(), aianalysis.AnalyzeRequest{TenantID: h.tenant, FindingID: h.finding, Kind: "triage.v1", RequestedBy: &h.user})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if strings.Contains(model.prompt, execHost) || strings.Contains(model.prompt, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("the model saw a real host name or a secret")
	}
	if !placeholderRE.MatchString(model.prompt) {
		t.Fatal("the host should reach the model as a placeholder")
	}
	r := d.Run
	if r.Status != aidom.RunCompleted || r.PromptTemplateID != "triage.v1" || !strings.HasPrefix(r.PromptTemplateDigest, "sha256:") ||
		r.OutputSchema != "openctem.ai.triage/v1" || !strings.HasPrefix(r.BundleDigest, "sha256:") || len(r.FieldsSent) == 0 ||
		r.Provider != "scripted" || r.Model != "scripted-1" || r.TokensIn != 100 {
		t.Fatalf("run provenance incomplete: %+v", r)
	}
	var summary, verdict *aidom.Suggestion
	for _, s := range d.Suggestions {
		switch s.Kind {
		case aidom.KindSummary:
			summary = s
		case aidom.KindVerdict:
			verdict = s
		}
	}
	// Subdomain labels stay (structure kept); the registrable domain is the
	// placeholder the model echoed, mapped back by the platform.
	if summary == nil || !strings.Contains(string(summary.Payload), "example.com") || strings.Contains(string(summary.Payload), "DOMAIN_") || summary.State != aidom.StateOpen {
		t.Fatalf("summary not mapped back to the real value: %+v", summary)
	}
	if verdict == nil || verdict.State != aidom.StateNeedsReview || !strings.Contains(string(verdict.Payload), "HOST_ZZZZZZ9") {
		t.Fatalf("a forged placeholder must stay as text and force review: %+v", verdict)
	}
	found := false
	for _, rr := range verdict.ReviewReasons {
		found = found || rr == aidom.ReviewUnknownPlaceholder
	}
	if !found {
		t.Fatalf("review reasons %v, want unknown_placeholder", verdict.ReviewReasons)
	}
}

func TestAIBuiltinExecutor_InvalidOutputStoresNothing(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeAutoApply)
	h.describeFinding()
	exec := newExecutor(t, h, &scriptedModel{respond: func(string) string {
		return `Sure, here you go: {"suggestions":[]}`
	}})
	d, err := exec.Analyze(context.Background(), aianalysis.AnalyzeRequest{TenantID: h.tenant, FindingID: h.finding, Kind: "summary.v1"})
	if !errors.Is(err, aianalysis.ErrRunRefused) || d == nil || d.Run.Status != aidom.RunFailed || d.Run.ErrorCode != aianalysis.RunErrInvalidOutput {
		t.Fatalf("got %+v %v, want failed invalid_output", d, err)
	}
	if len(d.Suggestions) != 0 {
		t.Fatal("nothing may be stored from invalid output")
	}
}

func TestAIBuiltinExecutor_EgressRefusesPentestWithoutCampaign(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeSuggest)
	h.exec(`UPDATE findings SET source = 'pentest' WHERE id = $1`, h.finding.String())
	model := &scriptedModel{respond: func(string) string { return `{"suggestions":[]}` }}
	d, err := newExecutor(t, h, model).Analyze(context.Background(), aianalysis.AnalyzeRequest{TenantID: h.tenant, FindingID: h.finding, Kind: "summary.v1"})
	if !errors.Is(err, aianalysis.ErrRunRefused) || d.Run.Status != aidom.RunRefused || d.Run.ErrorCode != aianalysis.RunErrPolicyRestricted {
		t.Fatalf("got %+v %v, want refused policy_restricted", d, err)
	}
	if model.prompt != "" {
		t.Fatal("nothing may be sent for a refused finding")
	}
}

func TestAIBuiltinExecutor_OtherTenantAndOffUseCase(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeSuggest)
	other, _ := h.newTenantWithFinding("low")
	model := &scriptedModel{respond: func(string) string { return `{"suggestions":[]}` }}
	exec := newExecutor(t, h, model)
	if _, err := exec.Analyze(context.Background(), aianalysis.AnalyzeRequest{TenantID: other, FindingID: h.finding, Kind: "summary.v1"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant's finding = %v, want not found", err)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM ai_runs WHERE tenant_id = $1`, other.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("runs recorded for the other tenant: %d %v", n, err)
	}
	p := aidom.DefaultPolicy(h.tenant, aidom.UseCaseRemediation, true)
	p.Mode = aidom.ModeOff
	if err := h.repo.UpsertPolicy(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Analyze(context.Background(), aianalysis.AnalyzeRequest{TenantID: h.tenant, FindingID: h.finding, Kind: "remediation.v1"}); !errors.Is(err, aianalysis.ErrUseCaseOff) {
		t.Fatalf("off use case = %v, want ErrUseCaseOff", err)
	}
	if model.prompt != "" {
		t.Fatal("nothing may be sent")
	}
}

// A completed legacy AI triage result is also written as a run (same id) with
// suggestions; they carry no evidence, so they wait for a person even in
// auto-apply; a second call does nothing.
func TestAILegacyTriageRecordedOnce(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeAutoApply)
	ctx := context.Background()
	res, err := aitriagedom.NewTriageResult(h.tenant, h.finding, aitriagedom.TriageTypeManual, &h.user)
	if err != nil {
		t.Fatal(err)
	}
	a := aitriagedom.TriageAnalysis{Provider: "claude", Model: "m", PromptTokens: 5, CompletionTokens: 3,
		SeverityAssessment: "high", FalsePositiveLikelihood: 0.95, FalsePositiveReason: "fixture", Summary: "s",
		RemediationSteps: []aitriagedom.RemediationStep{{Step: 1, Description: "patch", Effort: "low"}}}
	_ = res.MarkProcessing()
	if err := res.MarkCompleted(a); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := h.svc.RecordTriageRun(ctx, res, &a, "sha256:"+strings.Repeat("c", 64)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := h.svc.GetRun(ctx, h.tenant, res.ID())
	if err != nil {
		t.Fatal(err)
	}
	if d.Run.Kind != "triage.legacy" || d.Run.Provider != "claude" || len(d.Suggestions) != 4 {
		t.Fatalf("run %+v with %d suggestions, want triage.legacy with 4", d.Run, len(d.Suggestions))
	}
	for _, s := range d.Suggestions {
		if s.State != aidom.StateNeedsReview {
			t.Fatalf("%s state %s, want needs_review (no evidence)", s.Kind, s.State)
		}
	}
	if sev, st := h.findingState(); sev != "medium" || st != "new" {
		t.Fatalf("finding changed to %s/%s", sev, st)
	}
}
