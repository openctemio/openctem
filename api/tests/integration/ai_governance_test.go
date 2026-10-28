package integration

// AI governance against a real database (docs/architecture/ai-analysis.md):
//   - auto-apply never applies a risk-lowering change: a false-positive
//     verdict at confidence 0.99 becomes a pending approval requested by the AI
//     actor and the finding is unchanged; a severity raise waits for a person;
//     an additive plan is applied with no person recorded;
//   - a payload that carries its own direction is refused;
//   - evidence that does not resolve forces needs_review;
//   - undo restores, and undo after a later edit reports a conflict and
//     changes nothing;
//   - another tenant cannot read, apply, dismiss or undo by id;
//   - people overriding 20 % of the last decisions downgrades auto-apply.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type consentAll struct{}

func (consentAll) AIConsented(context.Context, shared.ID) (bool, error) { return true, nil }

type aiGovHarness struct {
	t       *testing.T
	db      *sql.DB
	svc     *aianalysis.Service
	repo    *postgres.AIAnalysisRepository
	tenant  shared.ID
	finding shared.ID
	user    shared.ID
}

func newAIGovHarness(t *testing.T) *aiGovHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		testdb.Skipf(t, "DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	log := logger.NewNop()
	findings := postgres.NewFindingRepository(pdb)
	vs := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(pdb), findings, log)
	vs.SetApprovalRepository(postgres.NewFindingApprovalRepository(pdb))
	repo := postgres.NewAIAnalysisRepository(pdb)
	h := &aiGovHarness{t: t, db: db, repo: repo,
		svc: aianalysis.New(repo, consentAll{}, findings, finding.AIActions{S: vs}, log)}
	h.tenant, h.finding = h.newTenantWithFinding("medium")
	h.user = shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'AI gov tester')`, h.user.String(), "aigov-"+h.user.String()[24:]+"@example.com")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, h.user.String()) })
	return h
}

func (h *aiGovHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Exec(q, args...); err != nil {
		h.t.Fatalf("%v\n%s", err, q)
	}
}

func (h *aiGovHarness) newTenantWithFinding(severity string) (shared.ID, shared.ID) {
	h.t.Helper()
	tenant, asset, f := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "aigov-"+tenant.String()[24:])
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, tenant.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
		asset.String(), tenant.String(), "aigov-"+tenant.String()[24:]+".example.com")
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'm', $4, $1::text, 'new')`, f.String(), tenant.String(), asset.String(), severity)
	return tenant, f
}

func (h *aiGovHarness) policy(mode aidom.Mode) {
	h.t.Helper()
	p := aidom.DefaultPolicy(h.tenant, aidom.UseCaseTriage, true)
	p.Mode = mode
	if err := h.repo.UpsertPolicy(context.Background(), p); err != nil {
		h.t.Fatal(err)
	}
}

func (h *aiGovHarness) run() *aidom.Run {
	h.t.Helper()
	now := time.Now()
	r := &aidom.Run{TenantID: h.tenant, UseCase: aidom.UseCaseTriage, Kind: "triage.v1", SubjectType: aidom.SubjectFinding,
		SubjectID: h.finding, Executor: aidom.ExecutorBuiltin, Status: aidom.RunCompleted, DataClass: aidom.DataClassInternal,
		FieldsSent: []string{"finding.title"}, Trigger: aidom.TriggerOnDemand, CompletedAt: &now}
	if err := h.repo.CreateRun(context.Background(), r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func conf(v float64) *float64 { return &v }

var titleEvidence = []aidom.Evidence{{Ref: "bundle:finding.title", Quote: "m"}}

func (h *aiGovHarness) record(run *aidom.Run, props ...aianalysis.Proposal) *aianalysis.RecordResult {
	h.t.Helper()
	res, err := h.svc.Record(context.Background(), aianalysis.RecordInput{
		Run: run, Proposals: props, KnownRefs: map[string]bool{"bundle:finding.title": true},
		SchemaVersion: "openctem.ai.triage/v1",
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func byKind(res *aianalysis.RecordResult, k aidom.Kind) *aidom.Suggestion {
	for _, s := range res.Suggestions {
		if s.Kind == k {
			return s
		}
	}
	return nil
}

func (h *aiGovHarness) findingState() (severity, status string) {
	h.t.Helper()
	if err := h.db.QueryRow(`SELECT severity, status FROM findings WHERE id = $1`, h.finding.String()).Scan(&severity, &status); err != nil {
		h.t.Fatal(err)
	}
	return
}

func (h *aiGovHarness) decide(id shared.ID, tenant shared.ID) aianalysis.DecideInput {
	return aianalysis.DecideInput{TenantID: tenant, SuggestionID: id, ActorID: h.user, Can: func(string) bool { return true }}
}

func TestAIGovernance_AutoApplyNeverLowersRisk(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeAutoApply)
	res := h.record(h.run(),
		aianalysis.Proposal{Kind: "verdict", Payload: json.RawMessage(`{"verdict":"likely_false_positive","reason":"test fixture"}`),
			Confidence: conf(0.99), Evidence: titleEvidence},
		aianalysis.Proposal{Kind: "severity", Payload: json.RawMessage(`{"severity":"critical","reason":"r"}`),
			Confidence: conf(0.99), Evidence: titleEvidence},
		aianalysis.Proposal{Kind: "remediation_steps", Payload: json.RawMessage(`{"steps":[{"step":1,"description":"upgrade"}]}`),
			Confidence: conf(0.99), Evidence: titleEvidence},
		// A payload that names its own direction is refused.
		aianalysis.Proposal{Kind: "summary", Payload: json.RawMessage(`{"text":"s","direction":"additive"}`),
			Confidence: conf(0.99), Evidence: titleEvidence},
	)
	if res.Rejected != 1 {
		t.Fatalf("rejected = %d, want 1 (payload with a direction field)", res.Rejected)
	}
	verdict := byKind(res, aidom.KindVerdict)
	if verdict == nil || verdict.State != aidom.StatePendingApproval || verdict.Direction != aidom.DirectionLowersRisk || verdict.ApprovalID == nil {
		t.Fatalf("verdict = %+v, want pending_approval with an approval", verdict)
	}
	var actor sql.NullString
	var status string
	if err := h.db.QueryRow(`SELECT requested_by_actor, status FROM finding_status_approvals WHERE tenant_id = $1 AND id = $2`,
		h.tenant.String(), verdict.ApprovalID.String()).Scan(&actor, &status); err != nil {
		t.Fatal(err)
	}
	if actor.String != "ai_triage" || status != "pending" {
		t.Fatalf("approval requested by %q status %q, want ai_triage/pending", actor.String, status)
	}
	if sev := byKind(res, aidom.KindSeverity); sev == nil || sev.State != aidom.StateOpen || sev.Direction != aidom.DirectionRaisesRisk {
		t.Fatalf("severity = %+v, want open raises_risk (a person applies severity)", sev)
	}
	plan := byKind(res, aidom.KindRemediationSteps)
	if plan == nil || plan.State != aidom.StateAutoApplied || plan.AppliedBy != nil {
		t.Fatalf("plan = %+v, want auto_applied by no person", plan)
	}
	if sev, st := h.findingState(); sev != "medium" || st != "new" {
		t.Fatalf("finding changed to %s/%s; AI must not change it", sev, st)
	}
}

func TestAIGovernance_UnresolvedEvidenceNeedsReview(t *testing.T) {
	h := newAIGovHarness(t)
	h.policy(aidom.ModeAutoApply)
	res := h.record(h.run(), aianalysis.Proposal{Kind: "summary", Payload: json.RawMessage(`{"text":"s"}`),
		Confidence: conf(0.99), Evidence: []aidom.Evidence{{Ref: "bundle:not.sent"}}})
	s := byKind(res, aidom.KindSummary)
	if s == nil || s.State != aidom.StateNeedsReview {
		t.Fatalf("summary = %+v, want needs_review", s)
	}
}

func TestAIGovernance_UndoAndConflict(t *testing.T) {
	h := newAIGovHarness(t)
	ctx := context.Background()
	h.policy(aidom.ModeSuggest)
	res := h.record(h.run(),
		aianalysis.Proposal{Kind: "severity", Payload: json.RawMessage(`{"severity":"high","reason":"r"}`), Confidence: conf(0.9), Evidence: titleEvidence},
		aianalysis.Proposal{Kind: "summary", Payload: json.RawMessage(`{"text":"s"}`), Confidence: conf(0.9), Evidence: titleEvidence},
	)
	sum := byKind(res, aidom.KindSummary)
	if sum.State != aidom.StateOpen {
		t.Fatalf("suggest mode must keep suggestions open, got %s", sum.State)
	}
	if _, err := h.svc.Apply(ctx, h.decide(sum.ID, h.tenant)); err != nil {
		t.Fatal(err)
	}
	u, err := h.svc.Undo(ctx, h.decide(sum.ID, h.tenant))
	if err != nil || u.Suggestion.State != aidom.StateUndone {
		t.Fatalf("undo = %+v %v", u, err)
	}

	sev := byKind(res, aidom.KindSeverity)
	ar, err := h.svc.Apply(ctx, h.decide(sev.ID, h.tenant))
	if err != nil || ar.Suggestion.State != aidom.StateApplied {
		t.Fatalf("apply severity = %+v %v", ar, err)
	}
	if s, _ := h.findingState(); s != "high" {
		t.Fatalf("severity = %s, want high after a person applied", s)
	}
	// A person changes the severity afterwards: undo must not overwrite it.
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, h.finding.String())
	if _, err := h.svc.Undo(ctx, h.decide(sev.ID, h.tenant)); !errors.Is(err, aidom.ErrUndoConflict) {
		t.Fatalf("undo after a later edit = %v, want ErrUndoConflict", err)
	}
	if s, _ := h.findingState(); s != "critical" {
		t.Fatalf("severity = %s after a refused undo, want critical", s)
	}
	// Without the permission of the change, nothing happens.
	in := h.decide(sev.ID, h.tenant)
	in.Can = func(string) bool { return false }
	if _, err := h.svc.Undo(ctx, in); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("undo without permission = %v, want forbidden", err)
	}
}

func TestAIGovernance_TenantIsolation(t *testing.T) {
	h := newAIGovHarness(t)
	ctx := context.Background()
	h.policy(aidom.ModeSuggest)
	run := h.run()
	res := h.record(run, aianalysis.Proposal{Kind: "summary", Payload: json.RawMessage(`{"text":"s"}`), Confidence: conf(0.9), Evidence: titleEvidence})
	sg := byKind(res, aidom.KindSummary)
	other, _ := h.newTenantWithFinding("low")

	if _, err := h.svc.Apply(ctx, h.decide(sg.ID, other)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("apply from another tenant = %v, want not found", err)
	}
	if _, err := h.svc.Dismiss(ctx, h.decide(sg.ID, other)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("dismiss from another tenant = %v, want not found", err)
	}
	if _, err := h.svc.Undo(ctx, h.decide(sg.ID, other)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("undo from another tenant = %v, want not found", err)
	}
	if _, err := h.svc.GetRun(ctx, other, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("run from another tenant = %v, want not found", err)
	}
	items, _, err := h.svc.ListForFinding(ctx, other, h.finding)
	if err != nil || len(items) != 0 {
		t.Fatalf("another tenant listed %d suggestions (%v)", len(items), err)
	}
	if _, err := h.svc.UndoRun(ctx, h.decide(run.ID, other), run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("undo run from another tenant = %v, want not found", err)
	}
	// The owner tenant still can.
	if _, err := h.svc.Dismiss(ctx, h.decide(sg.ID, h.tenant)); err != nil {
		t.Fatal(err)
	}
}

func TestAIGovernance_OverridesDowngradeAutoApply(t *testing.T) {
	h := newAIGovHarness(t)
	ctx := context.Background()
	h.policy(aidom.ModeAutoApply)
	var applied []*aidom.Suggestion
	for i := 0; i < 10; i++ {
		res := h.record(h.run(), aianalysis.Proposal{Kind: "summary", Payload: json.RawMessage(`{"text":"s"}`),
			Confidence: conf(0.95), Evidence: titleEvidence})
		s := byKind(res, aidom.KindSummary)
		if s.State != aidom.StateAutoApplied {
			t.Fatalf("summary %d state %s, want auto_applied", i, s.State)
		}
		applied = append(applied, s)
	}
	if _, err := h.svc.Undo(ctx, h.decide(applied[0].ID, h.tenant)); err != nil {
		t.Fatal(err)
	}
	if p, _ := h.svc.Policy(ctx, h.tenant, aidom.UseCaseTriage); p.Mode != aidom.ModeAutoApply {
		t.Fatal("one override in ten must not downgrade")
	}
	if _, err := h.svc.Undo(ctx, h.decide(applied[1].ID, h.tenant)); err != nil {
		t.Fatal(err)
	}
	p, err := h.svc.Policy(ctx, h.tenant, aidom.UseCaseTriage)
	if err != nil || p.Mode != aidom.ModeSuggest || p.DowngradedAt == nil || p.DowngradeReason != aidom.DowngradeReasonOverrideRate {
		t.Fatalf("policy = %+v %v, want downgraded to suggest at 2 of 10 overrides", p, err)
	}
}
