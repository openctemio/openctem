package routes

// The organization's AI use case settings applied by the built-in executor
// (docs/architecture/ai-use-cases.md), on a real database: off refuses the
// run before any model call; suggest (the default) changes nothing and files
// nothing; auto-apply under the minimum confidence stays a suggestion; the
// data class ceiling withholds fields; one organization's settings never
// reach another's runs.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const aiUseCaseVerdictAndSeverity = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"true_positive","reason":"Reproduced."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]},
 {"kind":"severity","payload":{"severity":"low","reason":"Internal only."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`

func (h *aiExecHarness) findingRow(id string) (status, severity string, requests int) {
	h.t.Helper()
	if err := h.db.QueryRow(`SELECT status, severity FROM findings WHERE id = $1`, id).Scan(&status, &severity); err != nil {
		h.t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT (SELECT count(*) FROM finding_status_approvals WHERE finding_id = $1)
		+ (SELECT count(*) FROM finding_severity_requests WHERE finding_id = $1)`, id).Scan(&requests); err != nil {
		h.t.Fatal(err)
	}
	return status, severity, requests
}

func TestAIUseCase_OffRefusesBeforeTheModel_DB(t *testing.T) {
	h := newAIExecHarness(t)
	h.setUseCase(h.org, aidom.UseCaseTriage, aidom.UseCaseOff, aidom.DataClassInternal, 0.85)
	a := h.aiAgent("triage")
	f := h.findingFor(a, "high")
	h.model.reply = aiUseCaseVerdictAndSeverity
	d, err := h.analyze(a, f, "triage.v1")
	if !errors.Is(err, aianalysis.ErrRunRefused) || d == nil || d.Run.ErrorCode != aianalysis.RunErrUseCaseOff || d.Run.Status != aidom.RunRefused {
		t.Fatalf("run with the use case off: err=%v detail=%+v", err, d)
	}
	if h.model.prompt != "" {
		t.Fatal("the model was called for a use case that is off")
	}
	// Another use case of the same organization still runs.
	h.model.reply = `{"suggestions":[{"kind":"summary","payload":{"text":"Upgrade TLS."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}]}`
	if _, err := h.analyze(a, f, "summary.v1"); err != nil {
		t.Fatalf("summary with triage off: %v", err)
	}
}

// Suggest is the default: even a triage AI agent with every permission only
// comments; no status, no severity, no request.
func TestAIUseCase_SuggestChangesNothing_DB(t *testing.T) {
	h := newAIExecHarness(t)
	a := h.aiAgent("triage")
	f := h.findingFor(a, "high")
	h.model.reply = aiUseCaseVerdictAndSeverity
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, act := range d.Actions {
		if act.Outcome != aianalysis.ActionCommented || act.Reason != "suggest_mode" {
			t.Fatalf("suggest mode acted: %+v", d.Actions)
		}
	}
	if status, sev, req := h.findingRow(f); status != "new" || sev != "high" || req != 0 {
		t.Fatalf("suggest mode changed the finding: %s/%s requests=%d", status, sev, req)
	}
}

// Auto-apply under the minimum confidence stays a suggestion; at or above
// it, the confirming verdict applies and the downgrade becomes a request.
func TestAIUseCase_AutoApplyHonoursMinConfidence_DB(t *testing.T) {
	h := newAIExecHarness(t)
	h.setUseCase(h.org, aidom.UseCaseTriage, aidom.UseCaseAutoApply, aidom.DataClassInternal, 0.95)
	a := h.aiAgent("triage")
	f := h.findingFor(a, "high")
	h.model.reply = aiUseCaseVerdictAndSeverity // confidence 0.9
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, act := range d.Actions {
		if act.Outcome != aianalysis.ActionCommented || act.Reason != "below_min_confidence" {
			t.Fatalf("under the minimum confidence: %+v", d.Actions)
		}
	}
	if status, sev, req := h.findingRow(f); status != "new" || sev != "high" || req != 0 {
		t.Fatalf("finding changed under the minimum: %s/%s requests=%d", status, sev, req)
	}

	h.setUseCase(h.org, aidom.UseCaseTriage, aidom.UseCaseAutoApply, aidom.DataClassInternal, 0.9)
	f2 := h.findingFor(a, "high")
	d, err = h.analyze(a, f2, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d); got["verdict"] != aianalysis.ActionApplied || got["severity"] != aianalysis.ActionRequested {
		t.Fatalf("at the minimum: %+v", d.Actions)
	}
	if status, sev, req := h.findingRow(f2); status != "confirmed" || sev != "high" || req != 1 {
		t.Fatalf("at the minimum: %s/%s requests=%d, want confirmed/high with one severity request", status, sev, req)
	}

	// A person rejects the AI agent's severity request: one decision, one
	// override toward the automatic downgrade; nothing for another
	// organization.
	h.exec(`UPDATE finding_severity_requests SET status = 'rejected', decided_at = now() WHERE finding_id = $1`, f2)
	tid, _ := shared.IDFromString(h.org)
	st, err := h.useCases.OverrideStats(context.Background(), tid, aidom.UseCaseTriage, time.Now().Add(-time.Hour), aidom.DowngradeWindow)
	if err != nil || st.Decisions != 1 || st.Overrides != 1 {
		t.Fatalf("override stats: %+v %v", st, err)
	}
	other, _ := shared.IDFromString(h.tenantWithFindings())
	if st, _ := h.useCases.OverrideStats(context.Background(), other, aidom.UseCaseTriage, time.Now().Add(-time.Hour), aidom.DowngradeWindow); st.Decisions != 0 {
		t.Fatalf("another organization's stats: %+v", st)
	}
}

// The use case's ceiling is applied on top of the AI agent's: under public,
// the finding's title and description are withheld and recorded as such.
func TestAIUseCase_CeilingWithholdsFields_DB(t *testing.T) {
	h := newAIExecHarness(t)
	h.setUseCase(h.org, aidom.UseCaseSummary, aidom.UseCaseSuggest, aidom.DataClassPublic, 0.85)
	a := h.aiAgent("suggest")
	f := h.findingFor(a, "high")
	h.exec(`UPDATE findings SET cve_id = 'CVE-2024-0001' WHERE id = $1`, f)
	h.model.reply = `{"suggestions":[{"kind":"summary","payload":{"text":"Patch it."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.cve"}]}]}`
	d, err := h.analyze(a, f, "summary.v1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Run.DataClass != aidom.DataClassPublic {
		t.Fatalf("run data class %s, want public", d.Run.DataClass)
	}
	if strings.Contains(h.model.prompt, "Outdated TLS") || strings.Contains(h.model.prompt, "accepts TLS 1.0") {
		t.Fatal("an internal field reached the model under a public ceiling")
	}
	withheld := strings.Join(d.Run.FieldsWithheld, ",")
	if !strings.Contains(withheld, "finding.title") || !strings.Contains(withheld, "finding.description") {
		t.Fatalf("fields withheld: %v", d.Run.FieldsWithheld)
	}
}

// One organization turning auto-apply on changes nothing for another.
func TestAIUseCase_TenantIsolation_DB(t *testing.T) {
	h := newAIExecHarness(t)
	other := h.tenantWithFindings()
	h.setUseCase(other, aidom.UseCaseTriage, aidom.UseCaseAutoApply, aidom.DataClassRestricted, 0.5)
	a := h.aiAgent("triage")
	f := h.findingFor(a, "high")
	h.model.reply = aiUseCaseVerdictAndSeverity
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if status, _, req := h.findingRow(f); status != "new" || req != 0 {
		t.Fatalf("another organization's auto-apply acted here: %s requests=%d %+v", status, req, d.Actions)
	}
	if d.Run.DataClass == aidom.DataClassRestricted {
		t.Fatal("another organization's ceiling applied here")
	}
}
