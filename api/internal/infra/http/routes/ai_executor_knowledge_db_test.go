package routes

// Knowledge in a triage run on a real database (docs/architecture/ai-knowledge.md):
// the run retrieves the organization's approved knowledge as its AI agent,
// the model sees it masked and fenced as kb:<n>, the run records what it saw
// and cited, another organization's knowledge never appears, and knowledge
// alone never changes a finding.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	"github.com/openctemio/openctem/api/internal/app/aiknowledge"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	kdom "github.com/openctemio/openctem/api/pkg/domain/aiknowledge"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func seedKnowledge(t *testing.T, svc *aiknowledge.Service, tenant, author, approver shared.ID, name, title, text string) {
	t.Helper()
	ctx := context.Background()
	src, err := svc.CreateSource(ctx, aiknowledge.Actor{TenantID: tenant, UserID: author},
		aiknowledge.CreateSourceInput{Name: name, Visibility: kdom.VisibilityOrganization, Class: kdom.ClassInternal}, auditapp.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddDocument(ctx, aiknowledge.Actor{TenantID: tenant, UserID: author}, src.ID,
		aiknowledge.AddDocumentInput{Title: title, Text: text}, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, aiknowledge.Actor{TenantID: tenant, UserID: approver, Owner: true}, src.ID, false, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
}

func TestAIExecutor_KnowledgeCitedNeverDecides_DB(t *testing.T) {
	h := newAIExecHarness(t)
	db := &postgres.DB{DB: h.db}
	svc := aiknowledge.New(postgres.NewAIKnowledgeRepository(db), nil, nil, logger.NewNop())
	h.executor.SetKnowledge(svc)

	org, _ := shared.IDFromString(h.org)
	owner, _ := shared.IDFromString(h.owner.id)
	seedKnowledge(t, svc, org, owner, owner, "Runbooks "+uuid.NewString()[:6], "TLS policy",
		"# Legacy TLS\n\nOutdated TLS on "+aiExecHost+" is a lab fixture kept for client testing.")
	// Another organization's knowledge with the same words.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'other', $2)`, other.String(), "kb-other-"+other.String()[:8])
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	seedKnowledge(t, svc, other, owner, owner, "Other", "Other TLS", "Outdated TLS everywhere is FOREIGN-ORG-SECRET-NOTE accepted.")

	a := h.aiAgent("suggest")

	// Knowledge as the only evidence for a false positive: a comment, never a request.
	f := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"likely_false_positive","reason":"The runbook calls it a lab fixture."},"confidence":0.95,"evidence":[{"ref":"kb:1","quote":"lab fixture"}]}
]}`
	d, err := h.analyze(a, f, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d); got["verdict"] != aianalysis.ActionCommented {
		t.Fatalf("knowledge-only verdict outcome: %v %+v", got, d.Actions)
	}
	if d.Actions[0].Reason != aianalysis.ReviewKnowledgeOnly {
		t.Fatalf("reason = %q", d.Actions[0].Reason)
	}
	var pending int
	_ = h.db.QueryRow(`SELECT count(*) FROM finding_status_approvals WHERE finding_id = $1`, f).Scan(&pending)
	if pending != 0 {
		t.Fatal("knowledge alone filed a false-positive request")
	}
	// The model saw the excerpt, masked and labeled; never the other organization's.
	if !strings.Contains(h.model.prompt, "kb:1") || !strings.Contains(h.model.prompt, "lab fixture") {
		t.Fatalf("excerpt not in the prompt")
	}
	if strings.Contains(h.model.prompt, aiExecHost) {
		t.Fatal("the knowledge excerpt leaked the real host name")
	}
	if strings.Contains(h.model.prompt, "FOREIGN-ORG-SECRET-NOTE") {
		t.Fatal("another organization's knowledge reached the prompt")
	}
	// The comment names the cited document.
	var body string
	if err := h.db.QueryRow(`SELECT content FROM finding_comments WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1`, f).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Sources: kb:1 TLS policy") {
		t.Fatalf("comment without sources: %q", body)
	}
	// The run records its retrieval: mode, index and the cited excerpt.
	var mode, index string
	var cited bool
	if err := h.db.QueryRow(`SELECT r.retrieval_mode, r.retrieval_index, k.cited FROM ai_runs r
		JOIN ai_run_knowledge k ON k.run_id = r.id AND k.tenant_id = r.tenant_id
		WHERE r.id = $1 AND k.ordinal = 1`, d.Run.ID.String()).Scan(&mode, &index, &cited); err != nil {
		t.Fatal(err)
	}
	if mode != string(kdom.ModeLexical) || index != kdom.LexicalIndex || !cited {
		t.Fatalf("run retrieval mode=%s index=%s cited=%v", mode, index, cited)
	}

	// With evidence about the finding too, the request is filed as usual.
	f2 := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"likely_false_positive","reason":"Lab fixture."},"confidence":0.95,"evidence":[{"ref":"bundle:finding.title"},{"ref":"kb:1"}]}
]}`
	d2, err := h.analyze(a, f2, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d2); got["verdict"] != aianalysis.ActionRequested {
		t.Fatalf("evidence + knowledge outcome: %v %+v", got, d2.Actions)
	}

	// A citation of an excerpt the run never had does not resolve.
	f3 := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"likely_false_positive","reason":"x"},"confidence":0.95,"evidence":[{"ref":"bundle:finding.title"},{"ref":"kb:9"}]}
]}`
	d3, err := h.analyze(a, f3, "triage.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := outcomes(d3); got["verdict"] != aianalysis.ActionCommented {
		t.Fatalf("unknown excerpt outcome: %v %+v", got, d3.Actions)
	}
}

func TestAIExecutor_EmptyRetrievalRecorded_DB(t *testing.T) {
	h := newAIExecHarness(t)
	h.executor.SetKnowledge(aiknowledge.New(postgres.NewAIKnowledgeRepository(&postgres.DB{DB: h.db}), nil, nil, logger.NewNop()))
	a := h.aiAgent("suggest")
	f := h.findingFor(a, "medium")
	h.model.reply = `{"suggestions":[{"kind":"summary","payload":{"text":"ok"},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}]}`
	d, err := h.analyze(a, f, "summary.v1")
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := h.db.QueryRow(`SELECT retrieval_mode FROM ai_runs WHERE id = $1`, d.Run.ID.String()).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != string(kdom.ModeLexical) {
		// Retrieval ran and found nothing: lexical with no excerpts.
		t.Fatalf("mode = %s", mode)
	}
	if strings.Contains(h.model.prompt, "Organization knowledge") {
		t.Fatal("an empty retrieval still added a knowledge section")
	}
}
