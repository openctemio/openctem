package unit

// Custom template versions approved for sensors (RFC-040 §5.8, §11.5): the
// scope policy's approval count, never the author, and the job signer
// accepts the version before it is saved as approved.

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fixedApprovals struct{ n int }

func (f fixedApprovals) EffectiveApprovals(context.Context, string) (int, int, error) {
	return f.n, 2, nil
}

// countingTemplates counts the writes that reach the repository.
type countingTemplates struct {
	*scannerTemplateMockRepository
	writes int
}

func (c *countingTemplates) Create(ctx context.Context, t *scannertemplate.ScannerTemplate) error {
	c.writes++
	return c.scannerTemplateMockRepository.Create(ctx, t)
}

func (c *countingTemplates) Update(ctx context.Context, t *scannertemplate.ScannerTemplate) error {
	c.writes++
	return c.scannerTemplateMockRepository.Update(ctx, t)
}

func templateLedgerService(t *testing.T, approvals int) (*app.ScannerTemplateService, *countingTemplates, *fakeLedger) {
	t.Helper()
	repo := &countingTemplates{scannerTemplateMockRepository: newScannerTemplateMockRepository()}
	svc := app.NewScannerTemplateService(repo, "test-signing-secret", logger.NewNop())
	l := &fakeLedger{}
	svc.SetLedger(l, fixedApprovals{approvals})
	return svc, repo, l
}

func createTemplate(t *testing.T, svc *app.ScannerTemplateService, tenantID, author shared.ID) *scannertemplate.ScannerTemplate {
	t.Helper()
	tpl, err := svc.CreateTemplate(context.Background(), app.CreateScannerTemplateInput{TenantID: tenantID.String(), UserID: author.String(),
		Name: "probe-" + shared.NewID().String(), TemplateType: "nuclei", Content: validNucleiYAML()})
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}

func TestTemplateLedger_PolicyZeroApprovesAtOnceThroughTheSigner(t *testing.T) {
	svc, _, l := templateLedgerService(t, 0)
	tenantID, author := shared.NewID(), shared.NewID()
	tpl := createTemplate(t, svc, tenantID, author)
	if !tpl.ApprovedForSensors() || len(l.changes) != 1 {
		t.Fatalf("approved %v, changes %d", tpl.ApprovedForSensors(), len(l.changes))
	}
	ch := l.changes[0]
	op := ch.Ops[0]
	if op.Op != jobsign.OpPutTemplate || op.Template.ID != tpl.ID.String() || op.Template.SHA256 != tpl.ContentDigest() ||
		ch.Requester != author.String() || ch.RequiredApprovals != 0 {
		t.Fatalf("change %+v", ch)
	}
	raw, _ := base64.StdEncoding.DecodeString(validNucleiYAML())
	if want := jobsign.PayloadDigest(raw); op.Template.SHA256 != want {
		t.Fatalf("digest %s, want the content digest %s", op.Template.SHA256, want)
	}
}

func TestTemplateLedger_SignerRefusalLeavesNothingSaved(t *testing.T) {
	svc, repo, l := templateLedgerService(t, 0)
	l.refuse = true
	_, err := svc.CreateTemplate(context.Background(), app.CreateScannerTemplateInput{TenantID: shared.NewID().String(),
		UserID: shared.NewID().String(), Name: "probe", TemplateType: "nuclei", Content: validNucleiYAML()})
	if domainCode(err) != "TEMPLATE_LEDGER_REFUSED" || repo.writes != 0 {
		t.Fatalf("create with the signer refusing: %v, %d writes", err, repo.writes)
	}
}

func TestTemplateLedger_ApprovalsFollowTheScopePolicy(t *testing.T) {
	svc, repo, l := templateLedgerService(t, 1)
	ctx := context.Background()
	tenantID, author, approver := shared.NewID(), shared.NewID(), shared.NewID()
	tpl := createTemplate(t, svc, tenantID, author)
	if tpl.ApprovedForSensors() || len(l.changes) != 0 {
		t.Fatal("a version needing an approval reached the ledger at creation")
	}

	// The author never approves their own version.
	if _, err := svc.ApproveTemplateForSensors(ctx, tenantID.String(), tpl.ID.String(), author.String()); domainCode(err) != "TEMPLATE_SELF_APPROVAL" {
		t.Fatalf("self-approval: %v", err)
	}
	// The signer refusing the approval: not saved as approved.
	l.refuse = true
	writes := repo.writes
	if _, err := svc.ApproveTemplateForSensors(ctx, tenantID.String(), tpl.ID.String(), approver.String()); domainCode(err) != "TEMPLATE_LEDGER_REFUSED" {
		t.Fatalf("approval with the signer refusing: %v", err)
	}
	if repo.writes != writes {
		t.Fatal("an approval the signer refused was saved")
	}

	l.refuse = false
	fresh := createTemplate(t, svc, tenantID, author)
	got, err := svc.ApproveTemplateForSensors(ctx, tenantID.String(), fresh.ID.String(), approver.String())
	if err != nil || !got.ApprovedForSensors() {
		t.Fatalf("approval: %v %v", got.ApprovedForSensors(), err)
	}
	ch := l.changes[len(l.changes)-1]
	if ch.Requester != author.String() || ch.RequiredApprovals != 1 || len(ch.Approvals) != 1 || ch.Approvals[0].UserID != approver.String() {
		t.Fatalf("change %+v", ch)
	}

	// A new version is not approved: it leaves the ledger, and its author
	// (the updater) cannot approve it.
	newContent := base64.StdEncoding.EncodeToString([]byte("id: changed\ninfo:\n  name: Changed\n  severity: low\n  author: x\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/x\"\n"))
	sent := len(l.changes)
	updated, err := svc.UpdateTemplate(ctx, app.UpdateScannerTemplateInput{TenantID: tenantID.String(), TemplateID: fresh.ID.String(),
		Content: newContent, UserID: approver.String()})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ApprovedForSensors() || len(l.changes) != sent+1 || l.changes[sent].Ops[0].Op != jobsign.OpRemoveTemplate {
		t.Fatalf("new version: approved %v, changes %+v", updated.ApprovedForSensors(), l.changes[sent:])
	}
	if _, err := svc.ApproveTemplateForSensors(ctx, tenantID.String(), fresh.ID.String(), approver.String()); domainCode(err) != "TEMPLATE_SELF_APPROVAL" {
		t.Fatalf("the updater approving their version: %v", err)
	}
	if _, err := svc.ApproveTemplateForSensors(ctx, tenantID.String(), fresh.ID.String(), author.String()); err != nil {
		t.Fatalf("another person approving the new version: %v", err)
	}

	// Deprecating takes it out of the ledger.
	sent = len(l.changes)
	if _, err := svc.DeprecateTemplate(ctx, tenantID.String(), fresh.ID.String()); err != nil {
		t.Fatal(err)
	}
	if len(l.changes) != sent+1 || l.changes[sent].Ops[0].Op != jobsign.OpRemoveTemplate {
		t.Fatalf("deprecate: %+v", l.changes[sent:])
	}
	tpls, err := svc.LedgerTemplates(ctx, tenantID.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range tpls {
		if x.ID == fresh.ID.String() {
			t.Fatal("a deprecated template is in the ledger snapshot")
		}
	}
}

func TestTemplateLedger_NoSignerNeedsNoApproval(t *testing.T) {
	repo := newScannerTemplateMockRepository()
	svc := app.NewScannerTemplateService(repo, "test-signing-secret", logger.NewNop())
	tpl := createTemplate(t, svc, shared.NewID(), shared.NewID())
	if !tpl.ApprovedForSensors() {
		t.Fatal("without a job signer a template version needs no approval")
	}
}
