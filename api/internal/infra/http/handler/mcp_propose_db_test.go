package handler

// An AI application's proposal against real Postgres (docs/rfcs/RFC-062-mcp-authorization.md,
// "Proposal tools"): the request is the person's own and records the
// application; it waits for a person even when the organization's
// false-positive level would let that person decide alone; the person can
// never approve it, not with the normal approval and not with the solo
// self-approval; another person can. Out-of-scope and other-tenant findings
// file nothing.

import (
	"errors"
	"net/http"
	"testing"

	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestMCPProposalFourEyes_DB(t *testing.T) {
	f := newWFDB(t)
	f.vuln.SetApprovalRepository(postgres.NewFindingApprovalRepository(&postgres.DB{DB: f.raw}))
	f.vuln.SetSoloApproval(nil, nil, fpLevelOff{})
	f.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{finding_approvals}', '{"fp_approval":"off"}'::jsonb) WHERE id = $1`, f.tenantA)
	reason := string(vulnerability.PersonClosureReasons(vulnerability.FindingStatusFalsePositive)[0])
	assetLow, fid := shared.NewID().String(), shared.NewID().String()
	f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'private', 'low')`,
		assetLow, f.tenantA, "mcpp-low-"+assetLow+".example.com")
	f.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		VALUES ($1, $2, $3, 'manual', 'mcpp', 'low', 'mcpp', $4)`, fid, f.tenantA, assetLow, "mcpp-"+fid)

	adminCtx := f.as(f.admin, http.MethodPost, "", nil).Context()
	in := findingapp.RequestApprovalInput{
		TenantID: f.tenantA, FindingID: fid, RequestedStatus: "false_positive",
		Justification: "the banner comes from the load balancer", RequestedBy: f.admin, ClosureReason: reason,
		CanApprove: true, RequestedVia: "Claude \u202eDesktop", Source: string(vulnerability.SourceMCP),
	}
	a, err := f.vuln.RequestApproval(adminCtx, in)
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if a.Status != vulnerability.ApprovalStatusPending {
		t.Fatalf("an AI proposal was decided at once (%s): it must wait for another person", a.Status)
	}
	var via, status, requestedBy string
	if err := f.raw.QueryRow(`SELECT COALESCE(requested_via, ''), status, requested_by::text FROM finding_status_approvals WHERE id = $1`, a.ID.String()).
		Scan(&via, &status, &requestedBy); err != nil {
		t.Fatal(err)
	}
	if via != "Claude Desktop" || status != "pending" || requestedBy != f.admin {
		t.Fatalf("stored proposal: via %q status %s requested_by %s", via, status, requestedBy)
	}
	var fstatus string
	_ = f.raw.QueryRow(`SELECT status FROM findings WHERE id = $1`, fid).Scan(&fstatus)
	if fstatus == "false_positive" {
		t.Fatal("the proposal changed the finding")
	}

	// The person it was filed for cannot approve it.
	if _, err := f.vuln.ApproveStatus(adminCtx, findingapp.ApproveStatusInput{TenantID: f.tenantA, ApprovalID: a.ID.String(), ApprovedBy: f.admin}); !errors.Is(err, vulnerability.ErrSelfApproval) {
		t.Fatalf("requester approved their agent's proposal: %v", err)
	}
	if _, err := f.vuln.SelfApproveSolo(adminCtx, findingapp.SelfApproveInput{TenantID: f.tenantA, ApprovalID: a.ID.String(), UserID: f.admin, Reason: "solo", Code: "000000"}); !errors.Is(err, vulnerability.ErrSoloApprovalNotAllowed) {
		t.Fatalf("solo self-approval of an agent proposal: %v", err)
	}
	// A second proposal for the same finding is a conflict.
	if _, err := f.vuln.RequestApproval(adminCtx, in); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second pending proposal: %v", err)
	}
	// Another person who can see the finding decides it.
	f.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		f.editor, f.tenantA, assetLow)
	editorCtx := f.as(f.editor, http.MethodPost, "", nil).Context()
	got, err := f.vuln.ApproveStatus(editorCtx, findingapp.ApproveStatusInput{TenantID: f.tenantA, ApprovalID: a.ID.String(), ApprovedBy: f.editor})
	if err != nil || got.Status != vulnerability.ApprovalStatusApproved {
		t.Fatalf("another person's approval: %+v %v", got, err)
	}

	// A member outside the finding's data scope, and another tenant's
	// finding, file nothing.
	operatorCtx := f.as(f.operator, http.MethodPost, "", nil).Context()
	for name, c := range map[string]struct{ tenant, finding string }{
		"out of scope":   {f.tenantA, f.fOut},
		"another tenant": {f.tenantA, f.fB},
	} {
		_, err := f.vuln.RequestApproval(operatorCtx, findingapp.RequestApprovalInput{
			TenantID: c.tenant, FindingID: c.finding, RequestedStatus: "false_positive", Justification: "x",
			RequestedBy: f.operator, ClosureReason: reason, RequestedVia: "Claude", Source: string(vulnerability.SourceMCP),
		})
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: %v, want not found", name, err)
		}
	}
	var n int
	_ = f.raw.QueryRow(`SELECT count(*) FROM finding_status_approvals WHERE finding_id IN ($1, $2)`, f.fOut, f.fB).Scan(&n)
	if n != 0 {
		t.Fatalf("%d requests filed outside scope", n)
	}
}
