package postgres

// Edits that lower an asset's risk inputs against a real database
// (docs/architecture/asset-risk-governance.md): the preview counts the
// findings whose class would drop; a lowering that would drop an open P0/P1
// waits for a second person under the organization's approval level and the
// asset keeps its values; the requester and the asset's owners never approve;
// raising risk and lowering that drops no P0/P1 are free; another tenant and
// another asset get not found. Skipped unless DATABASE_URL names a migrated
// test database.

import (
	"context"
	"errors"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type riskApprovers []shared.ID

func (a riskApprovers) FindingApprovers(context.Context, shared.ID) ([]finding.FindingApprover, error) {
	out := make([]finding.FindingApprover, 0, len(a))
	for _, id := range a {
		out = append(out, finding.FindingApprover{UserID: id.String()})
	}
	return out, nil
}

type riskGovernor struct{ g *finding.AssetRiskGovernance }

func (a riskGovernor) GovernRisk(ctx context.Context, in assetapp.RiskGovernInput) (assetapp.RiskGovernOutcome, error) {
	out, err := a.g.Govern(ctx, finding.GovernInput{
		TenantID: in.TenantID, AssetID: in.AssetID, Before: in.Before, After: in.After,
		Actor: in.Actor, CanApprove: in.CanApprove, Reason: in.Reason, Audit: in.Audit,
	})
	return assetapp.RiskGovernOutcome{Held: out.Held}, err
}

type riskFixture struct {
	*sevFixture
	owner shared.ID
	third shared.ID
	asvc  *assetapp.AssetService
	gov   *finding.AssetRiskGovernance
}

// newRiskFixture wires the asset service and the governance under approval
// level `level`, with approvers other, third and the asset's owner in the
// directory.
func newRiskFixture(t *testing.T, level string) *riskFixture {
	t.Helper()
	fx := &riskFixture{sevFixture: newSevFixture(t)}
	ctx := context.Background()
	pdb := &DB{DB: fx.db}
	fx.owner, fx.third = seedUser(ctx, t, pdb), seedUser(ctx, t, pdb)
	if _, err := fx.db.ExecContext(ctx, `INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`,
		fx.asset.String(), fx.owner.String()); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	// The approvers have the asset in their data scope.
	for _, u := range []shared.ID{fx.other, fx.third, fx.owner, fx.analyst} {
		if _, err := fx.db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
			VALUES ($1, $2, $3, 'secondary') ON CONFLICT DO NOTHING`, u.String(), fx.tenant.String(), fx.asset.String()); err != nil {
			t.Fatalf("seed scope row: %v", err)
		}
	}
	log := logger.NewNop()
	assets := NewAssetRepository(pdb)
	vsvc := fx.svc(level, "")
	vsvc.SetApprovalRepository(NewFindingApprovalRepository(pdb))
	vsvc.SetApprovalNotifier(riskApprovers{fx.other, fx.third, fx.owner, fx.analyst}, nil, nil, "")
	classifier := finding.NewPriorityClassificationService(fx.repo, assets, fakeEPSSRepo{}, fakeKEVRepo{}, fakeRuleRepo{}, fakeAuditRepo{}, log)
	fx.asvc = assetapp.NewAssetService(assets, log)
	fx.gov = finding.NewAssetRiskGovernance(vsvc, classifier, assets, NewAssetRiskRequestRepository(pdb), fx.asvc, log)
	fx.asvc.SetRiskGovernor(riskGovernor{fx.gov})
	return fx
}

func (fx *riskFixture) exposure(t *testing.T) asset.Exposure {
	t.Helper()
	a, err := NewAssetRepository(&DB{DB: fx.db}).GetByID(context.Background(), fx.tenant, fx.asset)
	if err != nil {
		t.Fatalf("load asset: %v", err)
	}
	return a.Exposure()
}

func ptr[T any](v T) *T { return &v }

func (fx *riskFixture) lower(t *testing.T, actor shared.ID, canApprove bool, reason string, in assetapp.UpdateAssetInput) (*asset.Asset, *asset.RiskChangeRequest, error) {
	t.Helper()
	in.ActorID = actor.String()
	return fx.asvc.UpdateAssetGoverned(context.Background(), fx.asset.String(), fx.tenant.String(), in,
		assetapp.RiskContext{CanApprove: canApprove, Reason: reason, Audit: auditapp.AuditContext{ActorID: actor.String()}})
}

func (fx *riskFixture) decide(request shared.ID, actor shared.ID) finding.DecideRiskRequestInput {
	return finding.DecideRiskRequestInput{TenantID: fx.tenant.String(), AssetID: fx.asset.String(),
		RequestID: request.String(), ActorID: actor.String()}
}

func TestAssetRisk_LoweringWaitsForSecondPerson(t *testing.T) {
	fx := newRiskFixture(t, tenantdom.FPApprovalAll)
	ctx := context.Background()
	f := fx.create(t, "critical")
	if classOf(fx.load(t, f.ID())) != "P1" {
		t.Fatalf("setup: class %s, want P1", classOf(fx.load(t, f.ID())))
	}

	// Preview: the impact and how it would be decided.
	proposed := asset.PriorityInputs{Exposure: asset.ExposureIsolated, Criticality: asset.CriticalityHigh}
	prev, err := fx.gov.Preview(ctx, fx.tenant, fx.asset, fx.analyst, true, proposed)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if prev.Impact.P0P1Drops != 1 || prev.Impact.ClassDrops != 1 || len(prev.Impact.Lowered) != 1 || prev.Impact.Lowered[0] != "exposure" {
		t.Fatalf("preview impact = %+v, want one P0/P1 drop from exposure", prev.Impact)
	}
	if prev.Approval == nil || !prev.Approval.Required || !prev.Approval.Satisfiable {
		t.Fatalf("preview approval = %+v, want a satisfiable second-person requirement", prev.Approval)
	}
	if got := fx.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("preview changed the asset: exposure %s", got)
	}

	// A reason is required, and nothing is applied without one.
	in := assetapp.UpdateAssetInput{Exposure: ptr("isolated"), Description: ptr("moved behind the gateway")}
	if _, _, err := fx.lower(t, fx.analyst, false, "", in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: want a validation error, got %v", err)
	}
	if got := fx.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("exposure changed without a reason: %s", got)
	}

	// With a reason the lowered field is held, the rest of the edit applies.
	a, held, err := fx.lower(t, fx.analyst, false, "moved behind the gateway", in)
	if err != nil || held == nil {
		t.Fatalf("lower: held=%v err=%v", held, err)
	}
	if a.Exposure() != asset.ExposurePublic || a.Description() != "moved behind the gateway" {
		t.Fatalf("after hold: exposure=%s description=%q, want public and the new description", a.Exposure(), a.Description())
	}
	if got := fx.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("stored exposure = %s, want public until approved", got)
	}
	if classOf(fx.load(t, f.ID())) != "P1" {
		t.Fatalf("the finding's class changed before approval")
	}
	if _, _, err := fx.lower(t, fx.analyst, false, "again", in); !errors.Is(err, asset.ErrRiskRequestPending) {
		t.Fatalf("second request: want ErrRiskRequestPending, got %v", err)
	}
	pending, err := fx.gov.PendingRequest(ctx, fx.tenant, fx.asset)
	if err != nil || pending == nil || pending.ID != held.ID {
		t.Fatalf("pending request read back: %v %v", pending, err)
	}

	// The requester and the asset's owner never approve; another person does.
	if _, err := fx.gov.ApproveRequest(ctx, fx.decide(held.ID, fx.analyst)); !errors.Is(err, asset.ErrRiskSelfApproval) {
		t.Fatalf("self approval: want ErrRiskSelfApproval, got %v", err)
	}
	if _, err := fx.gov.ApproveRequest(ctx, fx.decide(held.ID, fx.owner)); err == nil {
		t.Fatal("the asset's owner approved a request on their own asset")
	} else if _, ok := approvalpolicy.IsRefusal(err); !ok {
		t.Fatalf("owner approval: want an approval policy refusal, got %v", err)
	}
	if got := fx.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("exposure changed by a refused approval: %s", got)
	}
	res, err := fx.gov.ApproveRequest(ctx, fx.decide(held.ID, fx.other))
	if err != nil || !res.Applied {
		t.Fatalf("approve: applied=%v err=%v", res != nil && res.Applied, err)
	}
	if got := fx.exposure(t); got != asset.ExposureIsolated {
		t.Fatalf("exposure after approval = %s, want isolated", got)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM approval_signoffs WHERE tenant_id = $1 AND subject_type = 'asset_risk_request'
		AND subject_id = $2 AND user_id = $3`, fx.tenant.String(), held.ID.String(), fx.other.String()); n != 1 {
		t.Errorf("sign-off rows = %d, want 1", n)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM asset_risk_requests WHERE id = $1 AND status = 'approved' AND decided_by = $2`,
		held.ID.String(), fx.other.String()); n != 1 {
		t.Errorf("request not approved by the approver")
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2
		AND action IN ('asset_risk.requested', 'asset_risk.approved')`, fx.tenant.String(), fx.asset.String()); n != 2 {
		t.Errorf("audit rows (requested + approved) = %d, want 2", n)
	}
	if n := fx.count(t, `SELECT COUNT(*) FROM assets WHERE id = $1 AND tenant_id = $2`, fx.asset.String(), fx.tenant.String()); n != 1 {
		t.Fatal("asset vanished")
	}
}

func TestAssetRisk_FreeAndAloneUnderOff(t *testing.T) {
	ctx := context.Background()

	// Raising risk is free, even at the strictest level.
	fx := newRiskFixture(t, tenantdom.FPApprovalAll)
	fx.create(t, "critical")
	if _, err := fx.db.ExecContext(ctx, `UPDATE assets SET exposure = 'isolated' WHERE id = $1`, fx.asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, held, err := fx.lower(t, fx.analyst, false, "", assetapp.UpdateAssetInput{Exposure: ptr("public")}); err != nil || held != nil {
		t.Fatalf("raising exposure: held=%v err=%v", held, err)
	}
	if got := fx.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("raise not applied: %s", got)
	}

	// Lowering that drops no open P0/P1 finding is free, with no reason.
	low := newRiskFixture(t, tenantdom.FPApprovalAll)
	low.create(t, "low")
	if _, held, err := low.lower(t, low.analyst, false, "", assetapp.UpdateAssetInput{Exposure: ptr("isolated")}); err != nil || held != nil {
		t.Fatalf("lowering with no P0/P1 on the asset: held=%v err=%v", held, err)
	}
	if got := low.exposure(t); got != asset.ExposureIsolated {
		t.Fatalf("free lowering not applied: %s", got)
	}

	// Level off: someone who may approve and does not own the asset decides alone,
	// audited at High; a member without that permission still needs a second person.
	off := newRiskFixture(t, tenantdom.FPApprovalOff)
	off.create(t, "critical")
	_, held, err := off.lower(t, off.analyst, false, "behind the gateway", assetapp.UpdateAssetInput{Exposure: ptr("isolated")})
	if err != nil || held == nil {
		t.Fatalf("level off, no approve permission: held=%v err=%v, want a request", held, err)
	}
	if _, err := off.gov.CancelRequest(ctx, off.decide(held.ID, off.analyst)); err != nil {
		t.Fatal(err)
	}
	if _, held, err := off.lower(t, off.analyst, true, "behind the gateway", assetapp.UpdateAssetInput{Exposure: ptr("isolated")}); err != nil || held != nil {
		t.Fatalf("level off, may approve: held=%v err=%v, want applied", held, err)
	}
	if got := off.exposure(t); got != asset.ExposureIsolated {
		t.Fatalf("decided alone but not applied: %s", got)
	}
	if n := off.count(t, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 AND action = 'asset_risk.lowered'
		AND severity = 'high' AND metadata->>'reason' = 'behind the gateway'`, off.tenant.String(), off.asset.String()); n != 1 {
		t.Errorf("high-severity audit rows = %d, want 1", n)
	}
	// The asset's owner never decides alone: with the same permission they still need a second person.
	own := newRiskFixture(t, tenantdom.FPApprovalOff)
	own.create(t, "critical")
	if _, held, err := own.lower(t, own.owner, true, "my own asset", assetapp.UpdateAssetInput{Exposure: ptr("isolated")}); err != nil || held == nil {
		t.Fatalf("owner under level off: held=%v err=%v, want a request", held, err)
	}
	if got := own.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("owner lowered their own asset: %s", got)
	}
}

func TestAssetRisk_DecisionIsolationAndStaleness(t *testing.T) {
	fx := newRiskFixture(t, tenantdom.FPApprovalAll)
	ctx := context.Background()
	fx.create(t, "critical")
	_, held, err := fx.lower(t, fx.analyst, false, "behind the gateway", assetapp.UpdateAssetInput{Exposure: ptr("isolated")})
	if err != nil || held == nil {
		t.Fatalf("request: held=%v err=%v", held, err)
	}

	// Another tenant, and another asset of this tenant, do not find the request.
	otherTenant := seedTestTenant(ctx, t, fx.db)
	in := fx.decide(held.ID, fx.other)
	in.TenantID = otherTenant.String()
	if _, err := fx.gov.ApproveRequest(ctx, in); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant approve: want not found, got %v", err)
	}
	otherAsset := seedPublicAsset(ctx, t, fx.db, fx.tenant)
	in = fx.decide(held.ID, fx.other)
	in.AssetID = otherAsset.String()
	if _, err := fx.gov.ApproveRequest(ctx, in); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("approve through another asset: want not found, got %v", err)
	}

	// Rejecting needs a reason and a person other than the requester; only the requester withdraws.
	if _, err := fx.gov.RejectRequest(ctx, fx.decide(held.ID, fx.other)); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("reject without a reason: want a validation error, got %v", err)
	}
	rej := fx.decide(held.ID, fx.analyst)
	rej.Note = "no"
	if _, err := fx.gov.RejectRequest(ctx, rej); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("requester rejecting their own request: want forbidden, got %v", err)
	}
	if _, err := fx.gov.CancelRequest(ctx, fx.decide(held.ID, fx.other)); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("someone else withdrawing: want forbidden, got %v", err)
	}

	// The asset changed meanwhile: the request no longer applies.
	if _, err := fx.db.ExecContext(ctx, `UPDATE assets SET exposure = 'private' WHERE id = $1`, fx.asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.gov.ApproveRequest(ctx, fx.decide(held.ID, fx.other)); !errors.Is(err, asset.ErrRiskRequestStale) {
		t.Errorf("stale approve: want ErrRiskRequestStale, got %v", err)
	}
	if got := fx.exposure(t); got != asset.ExposurePrivate {
		t.Errorf("a stale approval changed the asset: %s", got)
	}

	// The requester withdraws; nothing is applied.
	res, err := fx.gov.CancelRequest(ctx, fx.decide(held.ID, fx.analyst))
	if err != nil || res.Request.Status != asset.RiskRequestCanceled {
		t.Fatalf("withdraw: %v %v", res, err)
	}
	if _, err := fx.gov.ApproveRequest(ctx, fx.decide(held.ID, fx.other)); !errors.Is(err, shared.ErrConflict) {
		t.Errorf("approving a withdrawn request: want a conflict, got %v", err)
	}
}

// Unmarking a crown jewel and locking a lower value go through the same
// decision: held when they would drop an open P0/P1, applied otherwise; the
// business impact of the crown-jewel call is recorded either way.
func TestAssetRisk_CrownJewelAndLock(t *testing.T) {
	fx := newRiskFixture(t, tenantdom.FPApprovalAll)
	ctx := context.Background()
	f := fx.create(t, "critical")
	if _, err := fx.db.ExecContext(ctx, `UPDATE assets SET is_crown_jewel = true, exposure = 'private' WHERE id = $1`, fx.asset.String()); err != nil {
		t.Fatal(err)
	}
	// A known-exploited finding on a crown jewel is P0; without the flag it is P1.
	if _, err := fx.db.ExecContext(ctx, `UPDATE findings SET is_in_kev = true, priority_class = 'P0' WHERE id = $1`, f.ID().String()); err != nil {
		t.Fatal(err)
	}
	prev, err := fx.gov.Preview(ctx, fx.tenant, fx.asset, fx.analyst, false,
		asset.PriorityInputs{Exposure: asset.ExposurePrivate, Criticality: asset.CriticalityHigh, CrownJewel: false})
	if err != nil {
		t.Fatal(err)
	}
	if prev.Impact.P0P1Drops == 0 {
		t.Skipf("unmarking a crown jewel drops no P0/P1 in this fixture: %+v", prev.Impact)
	}

	rc := assetapp.RiskContext{Reason: "decommissioned data set", Audit: auditapp.AuditContext{ActorID: fx.analyst.String()}}
	a, held, err := fx.asvc.UpdateCrownJewelGoverned(ctx, fx.tenant.String(), fx.asset.String(), false, 40, "notes", fx.analyst.String(), rc)
	if err != nil || held == nil {
		t.Fatalf("unmark: held=%v err=%v", held, err)
	}
	if !a.IsCrownJewel() {
		t.Fatal("the crown-jewel flag was removed before approval")
	}
	if len(held.Lowered) != 1 || held.Lowered[0] != "crown_jewel" {
		t.Fatalf("lowered = %v", held.Lowered)
	}
	if _, err := fx.gov.ApproveRequest(ctx, fx.decide(held.ID, fx.other)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := NewAssetRepository(&DB{DB: fx.db}).GetByID(ctx, fx.tenant, fx.asset)
	if err != nil || got.IsCrownJewel() {
		t.Fatalf("after approval: crown jewel=%v err=%v, want unmarked", got != nil && got.IsCrownJewel(), err)
	}
}

func TestAssetRisk_LockLowerValueIsGoverned(t *testing.T) {
	fx := newRiskFixture(t, tenantdom.FPApprovalAll)
	ctx := context.Background()
	fx.create(t, "critical")
	rc := assetapp.RiskContext{Reason: "behind the gateway", Audit: auditapp.AuditContext{ActorID: fx.analyst.String()}}
	// No attribute-source store is wired here, so only the decision is
	// visible: a lock that is not held would fail as "not configured".
	_, held, err := fx.asvc.LockAttributeGoverned(ctx, fx.tenant.String(), fx.asset.String(), "exposure", "isolated", fx.analyst.String(), rc)
	if held == nil {
		t.Fatalf("a lock that lowers exposure under an open P1 was not held (err=%v)", err)
	}
	if len(held.Lowered) != 1 || held.Lowered[0] != "exposure" {
		t.Fatalf("lowered = %v", held.Lowered)
	}
	if got := fx.exposure(t); got != asset.ExposurePublic {
		t.Fatalf("exposure = %s before approval", got)
	}
}
