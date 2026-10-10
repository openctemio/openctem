package automation

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fakeDelivery marks the given assets (and findings) restricted.
type fakeDelivery struct {
	assets   map[shared.ID]bool
	findings map[shared.ID]bool
	err      error
}

func (f *fakeDelivery) Resolve(_ context.Context, _ shared.ID, s bountyprogram.DeliverySubject) (bountyprogram.Delivery, error) {
	var d bountyprogram.Delivery
	if f.err != nil {
		return d, f.err
	}
	for _, id := range s.AssetIDs {
		if f.assets[id] {
			d.Restricted = append(d.Restricted, []shared.ID{shared.NewID()})
		}
	}
	for _, id := range s.FindingIDs {
		if f.findings[id] {
			d.Restricted = append(d.Restricted, []shared.ID{shared.NewID()})
		}
	}
	return d, nil
}

func (f *fakeDelivery) RestrictedAssets(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[shared.ID]bool{}
	for _, id := range ids {
		if f.assets[id] {
			out[id] = true
		}
	}
	return out, nil
}

// Events about a private program's assets start no organization-wide
// automation; an unknown decision starts nothing (RFC-065 §15.4).
func TestDispatcherSuppressesPrivateProgramEvents(t *testing.T) {
	tenant := shared.NewID()
	ctx := context.Background()
	hiddenF, ownF := mkFinding(t, tenant, vulnerability.SeverityCritical), mkFinding(t, tenant, vulnerability.SeverityCritical)
	fd := &fakeDelivery{assets: map[shared.ID]bool{hiddenF.AssetID(): true}, findings: map[shared.ID]bool{hiddenF.ID(): true}}

	t.Run("findings created", func(t *testing.T) {
		repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*automationdom.Workflow{
			tenant: {newWorkflow(tenant, automationdom.TriggerTypeFindingCreated, nil)}}}
		rec := &triggerRecorder{}
		d := newTestDispatcher(repo, rec)
		d.SetDeliveryResolver(fd)
		if n := d.dispatchFindingsCreated(ctx, tenant, []*vulnerability.Finding{hiddenF, ownF}); n != 1 {
			t.Fatalf("runs = %d, want 1 (own finding only)", n)
		}
		if *rec.calls[0].SubjectID != ownF.ID() {
			t.Fatal("the private program finding started an automation")
		}
		d.SetDeliveryResolver(&fakeDelivery{err: errors.New("db down")})
		if n := d.dispatchFindingsCreated(ctx, tenant, []*vulnerability.Finding{ownF}); n != 0 {
			t.Fatal("started automations on an unknown decision")
		}
	})

	t.Run("finding event", func(t *testing.T) {
		repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*automationdom.Workflow{
			tenant: {newWorkflow(tenant, automationdom.TriggerTypeFindingUpdated, nil)}}}
		rec := &triggerRecorder{}
		d := newTestDispatcher(repo, rec)
		d.SetDeliveryResolver(fd)
		_ = d.DispatchFindingEvent(ctx, FindingEvent{TenantID: tenant, Finding: hiddenF, EventType: automationdom.TriggerTypeFindingUpdated})
		if len(rec.calls) != 0 {
			t.Fatal("private program finding update started an automation")
		}
		_ = d.DispatchFindingEvent(ctx, FindingEvent{TenantID: tenant, Finding: ownF, EventType: automationdom.TriggerTypeFindingUpdated})
		if len(rec.calls) != 1 {
			t.Fatalf("own finding update runs = %d", len(rec.calls))
		}
	})

	t.Run("ai triage", func(t *testing.T) {
		repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*automationdom.Workflow{
			tenant: {newWorkflow(tenant, automationdom.TriggerTypeAITriageCompleted, nil)}}}
		rec := &triggerRecorder{}
		d := newTestDispatcher(repo, rec)
		d.SetDeliveryResolver(fd)
		_ = d.DispatchAITriageEvent(ctx, AITriageEvent{TenantID: tenant, FindingID: hiddenF.ID(), TriageID: shared.NewID(),
			EventType: automationdom.TriggerTypeAITriageCompleted, TriageData: map[string]any{}})
		if len(rec.calls) != 0 {
			t.Fatal("triage of a private program finding started an automation")
		}
		_ = d.DispatchAITriageEvent(ctx, AITriageEvent{TenantID: tenant, FindingID: ownF.ID(), TriageID: shared.NewID(),
			EventType: automationdom.TriggerTypeAITriageCompleted, TriageData: map[string]any{}})
		if len(rec.calls) != 1 {
			t.Fatalf("own finding triage runs = %d", len(rec.calls))
		}
	})

	t.Run("assets discovered", func(t *testing.T) {
		repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*automationdom.Workflow{
			tenant: {newWorkflow(tenant, automationdom.TriggerTypeAssetDiscovered, nil)}}}
		rec := &triggerRecorder{}
		d := newTestDispatcher(repo, rec)
		hidden := mkAsset(t, tenant, "app.secret.example", asset.AssetTypeDomain, true)
		own := mkAsset(t, tenant, "www.own.example", asset.AssetTypeDomain, true)
		d.SetDeliveryResolver(&fakeDelivery{assets: map[shared.ID]bool{hidden.ID(): true}})
		if n := d.dispatchAssetsDiscovered(ctx, tenant, []*asset.Asset{hidden}); n != 0 {
			t.Fatal("a private program asset alone started an automation")
		}
		if n := d.dispatchAssetsDiscovered(ctx, tenant, []*asset.Asset{hidden, own}); n != 1 {
			t.Fatalf("runs = %d", n)
		}
		if got := rec.calls[0].TriggerData["asset_count"]; got != 1 {
			t.Fatalf("asset_count = %v: the private program asset is in the trigger data", got)
		}
	})
}
