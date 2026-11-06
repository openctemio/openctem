package unit

// Private program routing in the notification outbox (RFC-065 §15.4): an
// event about an asset only private programs list reaches only the
// integrations attached to one of them; an unknown decision delivers
// nothing.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	outboxapp "github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeDeliveryResolver struct {
	delivery bountyprogram.Delivery
	err      error
	subjects []bountyprogram.DeliverySubject
}

func (f *fakeDeliveryResolver) Resolve(_ context.Context, _ shared.ID, s bountyprogram.DeliverySubject) (bountyprogram.Delivery, error) {
	f.subjects = append(f.subjects, s)
	return f.delivery, f.err
}

func (f *fakeDeliveryResolver) RestrictedAssets(context.Context, shared.ID, []shared.ID) (map[shared.ID]bool, error) {
	return nil, f.err
}

// drainOutbox runs processing passes, each channel's backoff elapsed before
// every pass, until the entries are archived or every channel spent its
// attempts. It returns the failed count of the first pass.
func drainOutbox(t *testing.T, svc *outboxapp.Service, entries []*outbox.Outbox, eventRepo *mockEventRepo) int {
	t.Helper()
	first := -1
	for i := 0; i < outbox.MaxDeliveryAttempts(); i++ {
		past := time.Now().Add(-time.Second)
		for _, e := range entries {
			ds := e.Deliveries()
			for j := range ds {
				if ds[j].Status == outbox.DeliveryPending {
					ds[j].NextAttemptAt = &past
				}
			}
			e.SetDeliveries(ds)
		}
		_, failed, err := svc.ProcessOutboxBatch(context.Background(), "w", 10)
		if err != nil {
			t.Fatal(err)
		}
		if first < 0 {
			first = failed
		}
		if eventRepo.createCalls > 0 {
			break
		}
	}
	return first
}

// exhaustedFindingEntry is a finding notice; drainOutbox spends its
// channels' attempts, so a failed send is archived with its send results.
func exhaustedFindingEntry(tenantID shared.ID, findingID uuid.UUID) *outbox.Outbox {
	now := time.Now()
	return outbox.Reconstitute(outbox.NewID(), tenantID, "new_finding", "finding", &findingID,
		"New high finding", "body", outbox.Severity("high"), "/findings/x", nil,
		outbox.OutboxStatusPending, 3, 3, "", now, nil, "", now, now, nil)
}

func sentTo(ev *outbox.Event) map[string]bool {
	out := map[string]bool{}
	if ev == nil {
		return out
	}
	for _, r := range ev.SendResults() {
		out[r.IntegrationID] = true
	}
	return out
}

func TestOutboxProgramDelivery(t *testing.T) {
	tenantID := shared.NewID()
	program := shared.NewID()
	orgWide := makeConnectedIntegration(tenantID, integration.ProviderSlack, nil)
	attached := makeConnectedIntegration(tenantID, integration.ProviderWebhook, nil)
	findingID := uuid.New()

	run := func(t *testing.T, resolver *fakeDeliveryResolver) (*mockOutboxRepo, *mockEventRepo, int) {
		t.Helper()
		outboxRepo := &mockOutboxRepo{fetchPendingResult: []*outbox.Outbox{exhaustedFindingEntry(tenantID, findingID)}}
		eventRepo := &mockEventRepo{}
		notifRepo := &mockNotifExtRepoForService{
			listIntWithNotifResult: []*integration.IntegrationWithNotification{orgWide, attached},
		}
		// Decrypt fails: no network, but every matched integration leaves
		// a send result.
		svc := newTestOutboxService(outboxRepo, eventRepo, notifRepo, failDecrypt())
		if resolver != nil {
			svc.SetDeliveryResolver(resolver)
		}
		failed := drainOutbox(t, svc, outboxRepo.fetchPendingResult, eventRepo)
		return outboxRepo, eventRepo, failed
	}

	t.Run("restricted event is suppressed from org-wide integrations", func(t *testing.T) {
		resolver := &fakeDeliveryResolver{delivery: bountyprogram.Delivery{
			Restricted: [][]shared.ID{{program}},
			Channels:   map[shared.ID]map[shared.ID]bool{attached.Integration.ID(): {program: true}},
		}}
		_, eventRepo, _ := run(t, resolver)
		got := sentTo(eventRepo.lastCreated)
		if got[orgWide.Integration.ID().String()] {
			t.Fatal("org-wide integration received a private program event")
		}
		if !got[attached.Integration.ID().String()] {
			t.Fatal("program channel did not receive the event")
		}
		// Resolved on every pass (the routing may change between retries),
		// always for the entry's finding.
		if len(resolver.subjects) == 0 {
			t.Fatal("routing never resolved")
		}
		for _, subj := range resolver.subjects {
			if len(subj.FindingIDs) != 1 || subj.FindingIDs[0].String() != findingID.String() {
				t.Fatalf("subject = %+v", resolver.subjects)
			}
		}
	})

	t.Run("restricted with no program channel reaches nobody", func(t *testing.T) {
		_, eventRepo, _ := run(t, &fakeDeliveryResolver{delivery: bountyprogram.Delivery{Restricted: [][]shared.ID{{program}}}})
		if got := sentTo(eventRepo.lastCreated); len(got) != 0 {
			t.Fatalf("delivered to %v", got)
		}
	})

	t.Run("unrestricted event (shared asset, or opted in) reaches every integration", func(t *testing.T) {
		_, eventRepo, _ := run(t, &fakeDeliveryResolver{delivery: bountyprogram.Delivery{
			Programs: []bountyprogram.DeliveryProgram{{ID: program, Name: "Secret"}},
		}})
		got := sentTo(eventRepo.lastCreated)
		if !got[orgWide.Integration.ID().String()] || !got[attached.Integration.ID().String()] {
			t.Fatalf("delivered to %v", got)
		}
	})

	t.Run("resolver error delivers nothing and fails the entry", func(t *testing.T) {
		outboxRepo, eventRepo, failed := run(t, &fakeDeliveryResolver{err: errors.New("db down")})
		if failed != 1 {
			t.Fatalf("failed = %d", failed)
		}
		if eventRepo.createCalls != 0 && len(sentTo(eventRepo.lastCreated)) != 0 {
			t.Fatal("delivered on an unknown decision")
		}
		if outboxRepo.lastUpdated == nil {
			t.Fatal("entry not updated after the resolver error")
		}
	})
}

func TestOutboxDeliverySubject(t *testing.T) {
	a1, a2, id := shared.NewID(), shared.NewID(), uuid.New()
	// A batch new-asset notice as stored (JSON decoded): every listed asset.
	s := outboxapp.DeliverySubject("asset", nil, map[string]any{"assets": []any{
		map[string]any{"id": a1.String()}, map[string]any{"id": a2.String()}, map[string]any{"id": "nope"}, "x"}})
	if len(s.AssetIDs) != 2 || s.AssetIDs[0] != a1 || s.AssetIDs[1] != a2 {
		t.Fatalf("batch assets = %+v", s.AssetIDs)
	}
	// As built in memory.
	s = outboxapp.DeliverySubject("asset", &id, map[string]any{"assets": []map[string]any{{"id": a1.String()}}})
	if len(s.AssetIDs) != 2 {
		t.Fatalf("aggregate + metadata = %+v", s.AssetIDs)
	}
	for agg, check := range map[string]func(bountyprogram.DeliverySubject) int{
		"finding":  func(s bountyprogram.DeliverySubject) int { return len(s.FindingIDs) },
		"exposure": func(s bountyprogram.DeliverySubject) int { return len(s.ExposureIDs) },
		"approval": func(s bountyprogram.DeliverySubject) int { return len(s.ApprovalIDs) },
	} {
		if got := check(outboxapp.DeliverySubject(agg, &id, nil)); got != 1 {
			t.Fatalf("%s: %d", agg, got)
		}
	}
	if !outboxapp.DeliverySubject("sensor", &id, nil).Empty() {
		t.Fatal("a sensor notice names an asset")
	}
}
