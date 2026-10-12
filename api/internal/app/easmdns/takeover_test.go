package easmdns

import (
	"context"
	"testing"

	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeTakeoverStore struct {
	open      []OpenDangling
	asked     []shared.ID
	confirmed []string
	reopened  []string
}

func (f *fakeTakeoverStore) OpenDanglingCNAMEs(_ context.Context, _ shared.ID, ids []shared.ID) ([]OpenDangling, error) {
	f.asked = ids
	return f.open, nil
}

func (f *fakeTakeoverStore) MarkConfirmed(_ context.Context, _ shared.ID, ids []string, _ map[string]any) error {
	f.confirmed = append(f.confirmed, ids...)
	return nil
}

func (f *fakeTakeoverStore) ReopenAuto(_ context.Context, _ shared.ID, _ string, fps []string, _ string) (int, error) {
	f.reopened = append(f.reopened, fps...)
	return 0, nil
}

type fakeUpserter struct{ events []*exposuredom.ExposureEvent }

func (f *fakeUpserter) BulkUpsert(_ context.Context, ev []*exposuredom.ExposureEvent) error {
	f.events = append(f.events, ev...)
	return nil
}

func TestIsTakeoverTemplate(t *testing.T) {
	for id, want := range map[string]bool{
		"azure-takeover-detection": true, "github-takeover": true, "aws-bucket-takeover": true,
		"tech-detect": false, "takeoverish-panel": false, "": false,
	} {
		if got := IsTakeoverTemplate(id, nil); got != want {
			t.Errorf("%q = %v", id, got)
		}
	}
	if !IsTakeoverTemplate("custom-check", []string{"dns", "Takeover"}) {
		t.Error("takeover tag not recognized")
	}
}

// Only a sighting on an asset with an open dangling_cname raises a takeover,
// at high, and marks that dangling_cname confirmed.
func TestConfirmTakeovers(t *testing.T) {
	tenant := shared.NewID()
	withDangling, without := shared.NewID(), shared.NewID()
	store := &fakeTakeoverStore{open: []OpenDangling{{ExposureID: "e1", AssetID: withDangling, Name: "shop.example.com",
		Target: "gone.azurewebsites.net", Provider: "Microsoft Azure"}}}
	up := &fakeUpserter{}
	cmd := shared.NewID()
	n, err := NewTakeoverConfirmer(store, up, logger.NewNop()).ConfirmTakeovers(context.Background(), tenant, []TakeoverSighting{
		{AssetID: withDangling, TemplateID: "azure-takeover-detection", SensorID: shared.NewID(), CommandID: &cmd},
		{AssetID: without, TemplateID: "github-takeover", SensorID: shared.NewID()},
	})
	if err != nil || n != 1 || len(up.events) != 1 {
		t.Fatalf("n=%d events=%d err=%v", n, len(up.events), err)
	}
	ev := up.events[0]
	if ev.EventType() != exposuredom.EventTypeSubdomainTakeover || ev.Severity() != exposuredom.SeverityHigh ||
		ev.TenantID() != tenant || *ev.AssetID() != withDangling || ev.Details()["template_id"] != "azure-takeover-detection" ||
		ev.Details()["command_id"] != cmd.String() {
		t.Fatalf("event = %+v", ev.Details())
	}
	if len(store.confirmed) != 1 || store.confirmed[0] != "e1" || len(store.reopened) != 1 {
		t.Fatalf("confirmed=%v reopened=%v", store.confirmed, store.reopened)
	}

	// The DNS check clears exactly this takeover when the record is fixed.
	takeover, _ := takeoverEvent(tenant, Target{AssetID: withDangling, Name: "shop.example.com"}, nil, nil)
	if takeover.Fingerprint() != ev.Fingerprint() {
		t.Fatal("the DNS check would clear a different takeover identity")
	}
}

func TestConfirmTakeovers_NoDanglingNoTakeover(t *testing.T) {
	up := &fakeUpserter{}
	n, err := NewTakeoverConfirmer(&fakeTakeoverStore{}, up, logger.NewNop()).ConfirmTakeovers(context.Background(), shared.NewID(),
		[]TakeoverSighting{{AssetID: shared.NewID(), TemplateID: "github-takeover"}})
	if err != nil || n != 0 || len(up.events) != 0 {
		t.Fatalf("a template match alone raised a takeover: n=%d %v", n, err)
	}
}
