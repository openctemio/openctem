package outbox

import (
	"context"
	"errors"
	"testing"
	"time"

	notificationclient "github.com/openctemio/openctem/api/internal/infra/notifier"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/webhooksig"
)

// redeliverRepos extends the harness fakes with what Redeliver reads.
type archiveRepo struct {
	fakeEventRepo
	byID map[shared.ID]*outboxdom.Event
}

func (a *archiveRepo) GetByTenantAndID(_ context.Context, tenantID shared.ID, id outboxdom.ID) (*outboxdom.Event, error) {
	ev, ok := a.byID[id]
	if !ok || ev.TenantID() != tenantID {
		return nil, outboxdom.ErrEventNotFound
	}
	return ev, nil
}

type queueRepo struct {
	fakeOutboxRepo
	created []*outboxdom.Outbox
}

func (q *queueRepo) Create(_ context.Context, e *outboxdom.Outbox) error {
	q.created = append(q.created, e)
	return nil
}

type channelRepo struct {
	fakeNotifRepo
}

func (c *channelRepo) GetIntegrationWithNotification(_ context.Context, id integration.ID) (*integration.IntegrationWithNotification, error) {
	for _, i := range c.list {
		if i.Integration.ID() == id {
			return i, nil
		}
	}
	return nil, integration.ErrIntegrationNotFound
}

func archivedEvent(tenant shared.ID, sentTo ...*integration.IntegrationWithNotification) *outboxdom.Event {
	results := make([]outboxdom.SendResult, 0, len(sentTo))
	for _, i := range sentTo {
		results = append(results, outboxdom.SendResult{IntegrationID: i.Integration.ID().String(), Status: "failed"})
	}
	return outboxdom.ReconstituteEvent(outboxdom.NewID(), tenant, "new_finding", "finding", nil,
		"title", "body", outboxdom.SeverityHigh, "https://app.example/f/1", map[string]any{"k": "v"},
		outboxdom.EventStatusFailed, len(sentTo), len(sentTo), 0, len(sentTo), results, "", 0, time.Now(), time.Now())
}

func redeliverSvc(events *archiveRepo, queue *queueRepo, chans *channelRepo) *Service {
	return NewService(queue, events, chans, func(s string) (string, error) { return s, nil }, nil)
}

func TestRedeliver_QueuesOneChannelWithOriginalKey(t *testing.T) {
	tenant := shared.NewID()
	a, b := channel(tenant, "a"), channel(tenant, "b")
	ev := archivedEvent(tenant, a, b)
	events := &archiveRepo{byID: map[shared.ID]*outboxdom.Event{ev.ID(): ev}}
	queue := &queueRepo{}
	svc := redeliverSvc(events, queue, &channelRepo{fakeNotifRepo{list: []*integration.IntegrationWithNotification{a, b}}})

	entry, err := svc.Redeliver(context.Background(), tenant, b.Integration.ID(), ev.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.created) != 1 || queue.created[0] != entry {
		t.Fatal("redelivery not queued")
	}
	ds := entry.Deliveries()
	if len(ds) != 1 || ds[0].IntegrationID != b.Integration.ID().String() || !ds[0].Due(time.Now()) {
		t.Fatalf("deliveries %+v, want channel b only", ds)
	}
	if entry.TenantID() != tenant || entry.EventType() != "new_finding" || entry.Title() != "title" {
		t.Fatalf("copied event %+v", entry)
	}
	if got := idempotencyKey(entry); got != "outbox-"+ev.ID().String() {
		t.Fatalf("idempotency key %q, want the original event's", got)
	}

	// A redelivery of the redelivery still names the first event.
	ev2 := outboxdom.NewEventFromOutbox(entry, outboxdom.ProcessingResults{SendResults: []outboxdom.SendResult{{IntegrationID: b.Integration.ID().String()}}})
	events.byID[ev2.ID()] = ev2
	again, err := svc.Redeliver(context.Background(), tenant, b.Integration.ID(), ev2.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got := idempotencyKey(again); got != "outbox-"+ev.ID().String() {
		t.Fatalf("second redelivery key %q", got)
	}
}

func TestRedeliver_RefusesWhatIsNotThisTenantsDelivery(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	a, never := channel(tenant, "a"), channel(tenant, "never")
	foreignChan := channel(other, "foreign")
	ev := archivedEvent(tenant, a)
	foreignEv := archivedEvent(other, foreignChan)
	events := &archiveRepo{byID: map[shared.ID]*outboxdom.Event{ev.ID(): ev, foreignEv.ID(): foreignEv}}
	queue := &queueRepo{}
	svc := redeliverSvc(events, queue, &channelRepo{fakeNotifRepo{list: []*integration.IntegrationWithNotification{a, never, foreignChan}}})
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"another tenant's event":            func() error { _, err := svc.Redeliver(ctx, tenant, a.Integration.ID(), foreignEv.ID()); return err },
		"another tenant's integration":      func() error { _, err := svc.Redeliver(ctx, other, foreignChan.Integration.ID(), ev.ID()); return err },
		"an integration the event skipped":  func() error { _, err := svc.Redeliver(ctx, tenant, never.Integration.ID(), ev.ID()); return err },
		"an unknown event":                  func() error { _, err := svc.Redeliver(ctx, tenant, a.Integration.ID(), shared.NewID()); return err },
		"own event, foreign integration id": func() error { _, err := svc.Redeliver(ctx, tenant, foreignChan.Integration.ID(), ev.ID()); return err },
	} {
		if err := call(); !errors.Is(err, ErrDeliveryNotFound) {
			t.Errorf("%s: want ErrDeliveryNotFound, got %v", name, err)
		}
	}
	if len(queue.created) != 0 {
		t.Fatalf("queued %d redeliveries on refusals", len(queue.created))
	}

	a.Integration.SetStatus(integration.StatusDisabled)
	if _, err := svc.Redeliver(ctx, tenant, a.Integration.ID(), ev.ID()); !errors.Is(err, ErrRedeliveryChannelUnavailable) {
		t.Fatalf("disabled channel: %v", err)
	}
}

// A redelivered entry goes to its one channel only, even though the
// channel's event filter would not match: the event already went there.
func TestRedeliver_EntrySendsToItsChannelOnly(t *testing.T) {
	tenant := shared.NewID()
	a, b := channel(tenant, "a"), channel(tenant, "b")
	h := newHarness(a, b)
	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "new_finding", Title: "t",
		Metadata: map[string]any{MetaRedeliveryOf: shared.NewID().String()}})
	entry.SetDeliveries([]outboxdom.ChannelDelivery{outboxdom.NewChannelDelivery(b.Integration.ID().String(), "b", "webhook")})
	if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if h.sentTo("https://a.example.com/hook") != 0 || h.sentTo("https://b.example.com/hook") != 1 {
		t.Fatalf("sent %+v", h.sent)
	}
}

// The webhook channel is signed with the integration's stored secret, and a
// secret that does not decrypt fails the delivery instead of sending it
// unsigned.
func TestSigning_ConfigFromStoredSecret(t *testing.T) {
	tenant := shared.NewID()
	secret, _ := webhooksig.GenerateSecret()
	signed := channel(tenant, "signed")
	signed.Integration.SetMetadata(map[string]any{integration.MetaSigningSecret: "enc:" + secret})
	broken := channel(tenant, "broken")
	broken.Integration.SetMetadata(map[string]any{integration.MetaSigningSecret: "garbage"})
	h := newHarness(signed, broken)
	h.svc.credentialDecrypt = func(s string) (string, error) {
		switch {
		case len(s) > 4 && s[:4] == "enc:":
			return s[4:], nil
		case s == "garbage":
			return "", errors.New("cipher: message authentication failed")
		}
		return s, nil
	}
	var cfgs []notificationclient.Config
	inner := h.svc.newClient
	h.svc.newClient = func(cfg notificationclient.Config) (notificationclient.Client, error) {
		cfgs = append(cfgs, cfg)
		return inner(cfg)
	}
	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "new_finding", Title: "t", Severity: outboxdom.SeverityHigh})
	if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 || len(cfgs[0].SigningSecrets) != 1 || cfgs[0].SigningSecrets[0] != secret {
		t.Fatalf("client configs %+v", cfgs)
	}
	for _, d := range entry.Deliveries() {
		if d.IntegrationName == "broken" && (d.Status != outboxdom.DeliveryPending || d.LastError == "" || d.Attempts != 1) {
			t.Fatalf("broken secret delivery %+v, want a failed attempt", d)
		}
	}
	if h.sentTo("https://broken.example.com/hook") != 0 {
		t.Fatal("sent unsigned with an unreadable secret")
	}
}
