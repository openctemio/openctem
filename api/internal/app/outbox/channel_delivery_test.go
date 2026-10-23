package outbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	notificationclient "github.com/openctemio/openctem/api/internal/infra/notifier"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeOutboxRepo records updates, archives and deletes. Methods the
// processing pass does not call are left to the embedded nil interface.
type fakeOutboxRepo struct {
	outboxdom.OutboxRepository
	updates, deletes int
}

func (f *fakeOutboxRepo) Update(context.Context, *outboxdom.Outbox) error { f.updates++; return nil }
func (f *fakeOutboxRepo) Delete(context.Context, outboxdom.ID) error      { f.deletes++; return nil }

type fakeEventRepo struct {
	outboxdom.EventRepository
	events []*outboxdom.Event
}

func (f *fakeEventRepo) Create(_ context.Context, e *outboxdom.Event) error {
	f.events = append(f.events, e)
	return nil
}

type fakeNotifRepo struct {
	integration.NotificationExtensionRepository
	list []*integration.IntegrationWithNotification
}

func (f *fakeNotifRepo) ListIntegrationsWithNotification(context.Context, integration.ID) ([]*integration.IntegrationWithNotification, error) {
	return f.list, nil
}

// fakeClient answers per webhook URL (the decrypted credentials name the
// channel) and records every message it was asked to send.
type fakeClient struct {
	fail map[string]bool
	sent *[]sentMsg
	url  string
}

type sentMsg struct {
	url string
	msg notificationclient.Message
}

func (c *fakeClient) Send(_ context.Context, m notificationclient.Message) (*notificationclient.SendResult, error) {
	*c.sent = append(*c.sent, sentMsg{url: c.url, msg: m})
	if c.fail[c.url] {
		// The HTTP clients report a refused delivery this way, not as an
		// error.
		return &notificationclient.SendResult{Success: false, Error: "webhook returned status 503"}, nil
	}
	if c.url == "" {
		return nil, errors.New("no URL")
	}
	return &notificationclient.SendResult{Success: true}, nil
}
func (c *fakeClient) TestConnection(context.Context) (*notificationclient.SendResult, error) {
	return nil, nil
}
func (c *fakeClient) Provider() string { return "webhook" }

func channel(tenant shared.ID, name string) *integration.IntegrationWithNotification {
	return integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), tenant, name, "",
		integration.CategoryNotification, integration.ProviderWebhook, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "https://"+name+".example.com/hook", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), nil)
}

type harness struct {
	svc    *Service
	outbox *fakeOutboxRepo
	events *fakeEventRepo
	notif  *fakeNotifRepo
	fail   map[string]bool
	sent   []sentMsg
}

func newHarness(chs ...*integration.IntegrationWithNotification) *harness {
	h := &harness{
		outbox: &fakeOutboxRepo{},
		events: &fakeEventRepo{},
		notif:  &fakeNotifRepo{list: chs},
		fail:   map[string]bool{},
	}
	h.svc = NewService(h.outbox, h.events, h.notif,
		func(s string) (string, error) { return s, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.svc.newClient = func(cfg notificationclient.Config) (notificationclient.Client, error) {
		return &fakeClient{fail: h.fail, sent: &h.sent, url: cfg.WebhookURL}, nil
	}
	return h
}

func (h *harness) sentTo(url string) int {
	n := 0
	for _, s := range h.sent {
		if s.url == url {
			n++
		}
	}
	return n
}

// makeDue moves every pending channel's retry to now, as if its backoff
// had elapsed.
func makeDue(e *outboxdom.Outbox) {
	ds := e.Deliveries()
	past := time.Now().Add(-time.Second)
	for i := range ds {
		if ds[i].Status == outboxdom.DeliveryPending {
			ds[i].NextAttemptAt = &past
		}
	}
	e.SetDeliveries(ds)
}

// One channel's success no longer ends the entry: the failed channel is
// retried on its own, and the one that got the event is not sent it again.
func TestProcess_FailedChannelRetriedAfterAnotherSucceeded(t *testing.T) {
	tenant := shared.NewID()
	a, b := channel(tenant, "a"), channel(tenant, "b")
	h := newHarness(a, b)
	urlA, urlB := "https://a.example.com/hook", "https://b.example.com/hook"
	h.fail[urlB] = true

	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "new_finding", Title: "t", Severity: outboxdom.SeverityHigh})
	if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if len(h.events.events) != 0 || h.outbox.deletes != 0 {
		t.Fatal("entry archived while channel b still has retries left")
	}
	if entry.Status() != outboxdom.OutboxStatusPending {
		t.Fatalf("entry status %s, want pending", entry.Status())
	}
	if d := time.Until(entry.ScheduledAt()); d < 50*time.Second || d > 70*time.Second {
		t.Fatalf("next pass in %s, want about 1m (first backoff step)", d)
	}

	// Channel b comes back.
	h.fail[urlB] = false
	makeDue(entry)
	if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if h.sentTo(urlA) != 1 {
		t.Fatalf("channel a got the event %d times, want once", h.sentTo(urlA))
	}
	if h.sentTo(urlB) != 2 {
		t.Fatalf("channel b attempts %d, want 2", h.sentTo(urlB))
	}
	if len(h.events.events) != 1 || h.outbox.deletes != 1 {
		t.Fatal("entry not archived once every channel was delivered")
	}
	ev := h.events.events[0]
	if ev.Status() != outboxdom.EventStatusCompleted || ev.IntegrationsSucceeded() != 2 {
		t.Fatalf("archive status %s succeeded %d", ev.Status(), ev.IntegrationsSucceeded())
	}
}

// A channel that never recovers is dead after its attempts and the archive
// says so, while the healthy channel's delivery stands.
func TestProcess_ChannelDeadAfterMaxAttempts(t *testing.T) {
	tenant := shared.NewID()
	h := newHarness(channel(tenant, "a"), channel(tenant, "b"))
	urlB := "https://b.example.com/hook"
	h.fail[urlB] = true

	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "new_finding", Title: "t", Severity: outboxdom.SeverityHigh})
	for i := 0; i < outboxdom.MaxDeliveryAttempts(); i++ {
		makeDue(entry)
		if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	if h.sentTo(urlB) != outboxdom.MaxDeliveryAttempts() {
		t.Fatalf("channel b attempts %d, want %d", h.sentTo(urlB), outboxdom.MaxDeliveryAttempts())
	}
	if len(h.events.events) != 1 {
		t.Fatalf("archived %d times, want once", len(h.events.events))
	}
	ev := h.events.events[0]
	if ev.IntegrationsSucceeded() != 1 || ev.IntegrationsFailed() != 1 {
		t.Fatalf("archive succeeded %d failed %d", ev.IntegrationsSucceeded(), ev.IntegrationsFailed())
	}
	for _, r := range ev.SendResults() {
		if r.IntegrationName == "b" && (r.Status != notificationStatusFailed || r.Attempts != outboxdom.MaxDeliveryAttempts()) {
			t.Fatalf("dead channel result %+v", r)
		}
	}
}

// Every message names the real catalog type and its version, with the
// idempotency key stable across retries.
func TestProcess_MessageCarriesEventType(t *testing.T) {
	tenant := shared.NewID()
	h := newHarness(channel(tenant, "a"))
	h.fail["https://a.example.com/hook"] = true
	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "sensor.offline", Title: "t", Severity: outboxdom.SeverityHigh})
	for i := 0; i < 2; i++ {
		makeDue(entry)
		if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.sent) != 2 {
		t.Fatalf("sent %d", len(h.sent))
	}
	for _, s := range h.sent {
		if s.msg.EventType != "sensor.offline" || s.msg.EventVersion != 1 {
			t.Fatalf("message type/version %q/%d", s.msg.EventType, s.msg.EventVersion)
		}
		if s.msg.IdempotencyKey != "outbox-"+entry.ID().String() {
			t.Fatalf("idempotency key %q", s.msg.IdempotencyKey)
		}
	}
}

// A channel removed after the event counts failed attempts (it may come
// back), and an integration created after the event never gets it.
func TestProcess_ChannelSetFixedAtFirstPass(t *testing.T) {
	tenant := shared.NewID()
	a := channel(tenant, "a")
	h := newHarness(a)
	h.fail["https://a.example.com/hook"] = true
	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "new_finding", Title: "t", Severity: outboxdom.SeverityHigh})
	if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	late := channel(tenant, "late")
	h.notif.list = []*integration.IntegrationWithNotification{late}
	makeDue(entry)
	if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	if h.sentTo("https://late.example.com/hook") != 0 {
		t.Fatal("an integration created after the event got it")
	}
	d := entry.Deliveries()
	if len(d) != 1 || d[0].Attempts != 2 || d[0].LastError != "integration is not connected" {
		t.Fatalf("deliveries %+v", d)
	}
}
