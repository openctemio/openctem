package outbox

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/server/internal/metrics"
	"github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/server/pkg/domain/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The alert reads a counter: dead entries are archived and removed at once,
// so a gauge of dead outbox rows never rises (the old OutboxDeadLetters
// expression could not fire). A channel that runs out of retries counts
// once, a healthy channel does not.
func TestProcess_DeadChannelCountsADeadLetter(t *testing.T) {
	tenant := shared.NewID()
	h := newHarness(channel(tenant, "a"), channel(tenant, "b"))
	h.fail["https://b.example.com/hook"] = true
	before := testutil.ToFloat64(metrics.NotificationDeadLettersTotal.WithLabelValues(deadLetterChannel))

	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: tenant, EventType: "new_finding", Title: "t", Severity: outboxdom.SeverityHigh})
	for i := 0; i < outboxdom.MaxDeliveryAttempts(); i++ {
		makeDue(entry)
		if err := h.svc.processOutboxEntry(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
		got := testutil.ToFloat64(metrics.NotificationDeadLettersTotal.WithLabelValues(deadLetterChannel)) - before
		if last := i == outboxdom.MaxDeliveryAttempts()-1; (last && got != 1) || (!last && got != 0) {
			t.Fatalf("pass %d: dead letters %v", i+1, got)
		}
	}
}

// An entry whose integrations cannot be read is retried; when its retries
// are spent it counts once as a dead letter and logs an ERROR.
func TestFailEntry_CountsWhenRetriesAreSpent(t *testing.T) {
	var buf bytes.Buffer
	repo := &fakeOutboxRepo{}
	s := &Service{outboxRepo: repo, log: slog.New(slog.NewJSONHandler(&buf, nil))}
	before := testutil.ToFloat64(metrics.NotificationDeadLettersTotal.WithLabelValues(deadLetterEntry))

	entry := outboxdom.NewOutbox(outboxdom.OutboxParams{TenantID: shared.NewID(), EventType: "new_finding", Title: "t", Severity: outboxdom.SeverityHigh})
	n := 0
	for entry.Status() != outboxdom.OutboxStatusFailed {
		s.failEntry(context.Background(), entry, "integrations unavailable")
		if n++; n > 50 {
			t.Fatal("entry never ran out of retries")
		}
		if entry.Status() != outboxdom.OutboxStatusFailed && buf.Len() != 0 {
			t.Fatalf("logged before the retries were spent: %s", buf.String())
		}
	}
	if got := testutil.ToFloat64(metrics.NotificationDeadLettersTotal.WithLabelValues(deadLetterEntry)) - before; got != 1 {
		t.Fatalf("entry dead letters %v, want 1", got)
	}
	if out := buf.String(); !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, "integrations unavailable") {
		t.Fatalf("want an ERROR naming the last error, got %s", out)
	}
	if repo.updates != n {
		t.Fatalf("updates %d, want %d", repo.updates, n)
	}
}

// The names of private programs are scrubbed from the message for an
// integration not attached to them, before the template (RFC-065 §15.4).
func TestBuildMessageScrubsPrivateProgramNames(t *testing.T) {
	program := shared.NewID()
	orgWide := integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "org", "",
		integration.CategoryNotification, integration.ProviderSlack, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), withDetails())
	attached := integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "prog", "",
		integration.CategoryNotification, integration.ProviderSlack, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), withDetails())
	d := bountyprogram.Delivery{
		Programs: []bountyprogram.DeliveryProgram{{ID: program, Name: "Hush Corp", Tag: "program:h1:hush"}},
		Channels: map[shared.ID]map[shared.ID]bool{attached.Integration.ID(): {program: true}},
	}
	entry := outboxdom.Reconstitute(outboxdom.NewID(), shared.NewID(), "new_finding", "finding", nil,
		"Hush Corp: XSS on shop", "tags: program:h1:hush", outboxdom.SeverityHigh, "",
		nil, outboxdom.OutboxStatusPending, 0, 3, "", time.Time{}, nil, "", time.Time{}, time.Time{}, nil)
	s := &Service{}
	m := s.buildMessage(orgWide, entry, d)
	if strings.Contains(m.Title+m.Body, "Hush") || strings.Contains(m.Body, "program:h1") {
		t.Fatalf("org-wide message leaks the program: %q / %q", m.Title, m.Body)
	}
	if m := s.buildMessage(attached, entry, d); m.Title != "Hush Corp: XSS on shop" {
		t.Fatalf("program channel message scrubbed: %q", m.Title)
	}
}

func withDetails() *integration.NotificationExtension {
	ext := integration.NewNotificationExtension(shared.NewID())
	ext.SetIncludeDetails(true)
	return ext
}

// Minimal by default (A9): a channel that did not opt in to details gets the
// event type, severity and link, never the finding title or body.
func TestBuildMessage_MinimalUnlessChannelOptsIn(t *testing.T) {
	mk := func(ext *integration.NotificationExtension) *integration.IntegrationWithNotification {
		return integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "c", "",
			integration.CategoryNotification, integration.ProviderSlack, integration.StatusConnected, "", integration.AuthTypeToken,
			"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), ext)
	}
	entry := outboxdom.Reconstitute(outboxdom.NewID(), shared.NewID(), "new_finding", "finding", nil,
		"SQL injection on payroll.example.com", "asset payroll.example.com, CVE-2026-1", outboxdom.SeverityHigh, "https://app.example/findings/1",
		nil, outboxdom.OutboxStatusPending, 0, 3, "", time.Time{}, nil, "", time.Time{}, time.Time{}, nil)
	s := &Service{}

	for name, ext := range map[string]*integration.NotificationExtension{
		"new channel default": integration.NewNotificationExtension(shared.NewID()),
		"no extension":        nil,
	} {
		m := s.buildMessage(mk(ext), entry, bountyprogram.Delivery{})
		if strings.Contains(m.Title+m.Body, "payroll") || strings.Contains(m.Title+m.Body, "SQL") || strings.Contains(m.Body, "CVE") {
			t.Errorf("%s leaks details: %q / %q", name, m.Title, m.Body)
		}
		if m.Title != "New finding (high)" || m.URL != "https://app.example/findings/1" {
			t.Errorf("%s: title %q url %q", name, m.Title, m.URL)
		}
	}

	m := s.buildMessage(mk(withDetails()), entry, bountyprogram.Delivery{})
	if m.Title != "SQL injection on payroll.example.com" || !strings.Contains(m.Body, "CVE-2026-1") {
		t.Errorf("opted-in channel lost details: %q / %q", m.Title, m.Body)
	}
}

// A delivered link is absolute and names the event's organization, so a
// member of several organizations lands on it whichever one is selected; an
// outside address never gets the organization ID (pkg/weblink).
func TestBuildMessage_LinkIsAbsoluteAndNamesOrg(t *testing.T) {
	intg := integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "c", "",
		integration.CategoryNotification, integration.ProviderSlack, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), nil)
	tenant := shared.NewID()
	mk := func(url string) *outboxdom.Outbox {
		return outboxdom.Reconstitute(outboxdom.NewID(), tenant, "emerging_threat", "emerging_threat", nil,
			"t", "b", outboxdom.SeverityCritical, url,
			nil, outboxdom.OutboxStatusPending, 0, 3, "", time.Time{}, nil, "", time.Time{}, time.Time{}, nil)
	}
	s := &Service{}
	s.SetLinkBase("https://ctem.example.com/")
	cases := map[string]string{
		"/emerging-threats/abc":             "https://ctem.example.com/emerging-threats/abc?org=" + tenant.String(),
		"/emerging-threats?level=immediate": "https://ctem.example.com/emerging-threats?level=immediate&org=" + tenant.String(),
		"https://elsewhere.example/x":       "https://elsewhere.example/x",
		"//elsewhere.example/x":             "//elsewhere.example/x",
		"":                                  "",
	}
	for in, want := range cases {
		if got := s.buildMessage(intg, mk(in), bountyprogram.Delivery{}).URL; got != want {
			t.Errorf("link %q delivered as %q, want %q", in, got, want)
		}
	}
	// Without a base the link stays relative but still names the organization.
	if got := (&Service{}).buildMessage(intg, mk("/findings/1"), bountyprogram.Delivery{}).URL; got != "/findings/1?org="+tenant.String() {
		t.Errorf("no base: %q", got)
	}
}
