package outbox

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func entryWithStatus(status outboxdom.OutboxStatus) *outboxdom.Outbox {
	return outboxdom.Reconstitute(
		outboxdom.NewID(), shared.NewID(), "new_finding", "finding", nil,
		"Critical finding", "body", outboxdom.SeverityCritical, "",
		nil, status, 3, 3, "smtp timeout",
		time.Time{}, nil, "", time.Time{}, time.Time{}, nil,
	)
}

func TestAlertIfDeadLettered_EmitsErrorForDead(t *testing.T) {
	var buf bytes.Buffer
	s := &Service{log: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}

	s.alertIfDeadLettered(entryWithStatus(outboxdom.OutboxStatusDead))

	out := buf.String()
	if !strings.Contains(out, "dead-lettered") {
		t.Fatalf("expected dead-letter alert, got: %s", out)
	}
	if !strings.Contains(out, `"level":"ERROR"`) {
		t.Fatalf("dead-letter must log at ERROR, got: %s", out)
	}
	if !strings.Contains(out, "smtp timeout") {
		t.Fatalf("alert should include last_error, got: %s", out)
	}
}

func TestAlertIfDeadLettered_SilentForNonDead(t *testing.T) {
	for _, st := range []outboxdom.OutboxStatus{
		outboxdom.OutboxStatusCompleted,
		outboxdom.OutboxStatusPending,
		outboxdom.OutboxStatusFailed,
		outboxdom.OutboxStatusProcessing,
	} {
		var buf bytes.Buffer
		s := &Service{log: slog.New(slog.NewJSONHandler(&buf, nil))}
		s.alertIfDeadLettered(entryWithStatus(st))
		if buf.Len() != 0 {
			t.Fatalf("status %q must not dead-letter, got: %s", st, buf.String())
		}
	}
}

// The names of private programs are scrubbed from the message for an
// integration not attached to them, before the template (RFC-065 §15.4).
func TestBuildMessageScrubsPrivateProgramNames(t *testing.T) {
	program := shared.NewID()
	orgWide := integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "org", "",
		integration.CategoryNotification, integration.ProviderSlack, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), nil)
	attached := integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "prog", "",
		integration.CategoryNotification, integration.ProviderSlack, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), nil)
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
