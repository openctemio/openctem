package outbox

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	outboxdom "github.com/openctemio/api/pkg/domain/outbox"
	"github.com/openctemio/api/pkg/domain/shared"
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
