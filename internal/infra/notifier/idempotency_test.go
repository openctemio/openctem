package notifier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// F-6: verify every HTTP-based notifier (Slack, Teams, generic webhook)
// forwards Message.IdempotencyKey as the Idempotency-Key header. This is
// the guard that prevents duplicate Slack/Teams deliveries when the
// outbox worker crashes between provider ACK and status-update.
//
// Each test spins a local httptest server as the provider, pushes a
// Message with a known key, and asserts the expected header was seen.

func runProvider(t *testing.T, wantHeader string, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() { _, _ = io.Copy(io.Discard, r.Body); _ = r.Body.Close() }()
		got := r.Header.Get("Idempotency-Key")
		if got != wantHeader {
			t.Errorf("Idempotency-Key = %q, want %q", got, wantHeader)
		}
		_, _ = io.WriteString(w, body)
	})
	return httptest.NewServer(mux)
}

func TestSlack_SendsIdempotencyKey(t *testing.T) {
	srv := runProvider(t, "outbox-abc", "ok")
	defer srv.Close()

	client, err := NewSlackClient(Config{WebhookURL: srv.URL})
	if err != nil {
		t.Fatalf("new slack: %v", err)
	}
	_, err = client.Send(context.Background(), Message{
		Title:          "t",
		Body:           "b",
		Severity:       "low",
		IdempotencyKey: "outbox-abc",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestSlack_NoIdempotencyKey_HeaderAbsent(t *testing.T) {
	srv := runProvider(t, "", "ok")
	defer srv.Close()

	client, _ := NewSlackClient(Config{WebhookURL: srv.URL})
	_, err := client.Send(context.Background(), Message{
		Title: "t", Body: "b", Severity: "low",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestTeams_SendsIdempotencyKey(t *testing.T) {
	srv := runProvider(t, "outbox-xyz", "1")
	defer srv.Close()

	client, err := NewTeamsClient(Config{WebhookURL: srv.URL})
	if err != nil {
		t.Fatalf("new teams: %v", err)
	}
	_, err = client.Send(context.Background(), Message{
		Title:          "t",
		Body:           "b",
		Severity:       "low",
		IdempotencyKey: "outbox-xyz",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestWebhook_SendsIdempotencyKey(t *testing.T) {
	srv := runProvider(t, "outbox-123", "ok")
	defer srv.Close()

	client, err := NewWebhookClient(Config{WebhookURL: srv.URL})
	if err != nil {
		t.Fatalf("new webhook: %v", err)
	}
	_, err = client.Send(context.Background(), Message{
		Title:          "t",
		Body:           "b",
		Severity:       "low",
		IdempotencyKey: "outbox-123",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
}
