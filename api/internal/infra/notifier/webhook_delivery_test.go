package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A destination that answers with a redirect is a failed delivery: the body
// never reaches the host the redirect names.
func TestWebhook_RefusesRedirects(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	c, err := NewWebhookClient(Config{WebhookURL: redirector.URL, AllowLoopback: true})
	if err != nil {
		t.Fatalf("new webhook client: %v", err)
	}
	res, err := c.Send(context.Background(), Message{Title: "t", Body: "b", Severity: "high", EventType: "new_finding"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res.Success {
		t.Fatal("a 307 answer must be a failed delivery")
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("redirect was followed: the other host got %d request(s)", n)
	}
}

// Every notifier client refuses redirects, not only the generic webhook.
func TestNotifierClients_RefuseRedirects(t *testing.T) {
	for name, hc := range map[string]*http.Client{
		"guarded":  newHTTPClient(time.Second, false),
		"loopback": newHTTPClient(time.Second, true),
	} {
		if hc.CheckRedirect == nil {
			t.Fatalf("%s client follows redirects", name)
		}
		if err := hc.CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse { //nolint:errorlint // sentinel identity is the contract
			t.Fatalf("%s client: CheckRedirect = %v, want ErrUseLastResponse", name, err)
		}
	}
	for name, mk := range map[string]func() (*http.Client, error){
		"slack": func() (*http.Client, error) {
			c, err := NewSlackClient(Config{WebhookURL: "https://hooks.example.com/x"})
			if err != nil {
				return nil, err
			}
			return c.httpClient, nil
		},
		"teams": func() (*http.Client, error) {
			c, err := NewTeamsClient(Config{WebhookURL: "https://hooks.example.com/x"})
			if err != nil {
				return nil, err
			}
			return c.httpClient, nil
		},
		"telegram": func() (*http.Client, error) {
			c, err := NewTelegramClient(Config{BotToken: "1:abc", ChatID: "1"})
			if err != nil {
				return nil, err
			}
			return c.httpClient, nil
		},
	} {
		hc, err := mk()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hc.CheckRedirect == nil {
			t.Fatalf("%s client follows redirects", name)
		}
	}
}

// The payload carries the real catalog type and its version, and the
// idempotency key in the body as well as the header.
func TestWebhook_PayloadCarriesEventType(t *testing.T) {
	var got WebhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewWebhookClient(Config{WebhookURL: srv.URL, AllowLoopback: true})
	if err != nil {
		t.Fatalf("new webhook client: %v", err)
	}
	occurred := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res, err := c.Send(context.Background(), Message{
		Title: "t", Body: "b", Severity: "high",
		EventType: "sensor.offline", EventVersion: 2,
		IdempotencyKey: "outbox-123", OccurredAt: occurred,
	})
	if err != nil || !res.Success {
		t.Fatalf("send: %v %+v", err, res)
	}
	if got.EventType != "sensor.offline" || got.EventVersion != 2 {
		t.Fatalf("event_type/version = %q/%d, want sensor.offline/2", got.EventType, got.EventVersion)
	}
	if got.IdempotencyKey != "outbox-123" {
		t.Fatalf("idempotency_key = %q", got.IdempotencyKey)
	}
	if got.OccurredAt != "2026-10-01T12:00:00Z" {
		t.Fatalf("occurred_at = %q", got.OccurredAt)
	}

	// A test delivery names itself.
	if _, err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("test connection: %v", err)
	}
	if got.EventType != TestEventType || got.EventVersion != 1 {
		t.Fatalf("test delivery event_type/version = %q/%d", got.EventType, got.EventVersion)
	}
}
