package notifier

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// The error text of a failed send is stored as the integration's
// status_message (readable with integrations:read), in the outbox and in
// notification_events. These tests pin that a credential carried in the URL
// or echoed by the receiver never reaches it.

const (
	telegramTestToken = "123456789:AAH-secret-telegram-bot-token"
	slackTestSecret   = "XXXXsecretSlackPathXXXX"
)

func TestTelegram_TransportErrorDoesNotLeakBotToken(t *testing.T) {
	// 127.0.0.1 is refused by the SSRF guard, so Do fails with a *url.Error
	// whose text would otherwise be "Post \"http://127.0.0.1:1/bot<token>/...\"".
	c, err := NewTelegramClient(Config{BotToken: telegramTestToken, ChatID: "42", APIEndpoint: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewTelegramClient: %v", err)
	}
	res, err := c.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure against a blocked address")
	}
	if strings.Contains(res.Error, telegramTestToken) || strings.Contains(res.Error, "/bot") {
		t.Fatalf("error leaks the bot token: %q", res.Error)
	}
	if !strings.Contains(res.Error, "127.0.0.1") {
		t.Fatalf("error should still name the endpoint host, got %q", res.Error)
	}
}

func TestTelegram_ProviderDescriptionIsScrubbedAndBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"description":"bad token ` + telegramTestToken + ` ` + strings.Repeat("x", 2000) + `"}`))
	}))
	defer srv.Close()
	c, err := NewTelegramClient(Config{BotToken: telegramTestToken, ChatID: "42", APIEndpoint: srv.URL})
	if err != nil {
		t.Fatalf("NewTelegramClient: %v", err)
	}
	c.httpClient = srv.Client() // reach the loopback test server
	res, err := c.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if strings.Contains(res.Error, telegramTestToken) {
		t.Fatalf("telegram description leaks the bot token: %q", res.Error)
	}
	if len(res.Error) > maxEchoedBody+64 {
		t.Fatalf("telegram description not bounded: %d bytes", len(res.Error))
	}
}

func TestSlackTeamsWebhook_TransportErrorDoesNotLeakWebhookURL(t *testing.T) {
	secretURL := "https://127.0.0.1:1/services/T000/B000/" + slackTestSecret + "?token=" + slackTestSecret
	for name, mk := range map[string]func() (Client, error){
		"slack": func() (Client, error) { return NewSlackClient(Config{WebhookURL: secretURL}) },
		"teams": func() (Client, error) { return NewTeamsClient(Config{WebhookURL: secretURL}) },
		// The generic webhook validates up front; build it with the test
		// opt-out, then put the SSRF-guarded client back so Do fails.
		"webhook": func() (Client, error) {
			c, err := NewWebhookClient(Config{WebhookURL: secretURL, AllowLoopback: true})
			if err != nil {
				return nil, err
			}
			c.httpClient = httpsec.SafeHTTPClient(5 * time.Second)
			return c, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := mk()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			res, err := c.Send(context.Background(), Message{Title: "t", Body: "b"})
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if res.Success {
				t.Fatal("expected failure against a blocked address")
			}
			if strings.Contains(res.Error, slackTestSecret) || strings.Contains(res.Error, "/services/") {
				t.Fatalf("error leaks the webhook URL: %q", res.Error)
			}
		})
	}
}

func TestWebhook_InvalidURLRejectionDoesNotEchoURL(t *testing.T) {
	// A control character makes url.Parse fail; its *url.Error repeats the
	// whole input, and this error becomes the integration's status_message.
	_, err := NewWebhookClient(Config{WebhookURL: "https://hooks.example.com/" + slackTestSecret + "\x7f"})
	if err == nil {
		t.Fatal("expected the URL to be rejected")
	}
	if strings.Contains(err.Error(), slackTestSecret) {
		t.Fatalf("rejection echoes the URL: %q", err.Error())
	}
}

func TestWebhookAndSplunk_ResponseBodyIsBoundedAndScrubbed(t *testing.T) {
	const hecToken = "hec-secret-token-value"
	huge := strings.Repeat("A", 10_000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(hecToken + " " + huge))
	}))
	defer srv.Close()

	wh, err := NewWebhookClient(Config{WebhookURL: srv.URL, AllowLoopback: true})
	if err != nil {
		t.Fatalf("NewWebhookClient: %v", err)
	}
	res, err := wh.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("webhook Send: %v", err)
	}
	if len(res.Error) > maxEchoedBody+64 || !strings.Contains(res.Error, "(truncated)") {
		t.Fatalf("webhook echoed body not bounded: %d bytes", len(res.Error))
	}

	sp, err := NewSplunkClient(Config{WebhookURL: srv.URL, Token: hecToken, AllowLoopback: true})
	if err != nil {
		t.Fatalf("NewSplunkClient: %v", err)
	}
	res, err = sp.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("splunk Send: %v", err)
	}
	if strings.Contains(res.Error, hecToken) {
		t.Fatalf("splunk error echoes the HEC token: %q", res.Error)
	}
	if len(res.Error) > maxEchoedBody+64 {
		t.Fatalf("splunk echoed body not bounded: %d bytes", len(res.Error))
	}
}

func TestTransportError(t *testing.T) {
	if got := transportError(nil); got != "" {
		t.Fatalf("nil error: got %q", got)
	}
	plain := errors.New("boom secret-x")
	if got := transportError(plain, "secret-x"); got != "boom "+redactedSecret {
		t.Fatalf("plain error not scrubbed: %q", got)
	}
	ue := &url.Error{Op: "Post", URL: "https://api.example.com/bot" + telegramTestToken + "/send?k=v", Err: errors.New("i/o timeout")}
	got := transportError(ue)
	if got != `Post https://api.example.com: i/o timeout` {
		t.Fatalf("url.Error not reduced to scheme+host: %q", got)
	}
	if got := redactURL("::not a url"); got != "<url>" {
		t.Fatalf("unparseable URL: got %q", got)
	}
}

func TestEchoBody_CutsOnRuneBoundary(t *testing.T) {
	body := []byte(strings.Repeat("é", maxEchoedBody)) // 2 bytes per rune
	got := echoBody(body)
	if !utf8.ValidString(got) {
		t.Fatalf("echoBody produced invalid UTF-8")
	}
	if !strings.HasSuffix(got, "(truncated)") {
		t.Fatalf("expected truncation marker, got suffix %q", got[len(got)-12:])
	}
	if got := echoBody([]byte("  short  ")); got != "short" {
		t.Fatalf("short body: got %q", got)
	}
}
