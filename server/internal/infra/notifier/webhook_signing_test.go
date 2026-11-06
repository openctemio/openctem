package notifier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/webhooksig"
)

type captured struct {
	header http.Header
	body   []byte
}

func captureServer(t *testing.T) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.header = r.Header.Clone()
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// A signed delivery verifies with the reference receiver check, over the
// exact bytes received, with webhook-id equal to the idempotency key.
func TestWebhook_SignedDeliveryVerifies(t *testing.T) {
	srv, got := captureServer(t)
	secret, _ := webhooksig.GenerateSecret()
	c, err := NewWebhookClient(Config{WebhookURL: srv.URL, AllowLoopback: true, SigningSecrets: []string{secret}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Send(context.Background(), Message{Title: "t", Body: "b", Severity: "high", EventType: "new_finding", IdempotencyKey: "outbox-42"})
	if err != nil || !res.Success {
		t.Fatalf("send: %v %+v", err, res)
	}
	if got.header.Get(webhooksig.HeaderID) != "outbox-42" {
		t.Fatalf("webhook-id %q", got.header.Get(webhooksig.HeaderID))
	}
	if err := webhooksig.Verify(secret, got.header.Get, got.body, time.Now(), webhooksig.DefaultTolerance); err != nil {
		t.Fatalf("receiver verification: %v", err)
	}
	other, _ := webhooksig.GenerateSecret()
	if err := webhooksig.Verify(other, got.header.Get, got.body, time.Now(), webhooksig.DefaultTolerance); err == nil {
		t.Fatal("verified under a secret the delivery was not signed with")
	}
}

// During a rotation overlap the delivery carries both signatures and each
// secret verifies it.
func TestWebhook_OverlapCarriesBothSignatures(t *testing.T) {
	srv, got := captureServer(t)
	cur, _ := webhooksig.GenerateSecret()
	prev, _ := webhooksig.GenerateSecret()
	c, err := NewWebhookClient(Config{WebhookURL: srv.URL, AllowLoopback: true, SigningSecrets: []string{cur, prev}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), Message{Title: "t", Body: "b", EventType: "new_finding", IdempotencyKey: "outbox-1"}); err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(got.header.Get(webhooksig.HeaderSignature))); n != 2 {
		t.Fatalf("%d signatures", n)
	}
	for _, s := range []string{cur, prev} {
		if err := webhooksig.Verify(s, got.header.Get, got.body, time.Now(), webhooksig.DefaultTolerance); err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
}

// Without a secret the delivery is unsigned but still carries an id and a
// timestamp; a test delivery gets a fresh id.
func TestWebhook_UnsignedWithoutSecret(t *testing.T) {
	srv, got := captureServer(t)
	c, err := NewWebhookClient(Config{WebhookURL: srv.URL, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.header.Get(webhooksig.HeaderSignature) != "" {
		t.Fatal("signed without a secret")
	}
	if !strings.HasPrefix(got.header.Get(webhooksig.HeaderID), "msg_") || got.header.Get(webhooksig.HeaderTimestamp) == "" {
		t.Fatalf("headers %v", got.header)
	}
}

func TestWebhook_MalformedSecretRefused(t *testing.T) {
	if _, err := NewWebhookClient(Config{WebhookURL: "https://hooks.example.com/x", SigningSecrets: []string{"plain"}}); err == nil {
		t.Fatal("a malformed signing secret was accepted")
	}
}
