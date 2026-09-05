package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captured holds what the fake HEC receiver saw for a single request.
type capturedHEC struct {
	path    string
	auth    string
	payload map[string]any
}

// fakeHEC spins a local Splunk HEC receiver and records the last request.
// AllowLoopback must be set on the client to reach 127.0.0.1 through the
// SSRF guard.
func fakeHEC(t *testing.T, status int) (*httptest.Server, *capturedHEC) {
	t.Helper()
	cap := &capturedHEC{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.path = r.URL.Path
		cap.auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &cap.payload)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	return srv, cap
}

func TestSplunk_SendBuildsHECEnvelope(t *testing.T) {
	srv, cap := fakeHEC(t, http.StatusOK)
	defer srv.Close()

	c, err := NewSplunkClient(Config{
		WebhookURL:    srv.URL, // bare host — client appends the collector path
		Token:         "hec-secret",
		Index:         "ctem",
		Sourcetype:    "openctem:finding",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("new splunk: %v", err)
	}

	res, err := c.Send(context.Background(), Message{
		Title:    "New Critical Finding",
		Body:     "SQLi on api.example.com",
		Severity: "critical",
		URL:      "https://app/finding/1",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if res == nil || !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	// Endpoint path was normalized to the HEC event collector.
	if !strings.HasSuffix(cap.path, "/services/collector/event") {
		t.Fatalf("path = %q, want .../services/collector/event", cap.path)
	}
	// Token rides the Splunk auth scheme, not the body.
	if cap.auth != "Splunk hec-secret" {
		t.Fatalf("Authorization = %q, want %q", cap.auth, "Splunk hec-secret")
	}
	// Envelope carries routing metadata + the event body.
	if cap.payload["sourcetype"] != "openctem:finding" {
		t.Fatalf("sourcetype = %v, want openctem:finding", cap.payload["sourcetype"])
	}
	if cap.payload["index"] != "ctem" {
		t.Fatalf("index = %v, want ctem", cap.payload["index"])
	}
	event, ok := cap.payload["event"].(map[string]any)
	if !ok {
		t.Fatalf("event body missing/not an object: %v", cap.payload["event"])
	}
	if event["title"] != "New Critical Finding" || event["severity"] != "critical" {
		t.Fatalf("event body wrong: %v", event)
	}
}

func TestSplunk_FullPathURLNotDoubled(t *testing.T) {
	srv, cap := fakeHEC(t, http.StatusOK)
	defer srv.Close()

	c, err := NewSplunkClient(Config{
		WebhookURL:    srv.URL + "/services/collector/event",
		Token:         "t",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("new splunk: %v", err)
	}
	if _, err := c.Send(context.Background(), Message{Title: "x"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if strings.Contains(cap.path, "/services/collector/event/services/collector") {
		t.Fatalf("collector path was doubled: %q", cap.path)
	}
}

func TestSplunk_Non2xxIsFailure(t *testing.T) {
	srv, _ := fakeHEC(t, http.StatusForbidden)
	defer srv.Close()

	c, _ := NewSplunkClient(Config{WebhookURL: srv.URL, Token: "bad", AllowLoopback: true})
	res, err := c.Send(context.Background(), Message{Title: "x"})
	if err != nil {
		t.Fatalf("transport error not expected: %v", err)
	}
	if res.Success {
		t.Fatal("expected failure on 403")
	}
}

func TestSplunk_RequiresURLAndToken(t *testing.T) {
	if _, err := NewSplunkClient(Config{Token: "t"}); err == nil {
		t.Fatal("expected error when HEC URL missing")
	}
	if _, err := NewSplunkClient(Config{WebhookURL: "https://splunk:8088"}); err == nil {
		t.Fatal("expected error when HEC token missing")
	}
}

func TestSplunk_SSRFGuardRejectsMetadataIP(t *testing.T) {
	// Without AllowLoopback the tenant-controlled URL is validated; an
	// internal/metadata target must be refused at construction.
	if _, err := NewSplunkClient(Config{WebhookURL: "http://169.254.169.254", Token: "t"}); err == nil {
		t.Fatal("expected SSRF guard to reject cloud-metadata IP")
	}
}

func TestSplunk_FactoryWiresProvider(t *testing.T) {
	c, err := (&ClientFactory{}).CreateClient(Config{
		Provider:      ProviderSplunk,
		WebhookURL:    "https://splunk.example.com:8088",
		Token:         "t",
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if c.Provider() != "splunk" {
		t.Fatalf("provider = %q, want splunk", c.Provider())
	}
}
