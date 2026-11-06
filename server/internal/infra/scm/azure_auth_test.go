package scm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newAzureServerClientForTest points an on-prem style AzureClient at an
// httptest server, bypassing the httpsec guards that reject loopback.
func newAzureServerClientForTest(baseURL string) *AzureClient {
	return &AzureClient{
		config:     Config{Provider: ProviderAzure, AccessToken: "bad"},
		httpClient: &http.Client{Timeout: 5 * time.Second},
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		isCloud:    false,
	}
}

// Azure DevOps answers a rejected PAT with 203 and a full HTML sign-in page.
// That used to land verbatim in the integration's status message.
func TestAzureGetUser_203IsAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>Azure DevOps Services | Sign In</title></head></html>"))
	}))
	defer srv.Close()

	_, err := newAzureServerClientForTest(srv.URL).GetUser(context.Background())
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed for a 203 sign-in page, got %v", err)
	}
	if strings.Contains(err.Error(), "<html") {
		t.Fatalf("error must not carry the HTML page: %v", err)
	}
}

func TestAzureBodySnippet(t *testing.T) {
	long := strings.Repeat("x ", 500)
	got := azureBodySnippet([]byte(long))
	if len(got) > 210 {
		t.Fatalf("snippet too long: %d", len(got))
	}
	if got := azureBodySnippet([]byte("  a\r\n\tb  ")); got != "a b" {
		t.Fatalf("whitespace not collapsed: %q", got)
	}
}
