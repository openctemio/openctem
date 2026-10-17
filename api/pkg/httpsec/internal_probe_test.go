package httpsec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInternalProbeClient(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	ok := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ok.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ok.URL, http.StatusFound)
	}))
	defer redir.Close()

	c := InternalProbeClient(3 * time.Second)
	if c.Timeout != 3*time.Second {
		t.Fatalf("timeout = %v", c.Timeout)
	}
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("proxy must be disabled")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, redir.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: %d", resp.StatusCode)
	}
}
