package mcpoauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateMetadataDocumentURL(t *testing.T) {
	ok := []string{
		"https://app.example/client.json",
		"https://app.example:8443/oauth/client-metadata.json",
	}
	for _, u := range ok {
		if _, err := ValidateMetadataDocumentURL(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	bad := []string{
		"http://app.example/client.json", // not https
		"https://app.example",            // no path
		"https://app.example/",
		"https://user@app.example/c.json",
		"https://app.example/c.json?x=1",
		"https://app.example/c.json?",
		"https://app.example/c.json#f",
		"https://app.example/a/../c.json",
		"https://app.example/a/%2e%2e/c.json",
		"https://app.example/./c.json",
		"https://app.example/c .json",
		"https://app.example/" + strings.Repeat("a", 2100),
	}
	for _, u := range bad {
		if _, err := ValidateMetadataDocumentURL(u); !errors.Is(err, ErrInvalidClientMetadata) {
			t.Errorf("%s accepted", u)
		}
	}
}

func TestParseClientMetadataDocument(t *testing.T) {
	const id = "https://app.example/client.json"
	good := `{"client_id":"https://app.example/client.json","client_name":" Desk‮ Assistant ","redirect_uris":["http://127.0.0.1:3000/cb","https://app.example/cb"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	c, err := parseClientMetadataDocument(id, []byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Desk Assistant" {
		t.Errorf("name %q: bidi override and padding must be removed", c.Name)
	}
	for name, doc := range map[string]string{
		"not json":           `nope`,
		"client_id mismatch": `{"client_id":"https://app.example/client.json/","client_name":"x","redirect_uris":["https://a.example/cb"]}`,
		"no name":            `{"client_id":"https://app.example/client.json","redirect_uris":["https://a.example/cb"]}`,
		"no redirect":        `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":[]}`,
		"custom scheme":      `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":["myapp://cb"]}`,
		"http non-loopback":  `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":["http://app.example/cb"]}`,
		"secret":             `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":["https://a.example/cb"],"client_secret":"s"}`,
		"secret auth method": `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"no code grant":      `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":["https://a.example/cb"],"grant_types":["client_credentials"]}`,
		"fragment redirect":  `{"client_id":"https://app.example/client.json","client_name":"x","redirect_uris":["https://a.example/cb#x"]}`,
	} {
		if _, err := parseClientMetadataDocument(id, []byte(doc)); !errors.Is(err, ErrInvalidClientMetadata) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCacheLifetime(t *testing.T) {
	for cc, want := range map[string]time.Duration{
		"":                      cimdDefaultCache,
		"max-age=600":           10 * time.Minute,
		"public, max-age=10":    cimdMinCache,
		"max-age=999999":        cimdMaxCache,
		"no-store":              cimdMinCache,
		"max-age=600, no-cache": cimdMinCache,
		"max-age=garbage":       cimdDefaultCache,
	} {
		if got := cacheLifetime(cc); got != want {
			t.Errorf("cacheLifetime(%q) = %v, want %v", cc, got, want)
		}
	}
}

// The fetch refuses redirects, oversized bodies and non-200 answers. (The
// SSRF guard itself is pkg/httpsec's, tested there; a local test server is
// reached here through a plain client.)
func TestFetchRules(t *testing.T) {
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect/client.json":
			http.Redirect(w, r, "/client.json", http.StatusFound)
		case "/missing/client.json":
			http.NotFound(w, r)
		default:
			w.Header().Set("Cache-Control", "max-age=900")
			_, _ = w.Write([]byte(body))
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	f := newMetadataFetcherWithClient(srv.Client(), func() time.Time { return now })
	fetch := func(path string) error {
		id := srv.URL + path
		body = `{"client_id":"` + id + `","client_name":"T","redirect_uris":["https://a.example/cb"]}`
		_, err := f.fetchURL(context.Background(), id)
		return err
	}
	if err := fetch("/client.json"); err != nil {
		t.Fatalf("plain fetch: %v", err)
	}
	if err := fetch("/redirect/client.json"); err == nil {
		t.Error("redirect followed")
	}
	if err := fetch("/missing/client.json"); err == nil {
		t.Error("404 accepted")
	}
	id := srv.URL + "/big.json"
	body = `{"client_id":"` + id + `","client_name":"` + strings.Repeat("x", cimdMaxBytes) + `","redirect_uris":["https://a.example/cb"]}`
	if _, err := f.fetchURL(context.Background(), id); err == nil {
		t.Error("oversized document accepted")
	}
	id = srv.URL + "/client.json"
	body = `{"client_id":"` + id + `","client_name":"T","redirect_uris":["https://a.example/cb"]}`
	c, err := f.fetchURL(context.Background(), id)
	if err != nil || c.ExpiresAt == nil || !c.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("cache expiry: %+v %v", c, err)
	}
}

// The production fetcher refuses private addresses before connecting.
func TestFetchRefusesPrivateAddresses(t *testing.T) {
	f := NewHTTPMetadataFetcher()
	for _, id := range []string{
		"https://127.0.0.1/client.json",
		"https://169.254.169.254/latest/client.json",
		"https://10.0.0.1/client.json",
		"https://[::1]/client.json",
	} {
		if _, err := f.Fetch(context.Background(), id); err == nil {
			t.Errorf("%s fetched", id)
		}
	}
}
