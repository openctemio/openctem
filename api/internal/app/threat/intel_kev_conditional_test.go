package threat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// The hourly KEV refresh repeats the validators of the last response, so an
// unchanged catalog costs a 304 and rewrites nothing.
func TestFetchKEVFrom_Conditional(t *testing.T) {
	const etag = `"v1"`
	const lastMod = "Mon, 19 Oct 2026 08:00:00 GMT"
	var gotINM, gotIMS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM, gotIMS = r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")
		if gotINM == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastMod)
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-0001","vulnerabilityName":"x","dateAdded":"2026-10-19"}]}`))
	}))
	defer srv.Close()
	s := NewIntelService(nil, logger.NewNop())
	s.httpClient = srv.Client() // the SSRF-guarded client refuses loopback

	entries, v, err := s.fetchKEVFrom(context.Background(), srv.URL, kevValidator{})
	if err != nil || len(entries) != 1 || v.ETag != etag || v.LastModified != lastMod {
		t.Fatalf("first fetch: %d entries, %+v, %v", len(entries), v, err)
	}
	if gotINM != "" || gotIMS != "" {
		t.Fatalf("first fetch was conditional: %q %q", gotINM, gotIMS)
	}

	_, v2, err := s.fetchKEVFrom(context.Background(), srv.URL, v)
	if !errors.Is(err, errKEVNotModified) || v2 != v {
		t.Fatalf("second fetch: %+v %v", v2, err)
	}
	if gotINM != etag || gotIMS != lastMod {
		t.Fatalf("validators not sent: %q %q", gotINM, gotIMS)
	}
}

// A 304 to an unconditional request is an error, not "unchanged".
func TestFetchKEVFrom_UnexpectedNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	s := NewIntelService(nil, logger.NewNop())
	s.httpClient = srv.Client()
	if _, _, err := s.fetchKEVFrom(context.Background(), srv.URL, kevValidator{}); err == nil || errors.Is(err, errKEVNotModified) {
		t.Fatalf("want an error, got %v", err)
	}
}

func TestReadKEVValidators(t *testing.T) {
	meta := map[string]any{kevValidatorsKey: map[string]any{
		kevURL:                   map[string]any{"etag": `"a"`, "modified": "Mon, 19 Oct 2026 08:00:00 GMT"},
		"https://evil.example/x": map[string]any{"etag": `"b"`},
		kevMirrorURL:             "not a map",
	}}
	got := readKEVValidators(meta)
	if len(got) != 1 || got[kevURL].ETag != `"a"` {
		t.Fatalf("validators: %+v", got)
	}
	if len(readKEVValidators(map[string]any{})) != 0 {
		t.Fatal("empty metadata gave validators")
	}
}
