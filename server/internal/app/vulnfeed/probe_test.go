package vulnfeed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// goldenServer serves the golden (v1) release under /releases/latest/download
// and answers status for everything else.
func goldenServer(t *testing.T, status int, paths *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if paths != nil {
			*paths = append(*paths, r.URL.Path)
		}
		name := filepath.Base(r.URL.Path)
		b, err := os.ReadFile(filepath.Join(goldenDir, name))
		if status != http.StatusOK || err != nil || !strings.HasPrefix(r.URL.Path, "/releases/latest/download/") {
			code := status
			if code == http.StatusOK {
				code = http.StatusNotFound
			}
			w.WriteHeader(code)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func probeImporter(t *testing.T, root string, now time.Time, srv *httptest.Server) (*Importer, *fakeCorpus) {
	t.Helper()
	corpus := &fakeCorpus{}
	im, _ := newTestImporter(t, Config{RootKeyID: root, BaseURL: "https://example.com/releases"}, corpus, nil)
	im.http, im.tmp, im.now = srv.Client(), t.TempDir(), func() time.Time { return now }
	return im, corpus
}

// The test fetch verifies the key set and the pointer against the pinned
// root, fetches nothing else and writes nothing.
func TestProbe_VerifiesWithoutImporting(t *testing.T) {
	root, now := goldenRoot(t)
	var paths []string
	srv := goldenServer(t, http.StatusOK, &paths)
	im, corpus := probeImporter(t, root, now, srv)
	res := im.Probe(context.Background(), srv.URL+"/releases", nil)
	if len(res) != 1 || !res[0].OK || res[0].Format != "v1" || res[0].Sequence != 2 || res[0].Error != "" {
		t.Fatalf("probe: %+v", res)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/releases/latest/download/") {
			t.Fatalf("the probe fetched beyond the pointer: %v", paths)
		}
	}
	if len(corpus.applied) != 0 {
		t.Fatal("the probe wrote the corpus")
	}
}

// A key set signed by another root is refused: the pinned root is the only
// trust, whatever the address.
func TestProbe_WrongRootRefused(t *testing.T) {
	_, now := goldenRoot(t)
	srv := goldenServer(t, http.StatusOK, nil)
	im, _ := probeImporter(t, "SHA256:"+strings.Repeat("0", 64), now, srv)
	res := im.Probe(context.Background(), srv.URL+"/releases", nil)
	if len(res) != 1 || res[0].OK || res[0].Error != ProbeNotVerified || res[0].Cause != ProbeRootMismatch {
		t.Fatalf("probe: %+v", res)
	}
}

// Fetch failures are classified for the server log (Cause) but answer one
// public code, so the test tells no 404 from a 502 or a dead host; a mirror
// is tested at its own path with no v1 fallback.
func TestProbe_FetchFailures(t *testing.T) {
	root, now := goldenRoot(t)
	notFound := goldenServer(t, http.StatusNotFound, nil)
	im, _ := probeImporter(t, root, now, notFound)
	if res := im.Probe(context.Background(), notFound.URL+"/releases", nil); res[0].Error != ProbeNotVerified || res[0].Cause != ProbeNotFound {
		t.Fatalf("404: %+v", res)
	}
	broken := goldenServer(t, http.StatusBadGateway, nil)
	im, _ = probeImporter(t, root, now, broken)
	if res := im.Probe(context.Background(), broken.URL+"/releases", nil); res[0].Error != ProbeNotVerified || res[0].Cause != ProbeHTTPError || res[0].HTTPStatus != http.StatusBadGateway {
		t.Fatalf("502: %+v", res)
	}
	good := goldenServer(t, http.StatusOK, nil)
	im, _ = probeImporter(t, root, now, good)
	// The mirror serves the key set but no chunked pointer (v1 only): not a
	// usable mirror.
	res := im.Probe(context.Background(), good.URL+"/releases", []string{good.URL + "/releases/latest/download"})
	if len(res) != 2 || !res[0].OK || res[1].OK || res[1].Error != ProbeNotVerified || res[1].Cause != ProbeNotFound {
		t.Fatalf("mirror: %+v", res)
	}
}

// The answer never carries the cause or an HTTP status: only origin, ok and
// the public code reach the console.
func TestProbe_AnswerCarriesNoCause(t *testing.T) {
	root, now := goldenRoot(t)
	broken := goldenServer(t, http.StatusBadGateway, nil)
	im, _ := probeImporter(t, root, now, broken)
	res := im.Probe(context.Background(), broken.URL+"/releases", nil)
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"502", "http_error", "http_status", "cause", "not_found"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("answer leaks %q: %s", leak, b)
		}
	}
	if !strings.Contains(string(b), `"error":"not_verified"`) {
		t.Fatalf("answer: %s", b)
	}
}

func TestProbe_NotConfigured(t *testing.T) {
	_, now := goldenRoot(t)
	srv := goldenServer(t, http.StatusOK, nil)
	im, _ := probeImporter(t, "", now, srv)
	if res := im.Probe(context.Background(), srv.URL+"/releases", nil); res[0].Error != ProbeNotConfigured {
		t.Fatalf("probe: %+v", res)
	}
}

type staticSources struct {
	base    string
	mirrors []string
}

func (s staticSources) FeedSources(context.Context) (string, []string) { return s.base, s.mirrors }

// A console change reaches the next run: new origins replace the old ones
// and drop the cached network fetcher; refused values never apply.
func TestRefreshOrigins(t *testing.T) {
	im, _ := newTestImporter(t, Config{RootKeyID: "x", BaseURL: "https://example.com/releases"}, &fakeCorpus{}, nil)
	im.WithChunks(nil, Transfer{Mirrors: []string{"https://old.example.com/feed"}, CacheDir: t.TempDir()})
	if _, err := im.fetcherV2(); err != nil {
		t.Fatal(err)
	}
	im.WithSources(staticSources{base: "https://feed.example.org/releases/", mirrors: []string{"https://m1.example.org/x/", "http://plain.example.org/x"}})
	im.refreshOrigins(context.Background())
	if im.BaseURL() != "https://feed.example.org/releases" {
		t.Fatalf("base %q", im.BaseURL())
	}
	if len(im.transfer.Mirrors) != 1 || im.transfer.Mirrors[0] != "https://m1.example.org/x" {
		t.Fatalf("mirrors %v (an http mirror must be skipped)", im.transfer.Mirrors)
	}
	if im.fetcher != nil {
		t.Fatal("the fetcher of the old origins is kept")
	}
	for _, bad := range []string{"http://feed.example.org/r", "https://127.0.0.1/r", "https://u:p@feed.example.org/r", "https://feed.example.org/r?x=1", ""} {
		im.WithSources(staticSources{base: bad})
		im.refreshOrigins(context.Background())
		if im.BaseURL() != "https://feed.example.org/releases" {
			t.Fatalf("%q applied: %q", bad, im.BaseURL())
		}
	}
	// A bundle directory is the only origin: sources are never read.
	im2, _ := newTestImporter(t, Config{RootKeyID: "x", BundleDir: t.TempDir()}, &fakeCorpus{}, nil)
	im2.WithSources(staticSources{base: "https://feed.example.org/releases"})
	im2.refreshOrigins(context.Background())
	if im2.BaseURL() == "https://feed.example.org/releases" {
		t.Fatal("a bundle directory platform took a network origin")
	}
}

func TestValidateOrigin(t *testing.T) {
	ok := []string{"https://github.com/openctemio/vulnfeed-bundles/releases", "https://mirror.example.com/vulnfeed"}
	for _, u := range ok {
		if err := ValidateOrigin(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	bad := []string{"", "http://github.com/x", "https://user:pw@github.com/x", "https://github.com/x?a=1", "https://github.com/x#f",
		"https://github.com/x?", "https://10.0.0.1/x", "https://[::1]/x", "https://169.254.169.254/latest", "ftp://github.com/x",
		"https:github.com", "https://github.com/" + strings.Repeat("a", MaxOriginLength)}
	for _, u := range bad {
		if err := ValidateOrigin(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
