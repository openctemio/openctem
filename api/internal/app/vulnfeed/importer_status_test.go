package vulnfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/feedstatus"
)

func viewOf(t *testing.T, fs *fakeStatus, now time.Time) feedstatus.View {
	t.Helper()
	return feedstatus.Build(fs.st, 0, now)
}

// The collector has published nothing: the key set answers 404. The feed is
// waiting for the publisher, not failed, and turns stale after three days.
func TestImport_PublisherEmptyIsWaiting(t *testing.T) {
	root, now := goldenRoot(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	im, fs := newTestImporter(t, Config{RootKeyID: root, BaseURL: "https://example.com/releases"}, &fakeCorpus{}, nil)
	im.cfg.BaseURL, im.http, im.tmp = srv.URL+"/releases", srv.Client(), t.TempDir()
	im.now = func() time.Time { return now }
	if _, err := im.Run(context.Background()); err == nil {
		t.Fatal("a 404 on the key set was accepted")
	}
	v := viewOf(t, fs, time.Now())
	if v.State != feedstatus.StateWaitingForPublisher || v.ErrorCode != feedstatus.CodePublisherEmpty {
		t.Fatalf("state %s code %s", v.State, v.ErrorCode)
	}
	if !strings.Contains(v.LastError, "status 404") {
		t.Fatalf("raw text lost: %q", v.LastError)
	}
	if got := viewOf(t, fs, time.Now().Add(4*24*time.Hour)).State; got != feedstatus.StateStale {
		t.Fatalf("after 4 days: %s, want stale", got)
	}
}

// A bundle the platform refuses to trust is "refused", with a code.
func TestImport_RefusalsAreClassified(t *testing.T) {
	root, now := goldenRoot(t)
	for name, tc := range map[string]struct {
		cfg  Config
		meta map[string]any
		now  time.Time
		code string
	}{
		"expired":             {Config{RootKeyID: root, BundleDir: goldenDir}, nil, now.Add(8 * 24 * time.Hour), feedstatus.CodeExpired},
		"key set rolled back": {Config{RootKeyID: root, BundleDir: goldenDir}, map[string]any{"keyset_version": 2}, now, feedstatus.CodeKeysetRollback},
		"other root":          {Config{RootKeyID: "SHA256:" + strings.Repeat("a", 64), BundleDir: goldenDir}, nil, now, feedstatus.CodeSignatureInvalid},
	} {
		im, fs := newTestImporter(t, tc.cfg, &fakeCorpus{}, tc.meta)
		im.now = func() time.Time { return tc.now }
		_, _ = im.Run(context.Background())
		v := viewOf(t, fs, time.Now())
		if v.State != feedstatus.StateRefused || v.ErrorCode != tc.code {
			t.Errorf("%s: state %s code %q, want refused %q", name, v.State, v.ErrorCode, tc.code)
		}
	}
}

// A good import is up to date with the bundle's data date, sequence and
// sources; a later run with nothing newer keeps it that way and clears an
// earlier failure.
func TestImport_SuccessAndCheckedClearFailure(t *testing.T) {
	root, now := goldenRoot(t)
	im, fs := newTestImporter(t, Config{RootKeyID: root, BundleDir: goldenDir}, &fakeCorpus{}, nil)
	im.now = func() time.Time { return now }
	if _, err := im.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	v := viewOf(t, fs, now)
	if v.State != feedstatus.StateUpToDate || v.Bundle == nil || v.Bundle.AppliedSequence == 0 || len(v.Bundle.Sources) == 0 {
		t.Fatalf("view %+v bundle %+v", v, v.Bundle)
	}
	if v.Bundle.RootKeyID != root {
		t.Fatalf("root key id %q", v.Bundle.RootKeyID)
	}
	fs.st.MarkSyncFailedWith("boom", feedstatus.CodeFailed, nil)
	if _, err := im.Run(context.Background()); err != nil { // nothing newer
		t.Fatal(err)
	}
	if v := viewOf(t, fs, now); v.State != feedstatus.StateUpToDate || v.ErrorCode != "" || v.LastError != "" {
		t.Fatalf("failure not cleared: %+v", v)
	}
}
