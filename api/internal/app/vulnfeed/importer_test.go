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

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

const goldenDir = "../../../pkg/vulnbundle/testdata/golden"

func goldenRoot(t *testing.T) (string, time.Time) {
	t.Helper()
	root, err := os.ReadFile(filepath.Join(goldenDir, "root-keyid.txt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(goldenDir, vulnbundle.LatestFile))
	var env scannertemplate.Envelope
	_ = json.Unmarshal(raw, &env)
	var l vulnbundle.Latest
	_ = json.Unmarshal(env.Payload, &l)
	return strings.TrimSpace(string(root)), l.CreatedAt.Add(time.Hour)
}

type fakeStatus struct{ st *threatintel.SyncStatus }

func (f *fakeStatus) GetBySource(context.Context, string) (*threatintel.SyncStatus, error) {
	return f.st, nil
}
func (f *fakeStatus) GetAll(context.Context) ([]*threatintel.SyncStatus, error)     { return nil, nil }
func (f *fakeStatus) GetEnabled(context.Context) ([]*threatintel.SyncStatus, error) { return nil, nil }
func (f *fakeStatus) GetDueForSync(context.Context) ([]*threatintel.SyncStatus, error) {
	return nil, nil
}
func (f *fakeStatus) Update(_ context.Context, st *threatintel.SyncStatus) error {
	f.st = st
	return nil
}

type fakeCorpus struct {
	stored  []string
	applied []cvecorpus.CVE
	emptied int
	ranges  int
}

func (f *fakeCorpus) EmptiedRanges(_ context.Context, cves []cvecorpus.CVE) (int, error) {
	n := 0
	for _, c := range cves {
		if len(c.Ranges) == 0 && !c.Rejected {
			n += f.emptied
		}
	}
	return n, nil
}
func (f *fakeCorpus) ApplyPage(_ context.Context, cves []cvecorpus.CVE) (cvecorpus.PageResult, error) {
	f.applied = append(f.applied, cves...)
	n := 0
	for _, c := range cves {
		n += len(c.Ranges)
	}
	return cvecorpus.PageResult{Upserted: len(cves), RangesWritten: n}, nil
}
func (f *fakeCorpus) Counts(context.Context) (int, int, error) { return len(f.applied), f.ranges, nil }
func (f *fakeCorpus) CVEIDs(context.Context) ([]string, error) { return f.stored, nil }

type fakeCatalog struct{}

func (fakeCatalog) EnsureCurated(context.Context, []software.Curated) error { return nil }
func newTestImporter(t *testing.T, cfg Config, corpus *fakeCorpus, meta map[string]any) (*Importer, *fakeStatus) {
	t.Helper()
	st := threatintel.NewSyncStatus(SourceName, 24)
	if meta != nil {
		st.SetMetadata(meta)
	}
	fs := &fakeStatus{st: st}
	im, err := NewImporter(cfg, corpus, fs, fakeCatalog{}, logger.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return im, fs
}

func TestImport_FromBundleDir(t *testing.T) {
	root, now := goldenRoot(t)
	corpus := &fakeCorpus{}
	im, fs := newTestImporter(t, Config{RootKeyID: root, BundleDir: goldenDir}, corpus, nil)
	im.now = func() time.Time { return now }
	res, err := im.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ran || res.Sequence != 2 || res.Kind != vulnbundle.KindSnapshot || res.CVEs == 0 || res.Ranges == 0 {
		t.Fatalf("%+v", res)
	}
	meta := fs.st.Metadata()
	if toUint(meta["applied_sequence"]) != 2 || toUint(meta["keyset_version"]) != 1 || fs.st.LastSyncStatus() != threatintel.SyncStateSuccess {
		t.Fatalf("status %+v %s", meta, fs.st.LastSyncStatus())
	}
	// Nothing newer: no work.
	corpus.applied = nil
	res, err = im.Run(context.Background())
	if err != nil || res.Ran || len(corpus.applied) != 0 {
		t.Fatalf("second run: %+v %v", res, err)
	}
}

func TestImport_DeltaWhenBaseMatches(t *testing.T) {
	root, now := goldenRoot(t)
	corpus := &fakeCorpus{}
	im, _ := newTestImporter(t, Config{RootKeyID: root, BundleDir: goldenDir}, corpus, map[string]any{"applied_sequence": 1})
	im.now = func() time.Time { return now }
	res, err := im.Run(context.Background())
	if err != nil || res.Kind != vulnbundle.KindDelta || len(corpus.applied) == 0 || len(corpus.applied) > 50 {
		t.Fatalf("%+v %v (%d applied)", res, err, len(corpus.applied))
	}
}

func TestImport_RefusesAndRecords(t *testing.T) {
	root, now := goldenRoot(t)
	for name, tc := range map[string]struct {
		cfg  Config
		meta map[string]any
		now  time.Time
	}{
		"expired":             {Config{RootKeyID: root, BundleDir: goldenDir}, nil, now.Add(8 * 24 * time.Hour)},
		"key set rolled back": {Config{RootKeyID: root, BundleDir: goldenDir}, map[string]any{"keyset_version": 2}, now},
		"other root":          {Config{RootKeyID: "SHA256:" + strings.Repeat("a", 64), BundleDir: goldenDir}, nil, now},
	} {
		corpus := &fakeCorpus{}
		im, fs := newTestImporter(t, tc.cfg, corpus, tc.meta)
		im.now = func() time.Time { return tc.now }
		if _, err := im.Run(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(corpus.applied) != 0 || fs.st.LastSyncStatus() != threatintel.SyncStateFailed {
			t.Errorf("%s: applied %d, status %s", name, len(corpus.applied), fs.st.LastSyncStatus())
		}
	}
}

func TestImport_DisabledOrUnconfigured(t *testing.T) {
	root, now := goldenRoot(t)
	corpus := &fakeCorpus{}
	im, fs := newTestImporter(t, Config{BundleDir: goldenDir}, corpus, nil)
	im.now = func() time.Time { return now }
	if res, err := im.Run(context.Background()); err != nil || res.Ran {
		t.Fatal("ran without a pinned root")
	}
	im2, fs2 := newTestImporter(t, Config{RootKeyID: root, BundleDir: goldenDir}, corpus, nil)
	fs2.st.SetEnabled(false)
	im2.now = func() time.Time { return now }
	if res, err := im2.Run(context.Background()); err != nil || res.Ran {
		t.Fatal("ran while disabled")
	}
	_ = fs
}

func TestImport_SnapshotOverCorpusWithdrawsAndGuards(t *testing.T) {
	root, now := goldenRoot(t)
	// Applied 1 but not as the delta's base: applied 1 is the delta base, so
	// use a gap (applied 0 means first import); simulate a gap with
	// applied_sequence that is not the base but lower than 2: none exists,
	// so drive apply directly.
	corpus := &fakeCorpus{stored: []string{"CVE-1999-0001"}, ranges: 10000}
	im, _ := newTestImporter(t, Config{RootKeyID: root, BundleDir: goldenDir}, corpus, nil)
	im.now = func() time.Time { return now }
	var res Result
	if err := im.apply(context.Background(), []cvecorpus.CVE{{ID: "CVE-2021-0001"}}, true, &res); err != nil {
		t.Fatal(err)
	}
	if len(corpus.applied) != 2 || corpus.applied[1].ID != "CVE-1999-0001" || len(corpus.applied[1].Ranges) != 0 {
		t.Fatalf("withdrawal %+v", corpus.applied)
	}
	// The guard: every page empties ranges beyond 2 % of the corpus.
	corpus2 := &fakeCorpus{emptied: 1000, ranges: 10000}
	im2, _ := newTestImporter(t, Config{RootKeyID: root, BundleDir: goldenDir}, corpus2, nil)
	if err := im2.apply(context.Background(), []cvecorpus.CVE{{ID: "CVE-2021-0001"}}, false, &res); err == nil {
		t.Fatal("mass removal accepted")
	}
}

// Over HTTP: the record files are fetched only after the pointer verified,
// from the tag the pointer names.
func TestImport_OverHTTP(t *testing.T) {
	root, now := goldenRoot(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		name := filepath.Base(r.URL.Path)
		ok := (strings.HasPrefix(r.URL.Path, "/releases/latest/download/") && (name == vulnbundle.LatestFile || name == vulnbundle.KeySetFile)) ||
			strings.HasPrefix(r.URL.Path, "/releases/download/v1-2/")
		b, err := os.ReadFile(filepath.Join(goldenDir, name))
		if !ok || err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	corpus := &fakeCorpus{}
	im, _ := newTestImporter(t, Config{RootKeyID: root, BaseURL: "https://example.com/releases"}, corpus, nil)
	im.cfg.BaseURL, im.http, im.tmp = srv.URL+"/releases", srv.Client(), t.TempDir()
	im.now = func() time.Time { return now }
	res, err := im.Run(context.Background())
	if err != nil || res.Sequence != 2 {
		t.Fatalf("%+v %v (%v)", res, err, paths)
	}
	if len(paths) != 10 || paths[0] != "/releases/latest/download/keyset.dsse.json" {
		t.Fatalf("paths %v", paths)
	}
	// Already applied: only the key set and the pointer are fetched.
	paths = nil
	if _, err := im.Run(context.Background()); err != nil || len(paths) != 2 {
		t.Fatalf("second run fetched %v (%v)", paths, err)
	}
}

func TestNewImporterRefusesBadBaseURL(t *testing.T) {
	for _, u := range []string{"http://github.com/x", "https://127.0.0.1/x", "https://example.com/x?y=1", "ftp://x"} {
		if _, err := NewImporter(Config{RootKeyID: "x", BaseURL: u}, &fakeCorpus{}, &fakeStatus{}, fakeCatalog{}, logger.NewNop()); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
}
