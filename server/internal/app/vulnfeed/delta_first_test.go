package vulnfeed

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// A release made in the test: a signed snapshot and a delta at sequence
// seq, the delta starting at seq-1, as the hourly collector publishes.
const (
	tProduct  = `{"key":"cpe:a:f5:nginx","part":"a","vendor":"f5","name":"nginx","cpe_vendor":"f5","cpe_product":"nginx"}`
	tVulnSnap = `{"id":"CVE-2021-23017","status":"Analyzed","description":"snapshot","severity":"high","cwes":["CWE-193"]}`
	tVulnOld  = `{"id":"CVE-2021-0001","status":"Analyzed","description":"snapshot only","severity":"low","cwes":[]}`
	tVulnDel  = `{"id":"CVE-2021-23017","status":"Analyzed","description":"delta","severity":"high","cwes":["CWE-193"]}`
	tRange    = `{"vuln":"CVE-2021-23017","product":"cpe:a:f5:nginx","scheme":"generic","end":"1.20.1","start_incl":false,"end_incl":false,"edition":"","target":"","source":"nvd"}`
)

type release struct {
	root  string
	files map[string][]byte // asset name -> bytes
	now   time.Time
}

func makeRelease(t *testing.T, seq uint64) release {
	t.Helper()
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now().UTC().Truncate(time.Second)
	ks, err := feedsign.SignKeySet(rootPriv, feedsign.KeySetType{PayloadType: vulnbundle.KeySetPayloadType, Kind: vulnbundle.KeySetKind,
		MaxValidity: vulnbundle.MaxKeySetValidity}, 1, now.Add(-time.Hour), now.Add(30*24*time.Hour), pub)
	if err != nil {
		t.Fatal(err)
	}
	r := release{root: jobsign.KeyID(rootPub), files: map[string][]byte{vulnbundle.KeySetFile: ks}, now: now}
	part := func(kind string, base uint64, vulns []string) {
		m := vulnbundle.Manifest{Schema: vulnbundle.ManifestSchema, Sequence: seq, Kind: kind, BaseSequence: base,
			CreatedAt: now, ExpiresAt: now.Add(vulnbundle.MaxBundleValidity)}
		for i, lines := range [][]string{{tProduct}, vulns, {tRange}} {
			name := vulnbundle.FileName(kind, []string{"products", "vulns", "ranges"}[i])
			var b strings.Builder
			gz := gzip.NewWriter(&b)
			for _, l := range lines {
				_, _ = gz.Write([]byte(l + "\n"))
			}
			_ = gz.Close()
			r.files[name] = []byte(b.String())
			sum := sha256.Sum256(r.files[name])
			m.Files = append(m.Files, vulnbundle.File{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(b.Len()), Records: len(lines)})
		}
		mp, _ := json.Marshal(m)
		r.files[vulnbundle.ManifestName(kind)], _ = feedsign.Sign(priv, vulnbundle.ManifestPayloadType, mp)
	}
	part(vulnbundle.KindSnapshot, 0, []string{tVulnOld, tVulnSnap})
	part(vulnbundle.KindDelta, seq-1, []string{tVulnDel})
	lp, _ := json.Marshal(vulnbundle.Latest{Schema: vulnbundle.LatestSchema, Sequence: seq, Tag: vulnbundle.Tag(seq),
		Snapshot: vulnbundle.ManifestName(vulnbundle.KindSnapshot), Delta: vulnbundle.ManifestName(vulnbundle.KindDelta),
		BaseSequence: seq - 1, CreatedAt: now, ExpiresAt: now.Add(vulnbundle.MaxBundleValidity)})
	r.files[vulnbundle.LatestFile], _ = feedsign.Sign(priv, vulnbundle.LatestPayloadType, lp)
	return r
}

// serve publishes the release like GitHub: the pointer and key set under
// latest/download, every asset under download/<tag>. It records each path.
func (r release) serve(t *testing.T, seq uint64) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	tag := "/releases/download/" + vulnbundle.Tag(seq) + "/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		paths = append(paths, req.URL.Path)
		mu.Unlock()
		name := filepath.Base(req.URL.Path)
		b, ok := r.files[name]
		latest := strings.HasPrefix(req.URL.Path, "/releases/latest/download/") && (name == vulnbundle.LatestFile || name == vulnbundle.KeySetFile)
		if !ok || (!latest && !strings.HasPrefix(req.URL.Path, tag)) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func httpImporter(t *testing.T, r release, srv *httptest.Server, corpus *fakeCorpus, applied uint64) (*Importer, *fakeStatus) {
	t.Helper()
	var meta map[string]any
	if applied != 0 {
		meta = map[string]any{"applied_sequence": applied, "keyset_version": 1}
	}
	im, fs := newTestImporter(t, Config{RootKeyID: r.root, BaseURL: "https://example.com/releases"}, corpus, meta)
	im.cfg.BaseURL, im.http, im.tmp = srv.URL+"/releases", srv.Client(), t.TempDir()
	im.now = func() time.Time { return r.now.Add(time.Minute) }
	return im, fs
}

func fetchedKinds(paths []string) (snapshot, delta int) {
	for _, p := range paths {
		switch name := filepath.Base(p); {
		case strings.HasPrefix(name, "snapshot"):
			snapshot++
		case strings.HasPrefix(name, "delta"):
			delta++
		}
	}
	return snapshot, delta
}

// A platform that applied the previous release fetches and applies the
// delta only: no snapshot file is requested.
func TestImport_DeltaOnlyWithoutSnapshot(t *testing.T) {
	r := makeRelease(t, 42)
	srv, paths := r.serve(t, 42)
	corpus := &fakeCorpus{}
	im, fs := httpImporter(t, r, srv, corpus, 41)
	res, err := im.Run(context.Background())
	if err != nil || !res.Ran || res.Kind != vulnbundle.KindDelta || res.Sequence != 42 {
		t.Fatalf("%+v %v", res, err)
	}
	snap, delta := fetchedKinds(paths())
	if snap != 0 || delta != 4 || len(paths()) != 6 {
		t.Fatalf("fetched %v", paths())
	}
	if len(corpus.applied) != 1 || corpus.applied[0].Description != "delta" {
		t.Fatalf("applied %+v", corpus.applied)
	}
	if toUint(fs.st.Metadata()["applied_sequence"]) != 42 || fs.st.Metadata()["kind"] != vulnbundle.KindDelta {
		t.Fatalf("status %+v", fs.st.Metadata())
	}
}

// A delta whose base is not the applied sequence is not used: the
// snapshot is fetched and applied, and the delta is never requested. This
// covers a platform more than 72 releases (the collector's retention)
// behind: it needs only the newest release's snapshot, never an old one.
func TestImport_BaseMismatchTakesSnapshot(t *testing.T) {
	for name, tc := range map[string]struct{ seq, applied uint64 }{
		"one release missed":           {42, 40},
		"more than 72 releases behind": {200, 200 - 74},
		"first import":                 {42, 0},
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRelease(t, tc.seq)
			srv, paths := r.serve(t, tc.seq)
			corpus := &fakeCorpus{stored: []string{"CVE-1999-0001"}, ranges: 100000}
			im, fs := httpImporter(t, r, srv, corpus, tc.applied)
			res, err := im.Run(context.Background())
			if err != nil || !res.Ran || res.Kind != vulnbundle.KindSnapshot || res.Sequence != tc.seq {
				t.Fatalf("%+v %v", res, err)
			}
			snap, delta := fetchedKinds(paths())
			if delta != 0 || snap != 4 {
				t.Fatalf("fetched %v", paths())
			}
			// Only the newest release is read, never one the collector may
			// already have deleted.
			for _, p := range paths() {
				if !strings.HasPrefix(p, "/releases/latest/download/") && !strings.HasPrefix(p, "/releases/download/"+vulnbundle.Tag(tc.seq)+"/") {
					t.Fatalf("another release was requested: %v", paths())
				}
			}
			ids := map[string]bool{}
			for _, c := range corpus.applied {
				ids[c.ID] = true
			}
			if !ids["CVE-2021-0001"] || !ids["CVE-2021-23017"] {
				t.Fatalf("snapshot not applied: %+v", corpus.applied)
			}
			// Over an existing corpus the snapshot also withdraws what it no
			// longer carries.
			if tc.applied != 0 && !ids["CVE-1999-0001"] {
				t.Fatalf("withdrawal missing: %+v", corpus.applied)
			}
			if toUint(fs.st.Metadata()["applied_sequence"]) != tc.seq {
				t.Fatalf("status %+v", fs.st.Metadata())
			}
		})
	}
}

// A tampered delta (bytes that do not match the signed manifest, a
// manifest not signed by the key set, a delta that claims another base)
// is refused: nothing is applied, the status records the failure, and the
// importer does not quietly fall back to the snapshot.
func TestImport_TamperedDeltaRefused(t *testing.T) {
	for name, tamper := range map[string]func(r *release){
		"record file": func(r *release) {
			f := vulnbundle.FileName(vulnbundle.KindDelta, "vulns")
			r.files[f] = append(append([]byte(nil), r.files[f]...), 0)
		},
		"manifest signature": func(r *release) {
			var env map[string]any
			_ = json.Unmarshal(r.files[vulnbundle.ManifestName(vulnbundle.KindDelta)], &env)
			sigs, _ := env["signatures"].([]any)
			sig, _ := sigs[0].(map[string]any)
			sig["sig"] = "AAAA" + strings.Repeat("A", 84)
			r.files[vulnbundle.ManifestName(vulnbundle.KindDelta)], _ = json.Marshal(env)
		},
		"manifest swapped for the snapshot's": func(r *release) {
			r.files[vulnbundle.ManifestName(vulnbundle.KindDelta)] = r.files[vulnbundle.ManifestName(vulnbundle.KindSnapshot)]
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRelease(t, 42)
			tamper(&r)
			srv, paths := r.serve(t, 42)
			corpus := &fakeCorpus{}
			im, fs := httpImporter(t, r, srv, corpus, 41)
			if _, err := im.Run(context.Background()); err == nil {
				t.Fatal("tampered delta accepted")
			}
			if len(corpus.applied) != 0 || fs.st.LastSyncStatus() != threatintel.SyncStateFailed {
				t.Fatalf("applied %d, status %s", len(corpus.applied), fs.st.LastSyncStatus())
			}
			if snap, _ := fetchedKinds(paths()); snap != 0 {
				t.Fatalf("fell back to the snapshot: %v", paths())
			}
			if toUint(fs.st.Metadata()["applied_sequence"]) != 41 {
				t.Fatalf("applied sequence moved: %+v", fs.st.Metadata())
			}
		})
	}
}

// Nothing newer: a 20-minute run fetches the key set and the pointer only.
func TestImport_NothingNewerFetchesPointerOnly(t *testing.T) {
	r := makeRelease(t, 42)
	srv, paths := r.serve(t, 42)
	im, _ := httpImporter(t, r, srv, &fakeCorpus{}, 42)
	res, err := im.Run(context.Background())
	if err != nil || res.Ran || len(paths()) != 2 {
		t.Fatalf("%+v %v %v", res, err, paths())
	}
}

func TestVerifyOneRefusesDeltaOnOtherBase(t *testing.T) {
	r := makeRelease(t, 42)
	dir := t.TempDir()
	for name, b := range r.files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opt := vulnbundle.Options{PinnedRoot: r.root, AppliedSeq: 40, Now: r.now.Add(time.Minute)}
	if _, err := vulnbundle.VerifyOne(dir, opt, vulnbundle.KindDelta); err == nil {
		t.Fatal("delta on another base accepted")
	}
	opt.AppliedSeq = 41
	v, err := vulnbundle.VerifyOne(dir, opt, vulnbundle.KindDelta)
	if err != nil || v.Delta == nil || v.Delta.BaseSequence != 41 {
		t.Fatalf("%v %+v", err, v)
	}
}
