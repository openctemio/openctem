package vulnfeed

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/feedsign"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

type mapFetcher map[string][]byte

func (m mapFetcher) Small(_ context.Context, name string, max int64) ([]byte, error) {
	b, ok := m[name]
	if !ok {
		return nil, errors.New("not found")
	}
	if int64(len(b)) > max {
		return nil, errors.New("over the cap")
	}
	return b, nil
}

type fakeIntel struct {
	held     map[string]time.Time // source -> data date held
	kev      int
	epss     int
	seen     map[string]threat.BundleStream
	refused  map[string]error
	applyErr map[string]error
}

func newFakeIntel() *fakeIntel {
	return &fakeIntel{held: map[string]time.Time{}, seen: map[string]threat.BundleStream{}, refused: map[string]error{}, applyErr: map[string]error{}}
}

func (f *fakeIntel) BundleWanted(_ context.Context, source string, asOf time.Time) (bool, error) {
	return asOf.After(f.held[source]), nil
}
func (f *fakeIntel) RecordBundleSeen(_ context.Context, source string, st threat.BundleStream) error {
	f.seen[source] = st
	return nil
}
func (f *fakeIntel) RecordBundleRefused(_ context.Context, source string, cause error) {
	f.refused[source] = cause
}
func (f *fakeIntel) ApplyBundleKEV(_ context.Context, st threat.BundleStream, e []*threatintel.KEVEntry, _ string) (threat.BundleOutcome, error) {
	if err := f.applyErr["kev"]; err != nil {
		return threat.BundleOutcome{}, err
	}
	f.kev += len(e)
	f.held["kev"] = st.AsOf
	return threat.BundleOutcome{Applied: true, Records: len(e)}, nil
}
func (f *fakeIntel) ApplyBundleEPSS(_ context.Context, st threat.BundleStream, s []*threatintel.EPSSScore) (threat.BundleOutcome, error) {
	f.epss += len(s)
	f.held["epss"] = st.AsOf
	return threat.BundleOutcome{Applied: true, Records: len(s)}, nil
}

type intelRelease struct {
	rootID string
	files  mapFetcher
	now    time.Time
}

func gzFile(lines ...string) ([]byte, vulnbundle.File, string) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(strings.Join(lines, "\n") + "\n"))
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), vulnbundle.File{SHA256: hex.EncodeToString(sum[:]), Size: int64(buf.Len()), Records: len(lines)}, ""
}

// newIntelRelease builds the files of a signed release: key set and an intel
// manifest of the given streams.
func newIntelRelease(t *testing.T, seq uint64, asOfKEV, asOfEPSS time.Time, extra ...vulnbundle.IntelStream) intelRelease {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPub, root, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	ks, err := feedsign.SignKeySet(root, feedsign.KeySetType{PayloadType: vulnbundle.KeySetPayloadType, Kind: vulnbundle.KeySetKind,
		MaxValidity: vulnbundle.MaxKeySetValidity}, 1, now.Add(-time.Hour), now.Add(30*24*time.Hour), pub)
	if err != nil {
		t.Fatal(err)
	}
	files := mapFetcher{vulnbundle.KeySetFile: ks}
	var streams []vulnbundle.IntelStream
	kevGz, kevF, _ := gzFile(
		`{"cve":"CVE-2021-44228","vendor":"A","product":"B","name":"N","description":"D","date_added":"2021-12-10","ransomware":"Known","cwes":[]}`,
		`{"cve":"CVE-2022-0001","vendor":"A","product":"B","name":"N","description":"D","date_added":"2022-01-10","ransomware":"Unknown","cwes":[]}`)
	kevF.Name = vulnbundle.IntelFileName("kev")
	files[kevF.Name] = kevGz
	streams = append(streams, vulnbundle.IntelStream{Name: "kev", AsOf: asOfKEV, FetchedAt: now, Version: "v", File: kevF})
	epGz, epF, _ := gzFile(`{"cve":"CVE-2020-0001","epss":0.5,"percentile":0.9}`)
	epF.Name = vulnbundle.IntelFileName("epss")
	files[epF.Name] = epGz
	streams = append(streams, vulnbundle.IntelStream{Name: "epss", AsOf: asOfEPSS, FetchedAt: now, Version: "v", File: epF})
	streams = append(streams, extra...)
	m := vulnbundle.IntelManifest{Schema: vulnbundle.IntelSchema, Sequence: seq, CreatedAt: now, ExpiresAt: now.Add(vulnbundle.MaxBundleValidity), Streams: streams}
	p, _ := json.Marshal(m)
	env, err := feedsign.Sign(priv, vulnbundle.IntelManifestPayloadType, p)
	if err != nil {
		t.Fatal(err)
	}
	files[vulnbundle.IntelManifestFile] = env
	return intelRelease{rootID: jobsign.KeyID(rootPub), files: files, now: now}
}

func intelImporter(t *testing.T, rel intelRelease, ap IntelApplier) (*Importer, *fakeStatus) {
	t.Helper()
	im, fs := newTestImporter(t, Config{RootKeyID: rel.rootID, BundleDir: t.TempDir()}, &fakeCorpus{}, nil)
	im.now = func() time.Time { return rel.now }
	im.WithIntel(ap)
	return im, fs
}

func TestSyncIntel_AppliesBothStreams(t *testing.T) {
	rel := newIntelRelease(t, 9, rel0(), rel0())
	ap := newFakeIntel()
	im, fs := intelImporter(t, rel, ap)
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if ap.kev != 2 || ap.epss != 1 || len(ap.refused) != 0 {
		t.Fatalf("kev %d epss %d refused %v", ap.kev, ap.epss, ap.refused)
	}
	if fs.st.Metadata()["intel_error"] != nil {
		t.Fatalf("%v", fs.st.Metadata())
	}
}

func rel0() time.Time { return time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second) }

func TestSyncIntel_NotNewerIsNotDownloadedOnlyRecordedFresh(t *testing.T) {
	asOf := rel0()
	rel := newIntelRelease(t, 9, asOf, asOf)
	ap := newFakeIntel()
	ap.held["kev"], ap.held["epss"] = asOf, asOf
	im, _ := intelImporter(t, rel, ap)
	// The entries files are gone: a download would fail. They are not needed.
	delete(rel.files, vulnbundle.IntelFileName("kev"))
	delete(rel.files, vulnbundle.IntelFileName("epss"))
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if ap.kev != 0 || ap.epss != 0 || len(ap.refused) != 0 || ap.seen["kev"].Sequence != 9 || ap.seen["epss"].FetchedAt.IsZero() {
		t.Fatalf("kev %d epss %d refused %v seen %v", ap.kev, ap.epss, ap.refused, ap.seen)
	}
}

func TestSyncIntel_RefusesWhatDoesNotVerify(t *testing.T) {
	good := newIntelRelease(t, 9, rel0(), rel0())
	for name, tc := range map[string]struct {
		seq   uint64
		mut   func(rel *intelRelease)
		wants string
	}{
		"another release's sequence": {10, nil, "sequence"},
		"another root":               {9, func(r *intelRelease) { r.rootID = "someone-else" }, ""},
		"tampered entries": {9, func(r *intelRelease) {
			b := append([]byte{}, r.files[vulnbundle.IntelFileName("kev")]...)
			b[len(b)-3] ^= 0xff
			r.files[vulnbundle.IntelFileName("kev")] = b
		}, ""},
	} {
		rel := intelRelease{rootID: good.rootID, now: good.now, files: mapFetcher{}}
		for k, v := range good.files {
			rel.files[k] = v
		}
		if tc.mut != nil {
			tc.mut(&rel)
		}
		ap := newFakeIntel()
		im, fs := intelImporter(t, rel, ap)
		im.syncIntel(context.Background(), rel.files, tc.seq, 0)
		if name == "tampered entries" {
			// One stream is refused, the other is still applied.
			if ap.refused["kev"] == nil || ap.kev != 0 || ap.epss != 1 {
				t.Errorf("%s: refused %v kev %d epss %d", name, ap.refused, ap.kev, ap.epss)
			}
		} else if ap.kev != 0 || ap.epss != 0 || ap.refused["kev"] == nil || ap.refused["epss"] == nil {
			t.Errorf("%s: applied or not recorded: kev %d epss %d refused %v", name, ap.kev, ap.epss, ap.refused)
		}
		if fs.st.Metadata()["intel_error"] == nil {
			t.Errorf("%s: the error is not in the feed status", name)
		}
		if tc.wants != "" && !strings.Contains(fmt.Sprint(ap.refused["kev"]), tc.wants) {
			t.Errorf("%s: %v", name, ap.refused["kev"])
		}
	}
}

func TestSyncIntel_SkipsUnknownStreamsAndReportsThem(t *testing.T) {
	extra := vulnbundle.IntelStream{Name: "exploits", AsOf: rel0(), FetchedAt: rel0(), File: vulnbundle.File{Name: vulnbundle.IntelFileName("exploits")}}
	rel := newIntelRelease(t, 9, rel0(), rel0(), extra)
	ap := newFakeIntel()
	im, fs := intelImporter(t, rel, ap)
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if ap.kev != 2 || ap.epss != 1 {
		t.Fatalf("known streams not applied: %d %d", ap.kev, ap.epss)
	}
	if fs.st.Metadata()["intel_skipped"] != "exploits" || fs.st.Metadata()["intel_error"] != nil {
		t.Fatalf("%v", fs.st.Metadata())
	}
}

func TestSyncIntel_NoManifestOrNoApplierIsNormal(t *testing.T) {
	rel := newIntelRelease(t, 9, rel0(), rel0())
	delete(rel.files, vulnbundle.IntelManifestFile)
	ap := newFakeIntel()
	im, fs := intelImporter(t, rel, ap)
	im.syncIntel(context.Background(), rel.files, 9, 0)
	if ap.kev != 0 || len(ap.refused) != 0 || fs.st.Metadata()["intel_error"] != nil {
		t.Fatalf("an older release without the manifest is not an error: %v", fs.st.Metadata())
	}
	im.intel = nil
	im.syncIntel(context.Background(), rel.files, 9, 0)
}
