package vulnbundle

import (
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// The golden bundle was produced by the collector (openctemio/vulnfeed) from
// the real NVD API: a snapshot of sequence 2 and the delta from 1.
func golden(t *testing.T) (string, Options) {
	t.Helper()
	dir := "testdata/golden"
	root, err := os.ReadFile(filepath.Join(dir, "root-keyid.txt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, LatestFile))
	var env scannertemplate.Envelope
	_ = json.Unmarshal(raw, &env)
	var l Latest
	_ = json.Unmarshal(env.Payload, &l)
	return dir, Options{PinnedRoot: strings.TrimSpace(string(root)), Now: l.CreatedAt.Add(time.Hour)}
}

func TestGoldenBundleFromTheCollector(t *testing.T) {
	dir, opt := golden(t)
	v, err := VerifyDir(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if v.Latest.Sequence != 2 || v.Delta == nil || v.Delta.BaseSequence != 1 || v.KeySet.Version != 1 {
		t.Fatalf("%+v", v.Latest)
	}
	snap, err := v.Read(v.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ranges := 0
	for _, c := range snap.CVEs {
		ranges += len(c.Ranges)
	}
	if len(snap.CVEs) != v.Snapshot.Stats.Vulns || ranges != v.Snapshot.Stats.Ranges || snap.Products != v.Snapshot.Stats.Products {
		t.Fatalf("snapshot %d/%d/%d vs stats %+v", len(snap.CVEs), ranges, snap.Products, v.Snapshot.Stats)
	}
	delta, err := v.Read(*v.Delta)
	if err != nil || len(delta.CVEs) != v.Delta.Stats.Vulns {
		t.Fatalf("delta %v", err)
	}
	// Rollback and expiry.
	opt2 := opt
	opt2.AppliedSeq = 2
	if _, err := VerifyDir(dir, opt2); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("replay: %v", err)
	}
	opt3 := opt
	opt3.Now = opt.Now.Add(8 * 24 * time.Hour)
	if _, err := VerifyDir(dir, opt3); err == nil {
		t.Fatal("expired bundle accepted")
	}
	opt4 := opt
	opt4.PinnedRoot = "SHA256:" + strings.Repeat("0", 64)
	if _, err := VerifyDir(dir, opt4); err == nil {
		t.Fatal("other root accepted")
	}
	opt5 := opt
	opt5.MinKeySetVer = 2
	if _, err := VerifyDir(dir, opt5); err == nil {
		t.Fatal("key set rollback accepted")
	}
}

func TestGoldenTamperedFileRefused(t *testing.T) {
	src, opt := golden(t)
	dir := t.TempDir()
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(src, e.Name()))
		if e.Name() == FileName(KindSnapshot, "ranges") {
			b[len(b)/2] ^= 0x01
		}
		_ = os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644)
	}
	if _, err := VerifyDir(dir, opt); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered: %v", err)
	}
}

// --- bundles made in the test, to poison under a valid signature ---------

type testKeys struct {
	rootID string
	priv   ed25519.PrivateKey
	keyset []byte
}

func newTestKeys(t *testing.T, version uint64) testKeys {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Now().UTC().Truncate(time.Second)
	ks := KeySet{Kind: KeySetKind, Version: version, IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		Keys: []jobsign.PublicKey{jobsign.NewPublicKey(pub)}, RootKeyID: jobsign.KeyID(rootPub),
		RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	payload, _ := json.Marshal(ks)
	return testKeys{rootID: jobsign.KeyID(rootPub), priv: priv, keyset: sign(root, KeySetPayloadType, payload)}
}

func sign(priv ed25519.PrivateKey, typ string, payload []byte) []byte {
	pub, _ := priv.Public().(ed25519.PublicKey)
	b, _ := json.Marshal(scannertemplate.Envelope{PayloadType: typ, Payload: payload,
		Signatures: []scannertemplate.EnvelopeSignature{{KeyID: jobsign.KeyID(pub), Sig: ed25519.Sign(priv, scannertemplate.PreAuthEncoding(typ, payload))}}})
	return b
}

const (
	okProduct = `{"key":"cpe:a:f5:nginx","part":"a","vendor":"f5","name":"nginx","cpe_vendor":"f5","cpe_product":"nginx"}`
	okVuln    = `{"id":"CVE-2021-23017","status":"Analyzed","description":"d","severity":"high","cwes":["CWE-193"]}`
	okRange   = `{"vuln":"CVE-2021-23017","product":"cpe:a:f5:nginx","scheme":"generic","end":"1.20.1","start_incl":false,"end_incl":false,"edition":"","target":"","source":"nvd"}`
)

// makeBundle writes a signed snapshot bundle with the given record lines.
func makeBundle(t *testing.T, k testKeys, seq uint64, products, vulns, ranges []string) string {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	m := Manifest{Schema: ManifestSchema, Sequence: seq, Kind: KindSnapshot, CreatedAt: now, ExpiresAt: now.Add(MaxBundleValidity)}
	for i, lines := range [][]string{products, vulns, ranges} {
		name := FileName(KindSnapshot, recordFiles[i])
		f, _ := os.Create(filepath.Join(dir, name))
		gz := gzip.NewWriter(f)
		for _, l := range lines {
			_, _ = gz.Write([]byte(l + "\n"))
		}
		_ = gz.Close()
		_ = f.Close()
		b, _ := os.ReadFile(filepath.Join(dir, name))
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, File{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b)), Records: len(lines)})
	}
	mp, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(dir, ManifestName(KindSnapshot)), sign(k.priv, ManifestPayloadType, mp), 0o644)
	lp, _ := json.Marshal(Latest{Schema: LatestSchema, Sequence: seq, Tag: Tag(seq), Snapshot: ManifestName(KindSnapshot), CreatedAt: now, ExpiresAt: now.Add(MaxBundleValidity)})
	_ = os.WriteFile(filepath.Join(dir, LatestFile), sign(k.priv, LatestPayloadType, lp), 0o644)
	_ = os.WriteFile(filepath.Join(dir, KeySetFile), k.keyset, 0o644)
	return dir
}

func TestMadeBundle(t *testing.T) {
	k := newTestKeys(t, 1)
	dir := makeBundle(t, k, 5, []string{okProduct}, []string{okVuln}, []string{okRange})
	v, err := VerifyDir(dir, Options{PinnedRoot: k.rootID, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.Read(v.Snapshot)
	if err != nil || len(r.CVEs) != 1 || len(r.CVEs[0].Ranges) != 1 || r.CVEs[0].Ranges[0].Product.Key() != "cpe:a:f5:nginx" {
		t.Fatalf("%v %+v", err, r)
	}
}

// Poisoned records under a valid signature and matching hashes: refused.
func TestPoisonedRecordsRefused(t *testing.T) {
	k := newTestKeys(t, 1)
	repl := func(old, new string) string { return strings.Replace(okRange, old, new, 1) }
	cases := map[string][3][]string{
		"wildcard product key":      {{`{"key":"cpe:a:*:*","part":"a","vendor":"*","name":"x","cpe_vendor":"*","cpe_product":"*"}`}, {okVuln}, {okRange}},
		"product key/fields differ": {{strings.Replace(okProduct, `"cpe_vendor":"f5"`, `"cpe_vendor":"evil"`, 1)}, {okVuln}, {okRange}},
		"unparseable bound":         {{okProduct}, {okVuln}, {repl(`"end":"1.20.1"`, `"end":"latest"`)}},
		"exact and bound":           {{okProduct}, {okVuln}, {repl(`"end":"1.20.1"`, `"end":"1.20.1","exact":"1.0"`)}},
		"unknown scheme":            {{okProduct}, {okVuln}, {repl(`"scheme":"generic"`, `"scheme":"semver"`)}},
		"unknown source":            {{okProduct}, {okVuln}, {repl(`"source":"nvd"`, `"source":"blog"`)}},
		"unlisted product":          {{okProduct}, {okVuln}, {repl(`"product":"cpe:a:f5:nginx"`, `"product":"cpe:a:evil:thing"`)}},
		"range of unknown vuln":     {{okProduct}, {okVuln}, {repl(`"vuln":"CVE-2021-23017"`, `"vuln":"CVE-2099-0001"`)}},
		"unknown field":             {{okProduct}, {okVuln}, {repl(`"source":"nvd"`, `"source":"nvd","sql":"1"`)}},
		"bad cve id":                {{okProduct}, {strings.Replace(okVuln, "CVE-2021-23017", "CVE-21-1", 1)}, {}},
		"bad severity":              {{okProduct}, {strings.Replace(okVuln, `"high"`, `"urgent"`, 1)}, {okRange}},
		"duplicate vuln":            {{okProduct}, {okVuln, okVuln}, {okRange}},
		"newline in description":    {{okProduct}, {strings.Replace(okVuln, `"d"`, `"a\nb"`, 1)}, {okRange}},
	}
	for name, files := range cases {
		dir := makeBundle(t, k, 1, files[0], files[1], files[2])
		v, err := VerifyDir(dir, Options{PinnedRoot: k.rootID, Now: time.Now()})
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if _, err := v.Read(v.Snapshot); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnvelopeRefusals(t *testing.T) {
	k := newTestKeys(t, 1)
	other := newTestKeys(t, 1)
	for name, mut := range map[string]func(dir string){
		"pointer signed by a stranger": func(dir string) {
			raw, _ := os.ReadFile(filepath.Join(dir, LatestFile))
			var env scannertemplate.Envelope
			_ = json.Unmarshal(raw, &env)
			_ = os.WriteFile(filepath.Join(dir, LatestFile), sign(other.priv, LatestPayloadType, env.Payload), 0o644)
		},
		"key set of another root": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, KeySetFile), other.keyset, 0o644)
		},
		"oversized pointer": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, LatestFile), make([]byte, MaxManifestBytes+1), 0o644)
		},
		"missing file": func(dir string) {
			_ = os.Remove(filepath.Join(dir, FileName(KindSnapshot, "vulns")))
		},
	} {
		dir := makeBundle(t, k, 1, []string{okProduct}, []string{okVuln}, []string{okRange})
		mut(dir)
		if _, err := VerifyDir(dir, Options{PinnedRoot: k.rootID, Now: time.Now()}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
