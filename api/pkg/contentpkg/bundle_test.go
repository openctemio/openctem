package contentpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The sast-rules v0.1.0 release: its tarball and the keyless Sigstore
// bundle its release workflow wrote. Verified offline with the embedded
// trusted root.
const (
	sastIdentity = "https://github.com/openctemio/sast-rules/.github/workflows/release.yml@refs/tags/v0.1.0"
	ghIssuer     = "https://token.actions.githubusercontent.com"
)

var (
	sigOnce     sync.Once
	sigVerifier *SigstoreVerifier
	sigErr      error
)

func sigstoreVerifier(t *testing.T) *SigstoreVerifier {
	t.Helper()
	sigOnce.Do(func() { sigVerifier, sigErr = NewSigstoreVerifier("") })
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	return sigVerifier
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rulesManifest(t *testing.T, artifact []byte, identity string) []byte {
	t.Helper()
	return []byte(fmt.Sprintf(`apiVersion: openctem.io/package/v1
id: openctem/sast-rules
version: 0.1.0
type: rules
title: Official SAST rules
content_kind: semgrep-rules
artifact:
  media_type: application/gzip
  digest: %s
  size: %d
compatibility:
  platform: ">=0.9.0"
permissions:
  tier: T0
  side_effects: none
  network: none
license:
  spdx: MIT
  service_use: true
  redistribution: true
provenance:
  build_identity: %s
  build_issuer: %s
`, Digest(artifact), len(artifact), identity, ghIssuer))
}

func sensorManifest(id string) []byte {
	return []byte(`apiVersion: openctem.io/package/v1
id: ` + id + `
version: 0.23.0
type: sensors
title: Scanning sensor
artifact:
  media_type: application/vnd.oci.image.index.v1+json
  digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
  size: 2048
  ref: ghcr.io/openctemio/sensor
compatibility:
  platform: ">=0.9.0"
  protocol: ">=3"
permissions:
  tier: T1
  side_effects: none
  network: targets-only
license:
  spdx: GPL-3.0-only
  service_use: true
  redistribution: true
provenance:
  build_identity: https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml@refs/tags/v0.23.0
  build_issuer: https://token.actions.githubusercontent.com
`)
}

type fixture struct {
	t       *testing.T
	now     time.Time
	root    ed25519.PrivateKey
	online  ed25519.PrivateKey
	keySet  []byte
	art     []byte
	sig     []byte
	in      BundleInput
	options VerifyOptions
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	_, online, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	ks, err := SignKeySet(root, 3, now.Add(-time.Hour), now.Add(90*24*time.Hour), online.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, now: now, root: root, online: online, keySet: ks,
		art: readTestdata(t, "sigstore/sast-rules-0.1.0.tar.gz"),
		sig: readTestdata(t, "sigstore/sast-rules-0.1.0.tar.gz.sigstore.json")}
	f.in = BundleInput{
		KeySet: ks, Online: online, Sequence: 10, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour),
		Revocations: Revocations{Sequence: 4, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(7 * 24 * time.Hour)},
		Packages: []PackageInput{
			{ManifestRaw: rulesManifest(t, f.art, sastIdentity), Artifact: f.art, Publisher: f.sig, Origin: OriginFirstParty, ReviewedAt: now},
			{ManifestRaw: sensorManifest("openctem/sensor"), Origin: OriginFirstParty, ReviewedAt: now},
		},
	}
	f.options = VerifyOptions{Trust: Trust{Roots: []string{RootKeyID(root.Public().(ed25519.PublicKey))}},
		Publisher: sigstoreVerifier(t), Now: now}
	return f
}

func (f *fixture) write() []byte {
	f.t.Helper()
	var buf bytes.Buffer
	if err := WriteBundle(&buf, f.in); err != nil {
		f.t.Fatal(err)
	}
	return buf.Bytes()
}

func (f *fixture) verify(raw []byte) (*Verified, error) {
	f.t.Helper()
	b, err := ReadBundle(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return Verify(b, f.options)
}

// rewrite returns raw with fn applied to its files.
func rewrite(t *testing.T, raw []byte, fn func(map[string][]byte)) []byte {
	t.Helper()
	b, err := ReadBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	fn(b.files)
	var buf bytes.Buffer
	if err := WriteFiles(&buf, b.files); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const sastDir = "packages/openctem/sast-rules/0.1.0/"

func TestVerify_Valid(t *testing.T) {
	f := newFixture(t)
	v, err := f.verify(f.write())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(v.Packages) != 2 || len(v.Refused) != 0 || v.KeySetVersion != 3 || v.Index.Sequence != 10 || v.Unchanged {
		t.Fatalf("verified: %+v", v)
	}
	rules := v.Packages[0]
	if rules.Manifest.ID != "openctem/sast-rules" || !bytes.Equal(rules.Artifact, f.art) || rules.PublisherSigned.IsZero() {
		t.Fatalf("rules package: %+v", rules.Manifest)
	}
	if v.Packages[1].Artifact != nil || v.Packages[1].Statement.Origin != OriginFirstParty {
		t.Fatal("an OCI package carries no artifact")
	}
	if v.RevocationsStale {
		t.Fatal("the revocation list is fresh")
	}
}

func TestVerify_GzipBundle(t *testing.T) {
	f := newFixture(t)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(f.write())
	_ = zw.Close()
	if _, err := f.verify(gz.Bytes()); err != nil {
		t.Fatalf("gzip bundle: %v", err)
	}
}

func TestVerify_TamperedArtifact(t *testing.T) {
	f := newFixture(t)
	raw := rewrite(t, f.write(), func(m map[string][]byte) {
		a := append([]byte(nil), m[sastDir+FileArtifact]...)
		a[len(a)/2] ^= 0xff
		m[sastDir+FileArtifact] = a
	})
	if _, err := f.verify(raw); !errors.Is(err, ErrTampered) {
		t.Fatalf("a tampered artifact: %v", err)
	}
}

func TestVerify_TamperedManifest(t *testing.T) {
	f := newFixture(t)
	raw := rewrite(t, f.write(), func(m map[string][]byte) {
		m[sastDir+FileManifest] = bytes.Replace(m[sastDir+FileManifest], []byte("tier: T0"), []byte("tier: T1"), 1)
	})
	if _, err := f.verify(raw); err == nil || !strings.Contains(err.Error(), "index digest") {
		t.Fatalf("a changed manifest: %v", err)
	}
}

func TestVerify_ManifestDiffersFromReviewedStatement(t *testing.T) {
	f := newFixture(t)
	// The publisher re-publishes the same version with wider permissions;
	// the index is re-signed but the statement is the reviewed one.
	raw := f.write()
	reviewed := rewrite(t, raw, func(map[string][]byte) {})
	b, _ := ReadBundle(bytes.NewReader(reviewed))
	oldStatement := b.files[sastDir+FileStatement]
	f.in.Packages[0].ManifestRaw = bytes.Replace(f.in.Packages[0].ManifestRaw, []byte("network: none"), []byte("network: targets-only"), 1)
	raw = rewrite(t, f.write(), func(m map[string][]byte) { m[sastDir+FileStatement] = oldStatement })
	if _, err := f.verify(raw); err == nil || !strings.Contains(err.Error(), "does not match the manifest") {
		t.Fatalf("a manifest that differs from the statement: %v", err)
	}
}

func TestVerify_Unsigned(t *testing.T) {
	f := newFixture(t)
	raw := rewrite(t, f.write(), func(m map[string][]byte) { delete(m, sastDir+FileStatement) })
	if _, err := f.verify(raw); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("no statement: %v", err)
	}
	raw = rewrite(t, f.write(), func(m map[string][]byte) { delete(m, sastDir+FilePublisher) })
	if _, err := f.verify(raw); !errors.Is(err, ErrPublisherSignature) {
		t.Fatalf("no publisher signature: %v", err)
	}
}

func TestVerify_StatementByUnknownKey(t *testing.T) {
	f := newFixture(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	m, _ := ParseManifest(f.in.Packages[0].ManifestRaw)
	forged, _ := Sign(other, StatementPayloadType, NewStatement(m, f.in.Packages[0].ManifestRaw, OriginFirstParty, f.now))
	raw := rewrite(t, f.write(), func(files map[string][]byte) { files[sastDir+FileStatement] = forged })
	if _, err := f.verify(raw); err == nil || !strings.Contains(err.Error(), "key set") {
		t.Fatalf("a statement by a key outside the key set: %v", err)
	}
}

func TestVerify_WrongPublisherIdentity(t *testing.T) {
	f := newFixture(t)
	f.in.Packages[0].ManifestRaw = rulesManifest(t, f.art, "https://github.com/evil/rules/.github/workflows/release.yml@refs/tags/v0.1.0")
	if _, err := f.verify(f.write()); !errors.Is(err, ErrPublisherSignature) {
		t.Fatalf("another build identity: %v", err)
	}
}

func TestVerify_SignatureOverOtherBytes(t *testing.T) {
	f := newFixture(t)
	other := append([]byte(nil), f.art...)
	other = append(other, 0)
	f.in.Packages[0] = PackageInput{ManifestRaw: rulesManifest(t, other, sastIdentity), Artifact: other,
		Publisher: f.sig, Origin: OriginFirstParty, ReviewedAt: f.now}
	if _, err := f.verify(f.write()); !errors.Is(err, ErrPublisherSignature) {
		t.Fatalf("a signature over other bytes: %v", err)
	}
}

func TestVerify_ExpiredIndex(t *testing.T) {
	f := newFixture(t)
	raw := f.write()
	f.options.Now = f.in.ExpiresAt.Add(time.Minute)
	if _, err := f.verify(raw); !errors.Is(err, ErrExpired) {
		t.Fatalf("an expired index: %v", err)
	}
	f = newFixture(t)
	f.in.ExpiresAt = f.in.IssuedAt.Add(MaxIndexValidity + time.Hour)
	if _, err := f.verify(f.write()); err == nil {
		t.Fatal("an index valid for longer than the bound")
	}
}

func TestVerify_Rollback(t *testing.T) {
	f := newFixture(t)
	raw := f.write()
	v, err := f.verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.options.LastIndexSequence, f.options.LastIndexDigest = v.Index.Sequence, v.IndexDigest
	again, err := f.verify(raw)
	if err != nil || !again.Unchanged {
		t.Fatalf("a repeated import is a no-op: %v", err)
	}
	f.in.IssuedAt = f.in.IssuedAt.Add(time.Second) // same sequence, other bytes
	if _, err := f.verify(f.write()); !errors.Is(err, ErrRollback) {
		t.Fatalf("same sequence, other contents: %v", err)
	}
	f.options.LastIndexSequence = 11
	if _, err := f.verify(raw); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older index: %v", err)
	}
	f.options.LastIndexSequence, f.options.LastRevocationsSequence = 0, 5
	if _, err := f.verify(raw); !errors.Is(err, ErrRollback) {
		t.Fatalf("an older revocation list: %v", err)
	}
}

func TestVerify_Revoked(t *testing.T) {
	cases := map[string]RevocationEntry{
		"by id":         {ID: "openctem/sast-rules"},
		"by id+version": {ID: "openctem/sast-rules", Version: "0.1.0"},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			e.Reason, e.Severity, e.RevokedAt = "malicious update", "critical", f.now
			f.in.Revocations.Entries = []RevocationEntry{e}
			v, err := f.verify(f.write())
			if err != nil {
				t.Fatal(err)
			}
			if len(v.Packages) != 1 || len(v.Refused) != 1 || v.Refused[0].ID != "openctem/sast-rules" ||
				!strings.Contains(v.Refused[0].Reason, "malicious update") {
				t.Fatalf("revoked: %+v", v)
			}
		})
	}
	t.Run("by digest", func(t *testing.T) {
		f := newFixture(t)
		f.in.Revocations.Entries = []RevocationEntry{{Digest: Digest(f.art), Reason: "bad", Severity: "high", RevokedAt: f.now}}
		if v, err := f.verify(f.write()); err != nil || len(v.Refused) != 1 {
			t.Fatalf("by digest: %v %+v", err, v)
		}
	})
	t.Run("already applied, absent from the bundle's list", func(t *testing.T) {
		f := newFixture(t)
		f.options.Revoked = []RevocationEntry{{ID: "openctem/sast-rules", Version: "0.1.0", Reason: "bad", Severity: "high", RevokedAt: f.now}}
		if v, err := f.verify(f.write()); err != nil || len(v.Refused) != 1 {
			t.Fatalf("applied revocation: %v %+v", err, v)
		}
	})
	t.Run("an entry naming nothing", func(t *testing.T) {
		f := newFixture(t)
		f.in.Revocations.Entries = []RevocationEntry{{Reason: "x", Severity: "high", RevokedAt: f.now}}
		if _, err := f.verify(f.write()); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestVerify_StaleRevocationList(t *testing.T) {
	f := newFixture(t)
	raw := f.write()
	f.options.Now = f.in.Revocations.ExpiresAt.Add(time.Hour)
	v, err := f.verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !v.RevocationsStale {
		t.Fatal("a list past its expiry is stale")
	}
}

func TestVerify_KeySet(t *testing.T) {
	f := newFixture(t)
	raw := f.write()
	f.options.Trust.Roots = nil
	if _, err := f.verify(raw); err == nil || !strings.Contains(err.Error(), "no catalog root") {
		t.Fatalf("no root configured: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f.options.Trust.Roots = []string{RootKeyID(other.Public().(ed25519.PublicKey))}
	if _, err := f.verify(raw); err == nil {
		t.Fatal("a key set by an unpinned root")
	}
	f.options.Trust.Roots = []string{RootKeyID(other.Public().(ed25519.PublicKey)), RootKeyID(f.root.Public().(ed25519.PublicKey))}
	if _, err := f.verify(raw); err != nil {
		t.Fatalf("the second pinned root (rotation overlap): %v", err)
	}
	f.options.Trust.MinKeySetVersion = 4
	if _, err := f.verify(raw); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("an older key set: %v", err)
	}
}

func TestVerify_OnlineKeyRotation(t *testing.T) {
	f := newFixture(t)
	_, next, _ := ed25519.GenerateKey(rand.Reader)
	ks, err := SignKeySet(f.root, 4, f.now.Add(-time.Minute), f.now.Add(24*time.Hour), next.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	f.in.KeySet, f.in.Online = ks, next
	f.options.Trust.MinKeySetVersion = 3
	if _, err := f.verify(f.write()); err != nil {
		t.Fatalf("a newer key set with a new online key: %v", err)
	}
	// The removed key can no longer sign, even with the newer key set.
	f.in.Online = f.online
	if _, err := f.verify(f.write()); err == nil {
		t.Fatal("a key removed from the key set still signs")
	}
}

func TestVerify_Origin(t *testing.T) {
	f := newFixture(t)
	f.in.Packages[1].ManifestRaw = sensorManifest("acme/sensor")
	if _, err := f.verify(f.write()); err == nil || !strings.Contains(err.Error(), "not reserved") {
		t.Fatalf("first-party origin outside the reserved namespace: %v", err)
	}
	f.in.Packages[1] = PackageInput{ManifestRaw: sensorManifest("openctem/sensor"), Origin: OriginCatalog, ReviewedAt: f.now}
	if _, err := f.verify(f.write()); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("a catalog origin in the reserved namespace: %v", err)
	}
}

func TestVerify_FilesOutsideTheIndex(t *testing.T) {
	f := newFixture(t)
	raw := rewrite(t, f.write(), func(m map[string][]byte) {
		m["packages/openctem/extra/1.0.0/package.yaml"] = []byte("x")
	})
	if _, err := f.verify(raw); !errors.Is(err, ErrBundle) {
		t.Fatalf("a package outside the index: %v", err)
	}
	raw = rewrite(t, f.write(), func(m map[string][]byte) { delete(m, FileRevocations) })
	if _, err := f.verify(raw); !errors.Is(err, ErrBundle) {
		t.Fatalf("no revocation list: %v", err)
	}
}

func tarOf(t *testing.T, hdrs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(make([]byte, h.Size))
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestReadBundle_Refusals(t *testing.T) {
	cases := map[string][]byte{
		"traversal":    tarOf(t, &tar.Header{Name: "../keyset.dsse.json", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}),
		"absolute":     tarOf(t, &tar.Header{Name: "/keyset.dsse.json", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}),
		"symlink":      tarOf(t, &tar.Header{Name: "keyset.dsse.json", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		"unknown file": tarOf(t, &tar.Header{Name: "run.sh", Typeflag: tar.TypeReg, Size: 1, Mode: 0o755}),
		"bad version":  tarOf(t, &tar.Header{Name: "packages/a/b/latest/package.yaml", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}),
		"oversize":     tarOf(t, &tar.Header{Name: "keyset.dsse.json", Typeflag: tar.TypeReg, Size: 65<<10 + 1, Mode: 0o644}),
		"duplicate": tarOf(t, &tar.Header{Name: "index.dsse.json", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
			&tar.Header{Name: "index.dsse.json", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644}),
		"not a tar": []byte("hello"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadBundle(bytes.NewReader(raw)); !errors.Is(err, ErrBundle) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func FuzzReadBundle(f *testing.F) {
	f.Add(tarOf(&testing.T{}, &tar.Header{Name: "index.dsse.json", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644}))
	f.Add([]byte{0x1f, 0x8b, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := ReadBundle(bytes.NewReader(raw))
		if err != nil {
			return
		}
		for name := range b.files {
			if !knownPath(name) {
				t.Fatalf("accepted %q", name)
			}
		}
	})
}

func TestVerify_RevocationListSameSequenceOtherContents(t *testing.T) {
	f := newFixture(t)
	v, err := f.verify(f.write())
	if err != nil {
		t.Fatal(err)
	}
	f.options.LastRevocationsSequence, f.options.LastRevocationsDigest = v.Revocations.Sequence, v.RevocationsDigest
	if _, err := f.verify(f.write()); err != nil {
		t.Fatalf("the same list again: %v", err)
	}
	// Same sequence, an entry dropped or added: refused.
	f.in.Revocations.Entries = []RevocationEntry{{ID: "acme/x", Reason: "bad", Severity: "low", RevokedAt: f.now}}
	if _, err := f.verify(f.write()); !errors.Is(err, ErrRollback) {
		t.Fatalf("same sequence, other contents: %v", err)
	}
}
