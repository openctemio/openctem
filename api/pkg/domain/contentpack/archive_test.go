package contentpack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type entry struct {
	name string
	typ  byte
	data string
	link string
	mode int64
}

func makeTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := int64(len(e.data))
		if typ != tar.TypeReg {
			size = 0
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o755
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Size: size, Linkname: e.link, Mode: mode, ModTime: time.Now(), Uname: "someone", Uid: 1000}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCanonicalizeIsDeterministic(t *testing.T) {
	a := makeTar(t, entry{name: "./templates/", typ: tar.TypeDir}, entry{name: "./templates/b.yaml", data: "b"}, entry{name: "a.yaml", data: "a"})
	b := makeTar(t, entry{name: "a.yaml", data: "a", mode: 0o600}, entry{name: "templates/b.yaml", data: "b"})
	ca, err := Canonicalize(bytes.NewReader(a), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Canonicalize(bytes.NewReader(gz(t, b)), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Digest != cb.Digest || !bytes.Equal(ca.Canonical, cb.Canonical) {
		t.Fatalf("same files, different digests: %s %s", ca.Digest, cb.Digest)
	}
	if len(ca.Files) != 2 || ca.Files[0].Path != "a.yaml" || ca.Files[1].Path != "templates/b.yaml" {
		t.Fatalf("files %+v", ca.Files)
	}
	if ValidateDigest(ca.Digest) != nil {
		t.Fatalf("digest %q", ca.Digest)
	}
	// The canonical archive reads back to itself, and tampering is caught.
	back, err := ReadCanonical(ca.Canonical, ca.Digest)
	if err != nil || back.Digest != ca.Digest {
		t.Fatalf("read back: %v", err)
	}
	tampered := bytes.Clone(ca.Canonical)
	tampered[len(tampered)-1100] ^= 1
	if _, err := ReadCanonical(tampered, ca.Digest); err == nil {
		t.Fatal("a tampered archive was accepted")
	}
	// Canonical entries carry no owner, mode or time of the uploader.
	tr := tar.NewReader(bytes.NewReader(ca.Canonical))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Uid != 0 || h.Uname != "" || h.Mode != 0o644 || !h.ModTime.Equal(time.Unix(0, 0)) {
			t.Fatalf("canonical header %+v", h)
		}
	}
}

// A git archive (a release tarball) opens with a PAX global header: it is
// metadata, skipped, and the files are kept.
func TestCanonicalizeSkipsPAXGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "abc123"}, Format: tar.FormatPAX})
	_ = tw.WriteHeader(&tar.Header{Name: "r/a.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("a"))
	_ = tw.Close()
	a, err := Canonicalize(bytes.NewReader(buf.Bytes()), DefaultLimits)
	if err != nil || len(a.Files) != 1 || a.Files[0].Path != "r/a.yaml" {
		t.Fatalf("%+v %v", a, err)
	}
}

// SECURITY: archive tricks are refused before anything is stored.
func TestCanonicalizeRefusesArchiveTricks(t *testing.T) {
	small := DefaultLimits
	small.MaxFiles = 3
	small.MaxFileSize = 10
	small.MaxTotal = 25
	small.MaxDepth = 3
	cases := map[string]struct {
		data []byte
		lim  Limits
	}{
		"symlink":          {makeTar(t, entry{name: "a", data: "x"}, entry{name: "l", typ: tar.TypeSymlink, link: "/etc/passwd"}), DefaultLimits},
		"hard link":        {makeTar(t, entry{name: "a", data: "x"}, entry{name: "l", typ: tar.TypeLink, link: "a"}), DefaultLimits},
		"device":           {makeTar(t, entry{name: "d", typ: tar.TypeChar}), DefaultLimits},
		"fifo":             {makeTar(t, entry{name: "f", typ: tar.TypeFifo}), DefaultLimits},
		"dot dot":          {makeTar(t, entry{name: "a/../../etc/passwd", data: "x"}), DefaultLimits},
		"leading dot dot":  {makeTar(t, entry{name: "../x", data: "x"}), DefaultLimits},
		"absolute":         {makeTar(t, entry{name: "/etc/passwd", data: "x"}), DefaultLimits},
		"backslash":        {makeTar(t, entry{name: `a\..\b`, data: "x"}), DefaultLimits},
		"control char":     {makeTar(t, entry{name: "a\nb", data: "x"}), DefaultLimits},
		"unclean":          {makeTar(t, entry{name: "a//b", data: "x"}), DefaultLimits},
		"case duplicate":   {makeTar(t, entry{name: "A.yaml", data: "x"}, entry{name: "a.yaml", data: "y"}), DefaultLimits},
		"file and dir":     {makeTar(t, entry{name: "a", data: "x"}, entry{name: "a/b", data: "y"}), DefaultLimits},
		"empty":            {makeTar(t, entry{name: "d/", typ: tar.TypeDir}), DefaultLimits},
		"not a tar":        {[]byte(strings.Repeat("hello world ", 100)), DefaultLimits},
		"too many files":   {makeTar(t, entry{name: "a", data: "1"}, entry{name: "b", data: "2"}, entry{name: "c", data: "3"}, entry{name: "d", data: "4"}), small},
		"file too large":   {makeTar(t, entry{name: "a", data: strings.Repeat("x", 11)}), small},
		"total too large":  {makeTar(t, entry{name: "a", data: strings.Repeat("x", 10)}, entry{name: "b", data: strings.Repeat("x", 10)}, entry{name: "c", data: strings.Repeat("x", 10)}), small},
		"too deep":         {makeTar(t, entry{name: "a/b/c/d/e", data: "x"}), small},
		"upload too large": {makeTar(t, entry{name: "a", data: strings.Repeat("x", 5000)}), Limits{MaxUpload: 1024, MaxTotal: 1 << 20, MaxFiles: 10, MaxFileSize: 1 << 20, MaxDepth: 4, MaxPath: 255}},
	}
	for name, c := range cases {
		if _, err := Canonicalize(bytes.NewReader(c.data), c.lim); !errors.Is(err, ErrArchive) || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// SECURITY: a gzip bomb stops at the limits, not after inflating.
func TestCanonicalizeStopsAGzipBomb(t *testing.T) {
	lim := DefaultLimits
	lim.MaxTotal = 1 << 20
	lim.MaxFileSize = 1 << 20
	bomb := gz(t, makeTar(t, entry{name: "a", data: strings.Repeat("\x00", 64<<20)}))
	if len(bomb) > 1<<20 {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	if _, err := Canonicalize(bytes.NewReader(bomb), lim); !errors.Is(err, ErrArchive) {
		t.Fatalf("bomb: %v", err)
	}
}

func TestSignerSignsPerTenant(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	s, err := NewSigner(master)
	if err != nil {
		t.Fatal(err)
	}
	st := Statement{TenantID: "t1", PackID: "p1", Name: "org", Version: "1", Content: KindNucleiTemplates, Digest: "sha256:" + strings.Repeat("a", 64), Tier: TierT1}
	env, err := s.Sign(st)
	if err != nil {
		t.Fatal(err)
	}
	pub1, _, _ := s.PublicKey("t1")
	pub2, _, _ := s.PublicKey("t2")
	got, err := Verify(env, pub1)
	if err != nil || got.Digest != st.Digest || got.Kind != StatementKind || got.TenantID != "t1" {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if _, err := Verify(env, pub2); err == nil {
		t.Fatal("a pack signed for t1 verified with t2's key")
	}
	// SECURITY: the content key is not the template key, even from the
	// same master: a template manifest signature never verifies as a pack.
	kr, _ := scannertemplate.NewKeyring(master)
	tpub, _, _ := kr.PublicKey("t1")
	if tpub.Equal(pub1) {
		t.Fatal("content and template keys are the same")
	}
	if _, err := s.Sign(Statement{TenantID: "t1", PackID: "p1", Digest: "nope"}); err == nil {
		t.Fatal("signed a statement without a digest")
	}
}

func TestValidators(t *testing.T) {
	for _, k := range []string{KindNucleiTemplates, KindWordlist, "x-acme/fingerprints"} {
		if ValidateKind(k) != nil {
			t.Errorf("kind %q refused", k)
		}
	}
	for _, k := range []string{"", "templates", "x-/a", "X-acme/a", "x-acme/../a"} {
		if ValidateKind(k) == nil {
			t.Errorf("kind %q accepted", k)
		}
	}
	if ValidateName("Org Custom") == nil || ValidateName("org-custom") != nil {
		t.Error("name validation")
	}
	if ValidateVersion("10.4.9") != nil || ValidateVersion("../1") == nil {
		t.Error("version validation")
	}
	if TierT0.Max(TierT2) != TierT2 || TierT1.Max(TierT0) != TierT1 {
		t.Error("tier max")
	}
}
