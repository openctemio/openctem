package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

func writeKey(t *testing.T, dir, name string) ed25519.PrivateKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	return priv
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The first-party bundle built from the real sast-rules release, the
// sensor products of versions.yaml and a feed key set verifies with both
// signatures, offline.
func TestBuild_FirstPartyBundleVerifies(t *testing.T) {
	dir := t.TempDir()
	root := writeKey(t, dir, "root.key")
	online := writeKey(t, dir, "online.key")
	ksPath := filepath.Join(dir, "keyset.dsse.json")
	if err := keyset([]string{"-root", filepath.Join(dir, "root.key"), "-online",
		hex.EncodeToString(online.Public().(ed25519.PublicKey)), "-version", "1", "-out", ksPath}); err != nil {
		t.Fatal(err)
	}
	sast := filepath.Join(dir, "sast")
	_ = os.Mkdir(sast, 0o700)
	src := filepath.Join("..", "..", "pkg", "contentpkg", "testdata", "sigstore")
	copyFile(t, filepath.Join(src, "sast-rules-0.1.0.tar.gz"), filepath.Join(sast, "sast-rules-0.1.0.tar.gz"))
	copyFile(t, filepath.Join(src, "sast-rules-0.1.0.tar.gz.sigstore.json"), filepath.Join(sast, "sast-rules-0.1.0.tar.gz.sigstore.json"))

	// A feed key set (any payload type; only its version is read).
	_, feedRoot, _ := ed25519.GenerateKey(rand.Reader)
	feedKS, _ := contentpkg.Sign(feedRoot, "application/vnd.openctem.program-feed-keyset+json", feedsign.KeySet{Kind: "x", Version: 4})
	feedPath := filepath.Join(dir, "feed.dsse.json")
	_ = os.WriteFile(feedPath, feedKS, 0o600)

	args := []string{"-keyset", ksPath, "-online-key", filepath.Join(dir, "online.key"), "-sequence", "5",
		"-sast-rules", sast, "-feed", "program-feed=" + feedPath, "-out", filepath.Join(dir, "b.tar"), "-platform", ">=0.9.0"}
	for _, p := range versions.Products() {
		args = append(args, "-image", p.Key+"=sha256:"+strings.Repeat("ab", 32)+":1500:GPL-3.0-only")
	}
	if err := build(args, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "b.tar"))
	b, err := contentpkg.ReadBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	sv, err := contentpkg.NewSigstoreVerifier("")
	if err != nil {
		t.Fatal(err)
	}
	v, err := contentpkg.Verify(b, contentpkg.VerifyOptions{
		Trust: contentpkg.Trust{Roots: []string{contentpkg.RootKeyID(root.Public().(ed25519.PublicKey))}}, Publisher: sv})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := 2 + len(versions.Products())
	if len(v.Packages) != want {
		t.Fatalf("%d packages, want %d", len(v.Packages), want)
	}
	ids := map[string]bool{}
	for _, p := range v.Packages {
		ids[p.Manifest.ID] = true
		if p.Statement.Origin != contentpkg.OriginFirstParty {
			t.Fatalf("%s origin %s", p.Manifest.ID, p.Statement.Origin)
		}
	}
	for _, id := range []string{"openctem/sast-rules", "openctem/sensor", "openctem/program-feed"} {
		if !ids[id] {
			t.Fatalf("missing %s in %v", id, ids)
		}
	}
}

func TestKeygen_RefusesOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := keygen([]string{"-out", p}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := keygen([]string{"-out", p}); err == nil {
		t.Fatal("overwrote a key")
	}
}

func TestBuild_Refusals(t *testing.T) {
	if _, _, err := parseImage("sensor=sha256:ab:12"); err == nil {
		t.Fatal("image without a license")
	}
	if _, err := feedPackage("other=/x", ">=0.9.0", time.Now()); err == nil {
		t.Fatal("unknown feed")
	}
}

// A catalog key set is valid for up to 365 days: the default signs and
// verifies, 366 is refused.
func TestKeyset_ValidityUpTo365Days(t *testing.T) {
	dir := t.TempDir()
	root := writeKey(t, dir, "root.key")
	online := writeKey(t, dir, "online.key")
	onlineHex := hex.EncodeToString(online.Public().(ed25519.PublicKey))
	ksPath := filepath.Join(dir, "keyset.dsse.json")
	args := func(days string) []string {
		return []string{"-root", filepath.Join(dir, "root.key"), "-online", onlineHex, "-version", "1", "-days", days, "-out", ksPath}
	}
	if err := keyset(args("366")); err == nil {
		t.Fatal("a 366 day key set was signed")
	}
	if err := keyset(args("365")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(ksPath)
	rootID := contentpkg.RootKeyID(root.Public().(ed25519.PublicKey))
	if _, err := feedsign.VerifyKeySet(raw, contentpkg.KeySetType, rootID, 1, time.Now().Add(300*24*time.Hour)); err != nil {
		t.Fatalf("a 365 day key set did not verify: %v", err)
	}
}
