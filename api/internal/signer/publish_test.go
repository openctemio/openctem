package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

func TestPublishPublicKey(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := PublishPublicKey(dir, pub); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, PublicKeyFile)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || !pub.Equal(ed25519.PublicKey(raw)) {
		t.Fatalf("published content is not the public key: %q", b)
	}
	// the sensor's pin parser (sdk-go jobsig.ParseKeys) accepts base64 keys;
	// the key id it derives is the signer's own.
	if got := jobsign.NewPublicKey(raw).KeyID; got != jobsign.NewPublicKey(pub).KeyID {
		t.Fatalf("key id %s", got)
	}

	// rotation: a new key replaces the file, nothing else is left behind
	pub2, _, _ := ed25519.GenerateKey(nil)
	if err := PublishPublicKey(dir, pub2); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if raw, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); !pub2.Equal(ed25519.PublicKey(raw)) {
		t.Fatal("rotated key not published")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}

func TestPublishPublicKeyRefusals(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := PublishPublicKey("", pub); err == nil {
		t.Error("empty dir accepted")
	}
	// a missing directory is not created: a missing mount must fail loudly
	if err := PublishPublicKey(filepath.Join(t.TempDir(), "nope"), pub); err == nil {
		t.Error("missing dir accepted")
	}
	if err := PublishPublicKey(t.TempDir(), ed25519.PublicKey("short")); err == nil {
		t.Error("short key accepted")
	}
	file := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(file, nil, 0o600)
	if err := PublishPublicKey(file, pub); err == nil {
		t.Error("file as dir accepted")
	}
	// an unwritable directory is an error, never a silent skip
	ro := t.TempDir()
	_ = os.Chmod(ro, 0o500)
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if os.Getuid() != 0 {
		if err := PublishPublicKey(ro, pub); err == nil {
			t.Error("unwritable dir accepted")
		}
	}
}
