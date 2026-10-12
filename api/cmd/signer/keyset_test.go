package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/signer"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// The offline ceremony end to end: a root, an online key, a key set that
// verifies against the root and lists the key.
func TestKeySetCeremony(t *testing.T) {
	dir := t.TempDir()
	rootFile, onlineFile, out := filepath.Join(dir, "root.key"), filepath.Join(dir, "signer.pem"), filepath.Join(dir, "keyset.json")
	if err := run([]string{"root", "keygen", "-out", rootFile}); err != nil {
		t.Fatal(err)
	}
	online, err := signer.GenerateKey(onlineFile)
	if err != nil {
		t.Fatal(err)
	}
	b64 := jobsign.NewPublicKey(online).PublicKey
	if err := run([]string{"keyset", "sign", "-root", rootFile, "-version", "7", "-days", "30",
		"-key", b64, "-out", out}); err != nil {
		t.Fatal(err)
	}
	root, err := signer.LoadKey(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	rootID := jobsign.KeyID(root.Public().(ed25519.PublicKey))
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	ks, _, err := jobsign.VerifyKeySet(raw[:len(raw)-1], rootID, time.Now())
	if err != nil || ks.Version != 7 || !ks.HasKey(jobsign.KeyID(online)) {
		t.Fatalf("key set %+v: %v", ks, err)
	}
	if err := run([]string{"keyset", "show", "-root", rootID, out}); err != nil {
		t.Fatal(err)
	}

	// The PEM key file is accepted for -key; an existing output is never
	// overwritten; more than 30 days is refused.
	if err := run([]string{"keyset", "sign", "-root", rootFile, "-version", "8", "-days", "30",
		"-key", onlineFile, "-out", filepath.Join(dir, "keyset-8.json")}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keyset", "sign", "-root", rootFile, "-version", "9", "-days", "30",
		"-key", b64, "-out", out}); err == nil {
		t.Fatal("an existing key set file was overwritten")
	}
	if err := run([]string{"keyset", "sign", "-root", rootFile, "-version", "9", "-days", strconv.Itoa(31),
		"-key", b64, "-out", filepath.Join(dir, "k9.json")}); err == nil {
		t.Fatal("a 31-day key set was signed")
	}
}
