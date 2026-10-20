package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
)

func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := f()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestKeygenAndLoad(t *testing.T) {
	dir := t.TempDir()
	ing := filepath.Join(dir, "ingest.pem")
	pub := capture(t, func() error { return keygen("ingest", []string{"-out", ing}) })
	if pub == "" {
		t.Fatal("no public key printed")
	}
	fi, _ := os.Stat(ing)
	if fi.Mode().Perm() != 0o400 {
		t.Fatalf("mode %04o", fi.Mode().Perm())
	}
	if _, err := loadIngestKey(ing); err != nil {
		t.Fatal(err)
	}
	// Never overwritten.
	if err := keygen("ingest", []string{"-out", ing}); err == nil {
		t.Fatal("existing key overwritten")
	}
	tk := filepath.Join(dir, "ticket.pem")
	capture(t, func() error { return keygen("ticket", []string{"-out", tk}) })
	key, err := loadEd25519Key(tk)
	if err != nil {
		t.Fatal(err)
	}
	// A key others can read is refused.
	_ = os.Chmod(tk, 0o644)
	if _, err := loadEd25519Key(tk); err == nil {
		t.Fatal("0644 key accepted")
	}
	_ = os.Chmod(tk, 0o400)
	// The ingest key is not a signing key and vice versa.
	if _, err := loadEd25519Key(ing); err == nil {
		t.Fatal("ingest key loaded as Ed25519")
	}
	if _, err := loadIngestKey(tk); err == nil {
		t.Fatal("ticket key loaded as ingest key")
	}

	sensorPub, _, _ := ed25519.GenerateKey(nil)
	tok := capture(t, func() error {
		return ticketSign([]string{"-key", tk, "-realm", "acme", "-tenant", "t1", "-sensor", "s1",
			"-sensor-key", b64(sensorPub), "-relay", "relay-1", "-ttl", "1h"})
	})
	got, err := relay.VerifyTicket(tok, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, "relay-1", time.Now())
	if err != nil || got.Sensor != "s1" || !got.KeyMatches(sensorPub) {
		t.Fatalf("minted ticket: %+v %v", got, err)
	}
	if err := ticketSign([]string{"-key", tk, "-realm", "acme", "-tenant", "t1", "-sensor", "s1",
		"-sensor-key", b64(sensorPub), "-relay", "relay-1", "-ttl", "48h"}); err == nil {
		t.Fatal("48h ticket minted")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
