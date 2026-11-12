package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/openctemio/openctem/api/internal/signer"
)

// SIGNER_GENERATE_KEY creates the key once, 0400, and never replaces an
// existing one; without it a missing key is the operator's to create.
func TestEnsureKey(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	path := filepath.Join(t.TempDir(), "signer.pem")

	t.Setenv("SIGNER_GENERATE_KEY", "")
	if err := ensureKey(path, log); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a key was created without SIGNER_GENERATE_KEY")
	}

	t.Setenv("SIGNER_GENERATE_KEY", "true")
	if err := ensureKey(path, log); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	first, err := signer.LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureKey(path, log); err != nil {
		t.Fatal(err)
	}
	again, err := signer.LoadKey(path)
	if err != nil || !again.Equal(first) {
		t.Fatal("an existing key was replaced")
	}
}
