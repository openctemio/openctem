// Package signer is the job-signing service (cmd/signer): it validates job
// statements against its own rules, assigns each a per-sensor sequence
// number and a nonce, signs it with a key the API never holds and records
// every decision in its own hash-chained log. Design:
// docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.6 and
// docs/architecture/job-signing.md.
//
// The package imports nothing from the API's application or
// infrastructure layers: no database, no Redis, no APP_ENCRYPTION_KEY.
package signer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const pemTypePrivateKey = "PRIVATE KEY"

// ErrKeyFilePermissions: the key file is readable or writable by group or
// others.
var ErrKeyFilePermissions = errors.New("signer key file must not be accessible by group or others (chmod 0400)")

// ErrKeyFileCorrupt: the key file exists but is not one valid Ed25519 PEM key
// (truncated, damaged or the wrong kind). It is never regenerated: a new key
// would change the signing identity.
var ErrKeyFileCorrupt = errors.New("signer key file is truncated or corrupt: restore it from the offline backup; do not delete it to regenerate (that changes the signing identity)")

// LoadKey reads an Ed25519 private key (PEM, PKCS#8) from path. A file that
// group or others can access is refused before it is read.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("signer key: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("signer key: not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyFilePermissions
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied key path
	if err != nil {
		return nil, fmt.Errorf("signer key: %w", err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != pemTypePrivateKey || len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("signer key %s: %w", path, ErrKeyFileCorrupt)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signer key %s: %w (%v)", path, ErrKeyFileCorrupt, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signer key: not an Ed25519 key")
	}
	return priv, nil
}

// GenerateKey creates a new Ed25519 key and writes it to path (PEM PKCS#8,
// mode 0400). An existing file is never overwritten.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	CleanStaleKeyTemps(path)
	data := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der})
	if err := writeNewFile(path, data, func(f *os.File, b []byte) error { _, err := f.Write(b); return err }); err != nil {
		return nil, err
	}
	return pub, nil
}

// writeNewFile publishes data at path crash-atomically and never overwrites
// an existing file. The bytes go to a temp file in the same directory (0600,
// O_EXCL, random suffix), are fsynced, then hard-linked to path: the link
// fails if path exists and makes the complete file appear in one step, so a
// kill mid-write can leave only a stale temp file (ignored by the loader and
// cleaned on the next generate), never a partial key at path. The temp is
// removed on every path and the directory is fsynced after the link.
func writeNewFile(path string, data []byte, write func(*os.File, []byte) error) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	tmp := filepath.Join(dir, tmpPrefix+base+tmpInfix+hex.EncodeToString(suffix[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := write(f, data); err != nil {
		_ = f.Close()
		return fmt.Errorf("signer key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("signer key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	if err := os.Chmod(tmp, 0o400); err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	if err := os.Link(tmp, path); err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- directory of the operator-supplied path
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

const (
	tmpPrefix = "."
	tmpInfix  = ".tmp-"
	// staleTempAge keeps a concurrent generator's live temp file safe.
	staleTempAge = time.Minute
)

// CleanStaleKeyTemps removes temp files a crashed GenerateKey left next to
// path: regular files named like this package's temp pattern for path, owned
// by this process's user and older than a minute. Nothing else is touched.
func CleanStaleKeyTemps(path string) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := tmpPrefix + base + tmpInfix
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		full := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(full)
		if err != nil || !fi.Mode().IsRegular() || time.Since(fi.ModTime()) < staleTempAge || !ownedByUs(fi) {
			continue
		}
		_ = os.Remove(full)
	}
}

func ownedByUs(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
