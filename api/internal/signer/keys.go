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
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const pemTypePrivateKey = "PRIVATE KEY"

// ErrKeyFilePermissions: the key file is readable or writable by group or
// others.
var ErrKeyFilePermissions = errors.New("signer key file must not be accessible by group or others (chmod 0400)")

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
		return nil, errors.New("signer key: expected one PEM PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signer key: %w", err)
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
	data := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der})
	if err := writeNewFile(path, data, func(f *os.File, b []byte) error { _, err := f.Write(b); return err }); err != nil {
		return nil, err
	}
	return pub, nil
}

// writeNewFile creates path (never overwriting) with mode 0400 and writes
// data. A file left half-written would be refused by the loader yet block a
// retry (the path exists), so on any failure after the create it is removed;
// that is safe because O_EXCL means this call made it.
func writeNewFile(path string, data []byte, write func(*os.File, []byte) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- operator-supplied path
	if err != nil {
		return fmt.Errorf("signer key: %w", err)
	}
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("signer key: %w", err)
	}
	if err := write(f, data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("signer key: %w", err)
	}
	return nil
}
