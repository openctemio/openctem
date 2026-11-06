package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PublicKeyFile is the file PublishPublicKey writes: the signer's public key
// (standard base64 of the 32 raw bytes, one line), the form a sensor's
// SENSOR_JOB_SIGNING_KEYS_FILE reads.
const PublicKeyFile = "signer.pub"

// PublishPublicKey writes the signer's PUBLIC key to dir/signer.pub (0644)
// for the installation's own sensor to pin, so that a platform which
// serves another key on first contact is not believed. The write is atomic
// (temp file in dir, then rename) and the file is replaced at every start,
// so a rotated key is republished.
//
// Threat model: dir is a volume only the signer writes and only the
// sensor mounts (read-only); the API never mounts it, so a compromised API
// cannot swap the pin. dir must already exist: it is not created here, so a
// missing mount is an error rather than a pin written to the container's
// own filesystem. Nothing secret is written.
func PublishPublicKey(dir string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("publish: not an Ed25519 public key")
	}
	if dir == "" {
		return errors.New("publish: no directory")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("publish: %s is not a directory", dir)
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.%x.tmp", PublicKeyFile, rnd))
	data := []byte(base64.StdEncoding.EncodeToString(pub) + "\n")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) // #nosec G302 G304 -- public key, operator-supplied dir
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("publish: %w", err)
	}
	if err := f.Chmod(0o644); err != nil { // not subject to the umask
		_ = f.Close()
		cleanup()
		return fmt.Errorf("publish: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("publish: %w", err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("publish: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, PublicKeyFile)); err != nil {
		cleanup()
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}
