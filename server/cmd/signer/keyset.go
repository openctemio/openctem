package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openctemio/openctem/api/internal/signer"
	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// keysetCheckInterval is how often a running signer re-checks its key
// set's expiry.
const keysetCheckInterval = time.Hour

// rootKeygen creates the offline root key. Run it on the machine that keeps
// the root, never on the platform host.
func rootKeygen(args []string) error {
	fs := flag.NewFlagSet("root keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path of the new root key file (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("root keygen: -out is required")
	}
	pub, err := signer.GenerateKey(*out)
	if err != nil {
		return err
	}
	k := jobsign.NewPublicKey(pub)
	fmt.Printf("root keyid: %s\nroot public_key: %s\n", k.KeyID, k.PublicKey)
	fmt.Println("Keep this file offline. Sensors pin the root keyid (SENSOR_JOB_SIGNING_ROOT).")
	return nil
}

type keyArgs []string

func (k *keyArgs) String() string     { return strings.Join(*k, ",") }
func (k *keyArgs) Set(v string) error { *k = append(*k, v); return nil }

// keysetSign signs a key set with the root key.
func keysetSign(args []string) error {
	fs := flag.NewFlagSet("keyset sign", flag.ContinueOnError)
	rootFile := fs.String("root", "", "the root key file")
	version := fs.Uint64("version", 0, "key set version, higher than every version signed before")
	days := fs.Int("days", 0, "validity in days (1 to 30)")
	out := fs.String("out", "", "path of the key set file to write (must not exist)")
	var keys keyArgs
	fs.Var(&keys, "key", "an online signer public key: base64 (openctem-signer pubkey) or a PEM key file; repeat for each key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootFile == "" || *out == "" || len(keys) == 0 {
		return errors.New("keyset sign: -root, -out and at least one -key are required")
	}
	if *days < 1 || *days > int(jobsign.MaxKeySetValidity/(24*time.Hour)) {
		return fmt.Errorf("keyset sign: -days must be 1 to %d", int(jobsign.MaxKeySetValidity/(24*time.Hour)))
	}
	root, err := signer.LoadKey(*rootFile)
	if err != nil {
		return err
	}
	pubs := make([]ed25519.PublicKey, 0, len(keys))
	for _, k := range keys {
		pub, err := parsePublicKeyArg(k)
		if err != nil {
			return err
		}
		pubs = append(pubs, pub)
	}
	env, ks, err := jobsign.SignKeySet(root, *version, time.Now(), time.Duration(*days)*24*time.Hour, pubs)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) // #nosec G302 G304 -- a public document at an operator-supplied path
	if err != nil {
		return err
	}
	if _, err := f.Write(append(env, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	printKeySet(ks)
	return nil
}

// keysetShow prints a key set after checking its signature; with -root it
// also checks the pin and the clock as a sensor does.
func keysetShow(args []string) error {
	fs := flag.NewFlagSet("keyset show", flag.ContinueOnError)
	pin := fs.String("root", "", "the pinned root keyid to check against (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: keyset show [-root <keyid>] <file>")
	}
	raw, err := os.ReadFile(fs.Arg(0)) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	var ks *jobsign.KeySet
	if *pin != "" {
		ks, _, err = jobsign.VerifyKeySet([]byte(strings.TrimSpace(string(raw))), *pin, time.Now())
	} else {
		ks, _, err = jobsign.ParseKeySet([]byte(strings.TrimSpace(string(raw))))
	}
	if err != nil {
		return err
	}
	printKeySet(ks)
	return nil
}

func printKeySet(ks *jobsign.KeySet) {
	fmt.Printf("version: %d\nissued_at: %s\nnot_after: %s\nroot_keyid: %s\n",
		ks.Version, ks.IssuedAt.Format(time.RFC3339), ks.NotAfter.Format(time.RFC3339), ks.RootKeyID)
	for _, k := range ks.Keys {
		fmt.Printf("key: %s\n", k.KeyID)
	}
}

// parsePublicKeyArg reads an online key given as the base64 public key
// openctem-signer pubkey prints, or as a PEM file (PUBLIC KEY, or the
// signer's PRIVATE KEY).
func parsePublicKeyArg(v string) (ed25519.PublicKey, error) {
	if raw, err := base64.StdEncoding.DecodeString(v); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	b, err := os.ReadFile(v) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("-key %q: neither a base64 Ed25519 public key nor a readable file", v)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("-key %s: no PEM block", v)
	}
	switch block.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("-key %s: %w", v, err)
		}
		if pub, ok := k.(ed25519.PublicKey); ok {
			return pub, nil
		}
	case "PRIVATE KEY":
		priv, err := signer.LoadKey(v)
		if err != nil {
			return nil, err
		}
		pub, _ := priv.Public().(ed25519.PublicKey)
		return pub, nil
	}
	return nil, fmt.Errorf("-key %s: not an Ed25519 key", v)
}

// watchKeySet reloads the key set on SIGHUP (a key set that does not load
// is logged and the current one kept) and re-checks its expiry hourly.
func watchKeySet(ctx context.Context, svc *signer.Service, path string, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	tick := time.NewTicker(keysetCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			ks, err := svc.LoadKeySetFile(path)
			if err != nil {
				logger.Error("key set not reloaded; the current one is kept", "error", err.Error())
				continue
			}
			logger.Info("key set reloaded", "keyset_version", ks.Version, "not_after", ks.NotAfter)
			svc.CheckKeySetExpiry()
		case <-tick.C:
			svc.CheckKeySetExpiry()
		}
	}
}
