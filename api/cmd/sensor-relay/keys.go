package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
	"github.com/openctemio/openctem/api/pkg/sensorproto/sealed"
)

const ingestPEMType = "OPENCTEM INGEST PRIVATE KEY"

// writeSecret creates path exclusively with mode 0400.
func writeSecret(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // the operator's output path
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

// readSecret reads a key file that only its owner may read.
func readSecret(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o; use 0400 or 0600", path, fi.Mode().Perm())
	}
	return os.ReadFile(path) //nolint:gosec // the operator's key file
}

// keygen creates a key of one kind and prints its public half.
//
//	ingest     HPKE key the connector opens sensor requests with
//	response   Ed25519 key the connector signs answers with
//	ticket     Ed25519 key tickets are signed with (its public half goes in the relay configuration)
func keygen(kind string, args []string) error {
	fs := flag.NewFlagSet(kind+"-keygen", flag.ContinueOnError)
	out := fs.String("out", "", "key file to create (0400)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	var data []byte
	var pub []byte
	switch kind {
	case "ingest":
		k, err := sealed.GenerateKey()
		if err != nil {
			return err
		}
		raw, err := k.Bytes()
		if err != nil {
			return err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: ingestPEMType, Bytes: raw})
		pub = k.Public().Bytes()
	case "response", "ticket":
		p, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		pub = p
	default:
		return fmt.Errorf("unknown key kind %q", kind)
	}
	if err := writeSecret(*out, data); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

func loadIngestKey(path string) (*sealed.PrivateKey, error) {
	raw, err := readSecret(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != ingestPEMType {
		return nil, fmt.Errorf("%s is not an ingest key", path)
	}
	return sealed.ParsePrivateKey(blk.Bytes)
}

func loadEd25519Key(path string) (ed25519.PrivateKey, error) {
	raw, err := readSecret(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PKCS#8 private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return ek, nil
}

// ticketSign mints one ticket: for an operator until the platform issues
// tickets itself.
func ticketSign(args []string) error {
	fs := flag.NewFlagSet("ticket", flag.ContinueOnError)
	keyFile := fs.String("key", "", "ticket signing key (from ticket-keygen)")
	realm := fs.String("realm", "", "realm")
	tenant := fs.String("tenant", "", "organization id")
	sensor := fs.String("sensor", "", "sensor id")
	sensorKey := fs.String("sensor-key", "", "the sensor's Ed25519 identity public key (base64)")
	relayID := fs.String("relay", "", "relay id")
	ttl := fs.Duration("ttl", 12*time.Hour, "validity (at most 24h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := loadEd25519Key(*keyFile)
	if err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*sensorKey))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("-sensor-key must be a base64 Ed25519 public key")
	}
	now := time.Now()
	tok, err := relay.SignTicket(key, relay.Ticket{V: 1, Realm: *realm, Tenant: *tenant, Sensor: *sensor, Key: pub, Relay: *relayID,
		IAT: now.Unix(), Exp: now.Add(*ttl).Unix()})
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
