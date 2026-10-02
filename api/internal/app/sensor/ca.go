package sensor

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxCACertFileSize bounds the CA file read (a bundle is a few KB).
const maxCACertFileSize = 256 << 10

// LoadCACertificate reads the platform's certificate authority for the sensor
// install snippets (SENSOR_CA_CERT_FILE), e.g. the root the built-in gateway
// exports in TLS mode internal (/ca/openctem-root-ca.crt).
//
// Only CERTIFICATE blocks that parse as X.509 are returned, re-encoded: a
// file that also holds a private key (a misconfiguration) never leaks it
// into a snippet. An empty path returns nothing and no error. The fingerprint
// is the SHA-256 of the first certificate, colon-separated hex, so an
// operator can check what they install.
func LoadCACertificate(path string) (pemOut, fingerprint string, err error) {
	if path == "" {
		return "", "", nil
	}
	f, err := os.Open(path) //nolint:gosec // operator-configured path (SENSOR_CA_CERT_FILE)
	if err != nil {
		return "", "", fmt.Errorf("open CA certificate: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxCACertFileSize+1))
	if err != nil {
		return "", "", fmt.Errorf("read CA certificate: %w", err)
	}
	if len(raw) > maxCACertFileSize {
		return "", "", errors.New("CA certificate file is too large")
	}

	var b strings.Builder
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, perr := x509.ParseCertificate(block.Bytes); perr != nil {
			continue
		}
		if fingerprint == "" {
			sum := sha256.Sum256(block.Bytes)
			hexes := make([]string, len(sum))
			for i, v := range sum {
				hexes[i] = fmt.Sprintf("%02X", v)
			}
			fingerprint = strings.Join(hexes, ":")
		}
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
	}
	if b.Len() == 0 {
		return "", "", errors.New("no X.509 certificate in the CA file")
	}
	return b.String(), fingerprint, nil
}
