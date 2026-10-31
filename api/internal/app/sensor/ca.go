package sensor

// The platform's private certificate authority (PLATFORM_CA_CERT_FILE):
// the public CA certificate(s) that sign the platform's TLS certificate when
// it is not publicly trusted (docs/how-to/sensors-behind-a-private-ca.md).
//
// The install commands carry the root's SHA-256 (SENSOR_CA_SHA256). A sensor
// that does not trust the platform's chain fetches this bundle from the
// public GET /api/v1/sensors/platform-ca and trusts only a certificate that
// matches the pin and signs the chain the server presented. The pin travels
// in the command the administrator copies from the console, the same trust
// path as the pairing code; the bundle itself needs no secrecy.
//
// Threat model: the file is operator-configured and may be misconfigured
// with a private key (a gateway's whole CA directory pointed at, a combined
// PEM). A file that holds any PRIVATE KEY block is refused as a whole, so a
// key can never reach the public endpoint or a snippet, and the refusal is
// logged. Only X.509 CA certificates are kept, re-encoded from their DER.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// PlatformCAPath is the public endpoint that serves the platform's CA
	// bundle (the sensor's SENSOR_CA_SHA256 fetch uses the same path).
	PlatformCAPath = "/api/v1/sensors/platform-ca"
	// maxCACertFileSize bounds the CA file read (a bundle is a few KB). The
	// sensor caps its fetch at the same size.
	maxCACertFileSize = 256 << 10
	// maxPlatformCACerts bounds the certificates kept from one bundle (a
	// root, its intermediates, and a root being rotated in).
	maxPlatformCACerts = 16
)

// ErrCAFileHasPrivateKey is returned for a CA file that holds a private key.
var ErrCAFileHasPrivateKey = errors.New("the CA file holds a private key; refusing it (it must hold public CA certificates only)")

// PlatformCACert describes one certificate of the platform's CA bundle.
type PlatformCACert struct {
	// CommonName is the certificate's subject CN (else the whole subject).
	CommonName string `json:"common_name"`
	// SHA256 is the SHA-256 of the DER certificate, colon-separated upper
	// case hex (what openssl x509 -fingerprint -sha256 prints).
	SHA256 string `json:"sha256"`
	// SHA256Hex is the same digest as 64 lower-case hex digits: the form the
	// install commands pass as SENSOR_CA_SHA256.
	SHA256Hex string `json:"sha256_hex"`
	// Root is true for a self-signed certificate (a root CA).
	Root bool `json:"root"`
	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after"`
}

// PlatformCA is the parsed platform CA bundle.
type PlatformCA struct {
	// PEM holds the CERTIFICATE blocks only, re-encoded.
	PEM   string
	Certs []PlatformCACert
}

// Pins returns the SENSOR_CA_SHA256 value the install commands carry: the
// lower-case hex SHA-256 of every root in the bundle that has not expired,
// comma separated (two roots while one is rotated in). A bundle without a
// root pins its CA certificates instead. Empty when nothing is pinnable.
func (c *PlatformCA) Pins(now time.Time) string {
	if c == nil {
		return ""
	}
	var roots, others []string
	for _, x := range c.Certs {
		if !x.NotAfter.After(now) {
			continue
		}
		if x.Root {
			roots = append(roots, x.SHA256Hex)
		} else {
			others = append(others, x.SHA256Hex)
		}
	}
	if len(roots) > 0 {
		return strings.Join(roots, ",")
	}
	return strings.Join(others, ",")
}

// Fingerprint is the colon-hex SHA-256 of the first root (else the first
// certificate): the one an operator compares with what a sensor prints.
func (c *PlatformCA) Fingerprint() string {
	if c == nil || len(c.Certs) == 0 {
		return ""
	}
	for _, x := range c.Certs {
		if x.Root {
			return x.SHA256
		}
	}
	return c.Certs[0].SHA256
}

// ParsePlatformCA parses a PEM bundle of CA certificates. A bundle that holds
// any private key is refused (ErrCAFileHasPrivateKey). Blocks that are not
// certificates, certificates that do not parse and certificates that are
// neither a CA nor self-signed are skipped; a bundle left empty is an error.
func ParsePlatformCA(raw []byte) (*PlatformCA, error) {
	if len(raw) > maxCACertFileSize {
		return nil, errors.New("CA certificate file is too large")
	}
	// Refuse before parsing anything: a key in a block pem.Decode cannot
	// read (bad base64) is still a key in the file.
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		return nil, ErrCAFileHasPrivateKey
	}
	out := &PlatformCA{}
	var b strings.Builder
	rest := raw
	for len(out.Certs) < maxPlatformCACerts {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, ErrCAFileHasPrivateKey
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		root := isSelfSigned(cert)
		if !root && !(cert.BasicConstraintsValid && cert.IsCA) {
			continue // a leaf certificate is not a CA anyone should pin
		}
		sum := sha256.Sum256(cert.Raw)
		out.Certs = append(out.Certs, PlatformCACert{
			CommonName: commonName(cert),
			SHA256:     colonHex(sum[:]),
			SHA256Hex:  hex.EncodeToString(sum[:]),
			Root:       root,
			NotAfter:   cert.NotAfter.UTC(),
		})
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	if len(out.Certs) == 0 {
		return nil, errors.New("no X.509 CA certificate in the CA file")
	}
	out.PEM = b.String()
	return out, nil
}

// LoadPlatformCA reads and parses the CA file. An empty path returns nil and
// no error (the feature is off).
func LoadPlatformCA(path string) (*PlatformCA, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) //nolint:gosec // operator-configured path (PLATFORM_CA_CERT_FILE)
	if err != nil {
		return nil, fmt.Errorf("open CA certificate: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxCACertFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	return ParsePlatformCA(raw)
}

// PlatformCASource serves the parsed CA file and re-reads it when its size
// or modification time changes, so a CA the gateway exports after the API
// started, or a rotated bundle, is picked up without a restart. Safe for
// concurrent use.
type PlatformCASource struct {
	path string

	mu      sync.Mutex
	ca      *PlatformCA
	err     error
	modTime time.Time
	size    int64
	loaded  bool
}

// NewPlatformCASource returns a source for path; an empty path is a source
// that is always off.
func NewPlatformCASource(path string) *PlatformCASource {
	return &PlatformCASource{path: path}
}

// Configured reports whether a CA file is set at all.
func (s *PlatformCASource) Configured() bool { return s != nil && s.path != "" }

// Path is the configured file (for logs).
func (s *PlatformCASource) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Get returns the current bundle: nil and no error when the feature is off,
// nil and the reason when the file is missing or refused.
func (s *PlatformCASource) Get() (*PlatformCA, error) {
	if !s.Configured() {
		return nil, nil
	}
	st, statErr := os.Stat(s.path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if statErr != nil {
		s.ca, s.err, s.loaded = nil, fmt.Errorf("open CA certificate: %w", statErr), false
		return nil, s.err
	}
	if s.loaded && st.ModTime().Equal(s.modTime) && st.Size() == s.size {
		return s.ca, s.err
	}
	s.ca, s.err = LoadPlatformCA(s.path)
	s.modTime, s.size, s.loaded = st.ModTime(), st.Size(), true
	return s.ca, s.err
}

func isSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

func commonName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func colonHex(b []byte) string {
	hexes := make([]string, len(b))
	for i, v := range b {
		hexes[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(hexes, ":")
}
