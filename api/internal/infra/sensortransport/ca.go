package sensortransport

// The sensor CA (RFC-059 T7, T9): it certifies sensors' registered Ed25519
// keys for the gRPC binding and signs the mTLS listener's server
// certificate. Its key is its own: it is not the job signer (RFC-040), so a
// certificate authenticates a channel and never authorizes a job.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TrustDomain is the SPIFFE trust domain of sensor certificates.
const TrustDomain = "openctem"

const (
	caValidity         = 10 * 365 * 24 * time.Hour
	serverCertValidity = 30 * 24 * time.Hour
	// clockSkew backdates NotBefore so a sensor whose clock is a little
	// behind accepts a fresh certificate.
	clockSkew = 5 * time.Minute
	// MinCertTTL and MaxCertTTL bound SENSOR_MTLS_CERT_TTL.
	MinCertTTL = time.Hour
	MaxCertTTL = 30 * 24 * time.Hour
	// DefaultCertTTL is the client certificate lifetime.
	DefaultCertTTL = 7 * 24 * time.Hour
	// caFileName is the generated CA (certificate and key, one file).
	caFileName  = "sensor-ca.pem"
	maxCAFileSz = 64 << 10
)

// CA is the sensor certificate authority.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	pool    *x509.CertPool
	now     func() time.Time

	mu     sync.Mutex
	server map[string]*tls.Certificate
}

// LoadCA reads the CA from certFile and keyFile (both PEM), or, when both
// are empty, from dir/sensor-ca.pem, creating it there once. The created
// file holds the key: mode 0600 in a 0700 directory, published with an
// atomic link so replicas sharing the directory all load the same CA.
func LoadCA(certFile, keyFile, dir string) (*CA, error) {
	switch {
	case certFile != "" && keyFile != "":
		certPEM, err := readBounded(certFile)
		if err != nil {
			return nil, fmt.Errorf("sensor CA certificate: %w", err)
		}
		keyPEM, err := readBounded(keyFile)
		if err != nil {
			return nil, fmt.Errorf("sensor CA key: %w", err)
		}
		return parseCA(certPEM, keyPEM)
	case certFile != "" || keyFile != "":
		return nil, errors.New("set both SENSOR_MTLS_CA_CERT_FILE and SENSOR_MTLS_CA_KEY_FILE, or neither")
	case dir == "":
		return nil, errors.New("no sensor CA: set SENSOR_MTLS_CA_CERT_FILE/SENSOR_MTLS_CA_KEY_FILE or SENSOR_MTLS_CA_DIR")
	}
	path := filepath.Join(dir, caFileName)
	if raw, err := readBounded(path); err == nil {
		return parseCA(raw, raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sensor CA directory: %w", err)
	}
	raw, err := newCAPEM(time.Now())
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".sensor-ca-*")
	if err != nil {
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	// Link fails if another replica published first: then its CA wins.
	if err := os.Link(tmp.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	published, err := readBounded(path)
	if err != nil {
		return nil, fmt.Errorf("sensor CA: %w", err)
	}
	return parseCA(published, published)
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxCAFileSz+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCAFileSz {
		return nil, errors.New("file too large")
	}
	return raw, nil
}

// newCAPEM creates a CA: ECDSA P-256, self-signed, path length 0.
func newCAPEM(now time.Time) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OpenCTEM sensor CA", Organization: []string{"OpenCTEM"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&b, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return b.Bytes(), nil
}

// parseCA reads the first CERTIFICATE of certPEM and the first private key
// of keyPEM, and checks they belong together and form a CA.
func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	var cert *x509.Certificate
	for rest := certPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("sensor CA certificate: %w", err)
			}
			cert = c
			break
		}
	}
	if cert == nil {
		return nil, errors.New("sensor CA: no certificate")
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("sensor CA: the certificate is not a CA")
	}
	var key crypto.Signer
	for rest := keyPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		var k any
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(b.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("sensor CA key: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("sensor CA key: unsupported key type")
		}
		key = s
		break
	}
	if key == nil {
		return nil, errors.New("sensor CA: no private key")
	}
	if !samePublicKey(cert.PublicKey, key.Public()) {
		return nil, errors.New("sensor CA: the key does not match the certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:     key,
		pool:    pool,
		now:     time.Now,
		server:  map[string]*tls.Certificate{},
	}, nil
}

func samePublicKey(a, b any) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equaler)
	return ok && ea.Equal(b)
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// CertificatePEM is the CA certificate, the bundle sensors pin.
func (c *CA) CertificatePEM() string { return string(c.certPEM) }

// Pool is the CA as a certificate pool (ClientCAs of the mTLS listener).
func (c *CA) Pool() *x509.CertPool { return c.pool }

// Fingerprint is the SHA-256 of the CA certificate, colon-separated hex.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// SensorURI is the identity a client certificate carries.
func SensorURI(tenantID, sensorID string) *url.URL {
	return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: "/tenant/" + tenantID + "/sensor/" + sensorID}
}

// IssuedCertificate is a client certificate and its validity.
type IssuedCertificate struct {
	DER       []byte
	NotBefore time.Time
	NotAfter  time.Time
}

// IssueClient certifies a sensor's registered Ed25519 key for ttl.
func (c *CA) IssueClient(pub ed25519.PublicKey, tenantID, sensorID string, ttl time.Duration) (*IssuedCertificate, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key")
	}
	ttl = ClampCertTTL(ttl)
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sensorID, OrganizationalUnit: []string{"tenant:" + tenantID}},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{SensorURI(tenantID, sensorID)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, pub, c.key)
	if err != nil {
		return nil, err
	}
	return &IssuedCertificate{DER: der, NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter}, nil
}

// ClampCertTTL keeps a client certificate lifetime in [MinCertTTL, MaxCertTTL].
func ClampCertTTL(ttl time.Duration) time.Duration {
	switch {
	case ttl <= 0:
		return DefaultCertTTL
	case ttl < MinCertTTL:
		return MinCertTTL
	case ttl > MaxCertTTL:
		return MaxCertTTL
	}
	return ttl
}

// ServerCertificate returns the mTLS listener's certificate for host, minted
// from the CA and re-minted at two thirds of its lifetime.
func (c *CA) ServerCertificate(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if cert, ok := c.server[host]; ok && cert.Leaf != nil &&
		now.Before(cert.Leaf.NotBefore.Add(cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)*2/3)) {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	c.server[host] = cert
	return cert, nil
}

// SensorIDs reads tenant and sensor from a client certificate's SPIFFE URI;
// ok is false when it carries no single well-formed sensor identity.
func SensorIDs(cert *x509.Certificate) (tenantID, sensorID string, ok bool) {
	if cert == nil || len(cert.URIs) != 1 {
		return "", "", false
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != TrustDomain || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "tenant" || parts[2] != "sensor" || !validID(parts[1]) || !validID(parts[3]) {
		return "", "", false
	}
	return parts[1], parts[3], true
}
