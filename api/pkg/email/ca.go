package email

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// A CA bundle is the operator's own root of trust for an internal mail relay
// whose certificate is signed by a private CA. It is public data (certificates,
// never keys) and is used only to verify the relay's certificate in SMTP TLS.
const (
	// MaxCABundleBytes bounds the PEM text accepted.
	MaxCABundleBytes = 64 * 1024
	// MaxCACertificates bounds the certificates in one bundle.
	MaxCACertificates = 16
)

// ErrInvalidCABundle is returned for a bundle that is not a list of PEM
// certificates. The message never echoes the input.
var ErrInvalidCABundle = errors.New("invalid CA bundle")

// ParseCABundle parses a PEM bundle of CA (or self-signed server) certificates
// into a verification pool. It refuses anything but CERTIFICATE blocks (a
// pasted private key is rejected, not stored), trailing junk and bundles over
// the size limits. The fingerprint is the SHA-256 over the DER of every
// certificate in order, in hex: it changes whenever the bundle's trust changes.
func ParseCABundle(pemText string) (*x509.CertPool, string, error) {
	pemText = strings.TrimSpace(pemText)
	if pemText == "" {
		return nil, "", fmt.Errorf("%w: empty", ErrInvalidCABundle)
	}
	if len(pemText) > MaxCABundleBytes {
		return nil, "", fmt.Errorf("%w: larger than %d KB", ErrInvalidCABundle, MaxCABundleBytes/1024)
	}
	pool := x509.NewCertPool()
	h := sha256.New()
	rest := []byte(pemText)
	n := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(strings.TrimSpace(string(rest))) > 0 {
				return nil, "", fmt.Errorf("%w: text that is not a PEM certificate", ErrInvalidCABundle)
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			// Includes PRIVATE KEY blocks: never accepted, never stored.
			return nil, "", fmt.Errorf("%w: only CERTIFICATE blocks are accepted", ErrInvalidCABundle)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("%w: a certificate does not parse", ErrInvalidCABundle)
		}
		n++
		if n > MaxCACertificates {
			return nil, "", fmt.Errorf("%w: more than %d certificates", ErrInvalidCABundle, MaxCACertificates)
		}
		pool.AddCert(cert)
		h.Write(cert.Raw)
	}
	if n == 0 {
		return nil, "", fmt.Errorf("%w: no certificate found", ErrInvalidCABundle)
	}
	return pool, hex.EncodeToString(h.Sum(nil)), nil
}

// Failure reasons of ClassifySendError. They are safe to show to a super admin
// (no server reply text, no address).
const (
	ReasonUnknownAuthority = "unknown_authority"
	ReasonHostnameMismatch = "hostname_mismatch"
	ReasonCertInvalid      = "certificate_invalid"
	ReasonTLSFailed        = "tls_failed"
	ReasonAuthFailed       = "auth_failed"
	ReasonAuthRequired     = "auth_required"
	ReasonSenderRejected   = "sender_rejected"
	ReasonRelayDenied      = "relay_denied"
	ReasonHostRejected     = "host_rejected"
	ReasonConnectFailed    = "connect_failed"
	ReasonTimeout          = "timeout"
	ReasonNotConfigured    = "not_configured"
	ReasonUnknown          = "unknown"
)

// ClassifySendError names why a send failed, in terms an administrator can act
// on. It never returns text from the server.
func ClassifySendError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrNotConfigured) {
		return ReasonNotConfigured
	}
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.As(err, &ua):
		return ReasonUnknownAuthority
	case errors.As(err, &he):
		return ReasonHostnameMismatch
	case errors.As(err, &ci):
		return ReasonCertInvalid
	}
	msg := err.Error()
	var tp *textproto.Error
	haveCode := errors.As(err, &tp)
	switch {
	case strings.Contains(msg, "smtp host rejected"):
		return ReasonHostRejected
	case strings.Contains(msg, "failed to start TLS"), strings.Contains(msg, "TLS handshake"):
		return ReasonTLSFailed
	case strings.Contains(msg, "authentication failed"):
		return ReasonAuthFailed
	case strings.Contains(msg, "failed to set recipient"):
		return ReasonRelayDenied
	case strings.Contains(msg, "failed to set sender"):
		if haveCode && tp.Code == 530 {
			return ReasonAuthRequired
		}
		return ReasonSenderRejected
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonTimeout
	}
	if strings.Contains(msg, "failed to connect") {
		return ReasonConnectFailed
	}
	return ReasonUnknown
}
