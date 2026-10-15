package contentpkg

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// MaxPublisherSignatureBytes bounds publisher.sigstore.json.
const MaxPublisherSignatureBytes = 64 << 10

// sigstoreTrustedRoot is the public Sigstore trusted root (Fulcio
// certificate authorities, transparency logs, timestamp authorities) this
// release verifies keyless signatures with, offline. Refreshed with each
// release; CONTENT_SIGSTORE_TRUSTED_ROOT points at a newer file.
//
//go:embed sigstore/trusted_root.json
var sigstoreTrustedRoot []byte

// PublisherVerifier checks a publisher signature over an artifact and
// returns when it was signed.
type PublisherVerifier interface {
	Verify(signature, artifact []byte, want Publisher) (time.Time, error)
}

// ErrPublisherSignature: the publisher signature does not verify or names
// another identity.
var ErrPublisherSignature = errors.New("publisher signature not verified")

// SigstoreVerifier verifies keyless Sigstore bundles (v0.1 to v0.3, what
// `cosign sign-blob --bundle` writes) without network access: certificate
// chain to the Fulcio roots, a transparency log entry, and the certificate
// identity and issuer, both exact.
type SigstoreVerifier struct {
	v *verify.Verifier
}

// NewSigstoreVerifier uses the trusted root at path, or the embedded one
// when path is empty.
func NewSigstoreVerifier(path string) (*SigstoreVerifier, error) {
	raw := sigstoreTrustedRoot
	if path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- operator-configured trust file
		if err != nil {
			return nil, fmt.Errorf("sigstore trusted root: %w", err)
		}
		raw = b
	}
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("sigstore trusted root: %w", err)
	}
	v, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, fmt.Errorf("sigstore verifier: %w", err)
	}
	return &SigstoreVerifier{v: v}, nil
}

// Verify implements PublisherVerifier.
func (s *SigstoreVerifier) Verify(signature, artifact []byte, want Publisher) (time.Time, error) {
	if len(signature) == 0 || len(signature) > MaxPublisherSignatureBytes {
		return time.Time{}, fmt.Errorf("%w: missing or over %d bytes", ErrPublisherSignature, MaxPublisherSignatureBytes)
	}
	if want.Identity == "" || want.Issuer == "" {
		return time.Time{}, fmt.Errorf("%w: no publisher identity to check", ErrPublisherSignature)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(signature); err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrPublisherSignature, err)
	}
	id, err := verify.NewShortCertificateIdentity(want.Issuer, "", want.Identity, "")
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrPublisherSignature, err)
	}
	res, err := s.v.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)), verify.WithCertificateIdentity(id)))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrPublisherSignature, err)
	}
	if len(res.VerifiedTimestamps) == 0 {
		return time.Time{}, fmt.Errorf("%w: no verified timestamp", ErrPublisherSignature)
	}
	return res.VerifiedTimestamps[0].Timestamp.UTC(), nil
}
