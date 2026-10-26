// Package sigstore verifies keyless Sigstore publisher signatures for content
// packages. It is a separate package so that binaries that only read the
// catalog (the admin CLI) do not link the Sigstore client.
package sigstore

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

// trustedRoot is the public Sigstore trusted root (Fulcio
// certificate authorities, transparency logs, timestamp authorities) this
// release verifies keyless signatures with, offline. Refreshed with each
// release; CONTENT_SIGSTORE_TRUSTED_ROOT points at a newer file.
//
//go:embed trusted_root.json
var trustedRoot []byte

// Verifier verifies keyless Sigstore bundles (v0.1 to v0.3, what
// `cosign sign-blob --bundle` writes) without network access: certificate
// chain to the Fulcio roots, a transparency log entry, and the certificate
// identity and issuer, both exact.
type Verifier struct {
	v *verify.Verifier
}

// New uses the trusted root at path, or the embedded one
// when path is empty.
func New(path string) (*Verifier, error) {
	raw := trustedRoot
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
	return &Verifier{v: v}, nil
}

// MaxSignatureBytes bounds publisher.sigstore.json.
const MaxSignatureBytes = 64 << 10

// Verify checks that signature is a Sigstore bundle over artifact, issued to
// exactly identity by exactly issuer, and returns when it was signed. It does
// not know about content packages: contentpkg.PublisherVerifierFunc adapts it.
func (s *Verifier) Verify(signature, artifact []byte, identity, issuer string) (time.Time, error) {
	if len(signature) == 0 || len(signature) > MaxSignatureBytes {
		return time.Time{}, fmt.Errorf("missing or over %d bytes", MaxSignatureBytes)
	}
	if identity == "" || issuer == "" {
		return time.Time{}, errors.New("no publisher identity to check")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(signature); err != nil {
		return time.Time{}, err
	}
	id, err := verify.NewShortCertificateIdentity(issuer, "", identity, "")
	if err != nil {
		return time.Time{}, err
	}
	res, err := s.v.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)), verify.WithCertificateIdentity(id)))
	if err != nil {
		return time.Time{}, err
	}
	if len(res.VerifiedTimestamps) == 0 {
		return time.Time{}, errors.New("no verified timestamp")
	}
	return res.VerifiedTimestamps[0].Timestamp.UTC(), nil
}
