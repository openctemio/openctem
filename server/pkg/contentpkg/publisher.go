package contentpkg

import (
	"errors"
	"fmt"
	"time"
)

// MaxPublisherSignatureBytes bounds publisher.sigstore.json.
const MaxPublisherSignatureBytes = 64 << 10 // keep equal to sigstore.MaxSignatureBytes

// PublisherVerifier checks a publisher signature over an artifact and
// returns when it was signed. The Sigstore implementation lives in
// pkg/contentpkg/sigstore.
type PublisherVerifier interface {
	Verify(signature, artifact []byte, want Publisher) (time.Time, error)
}

// ErrPublisherSignature: the publisher signature does not verify or names
// another identity.
var ErrPublisherSignature = errors.New("publisher signature not verified")

// PublisherVerifierFunc adapts a low-level signature check (the Sigstore
// verifier) to PublisherVerifier: every failure is reported as
// ErrPublisherSignature.
type PublisherVerifierFunc func(signature, artifact []byte, identity, issuer string) (time.Time, error)

// Verify implements PublisherVerifier.
func (f PublisherVerifierFunc) Verify(signature, artifact []byte, want Publisher) (time.Time, error) {
	t, err := f(signature, artifact, want.Identity, want.Issuer)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrPublisherSignature, err)
	}
	return t, nil
}
