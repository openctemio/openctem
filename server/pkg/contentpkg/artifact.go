package contentpkg

import (
	"context"
	"fmt"
	"io"
)

// CheckArtifact refuses bytes that are not the artifact a signed manifest
// names: size first, then the SHA-256 digest. Every path that reads an
// artifact (a bundle, an upload, a later fetch from storage, a mirror or a
// registry) goes through it before the bytes are used.
func CheckArtifact(b []byte, a Artifact) error {
	if int64(len(b)) != a.Size {
		return fmt.Errorf("%w: artifact size %d, the manifest says %d", ErrTampered, len(b), a.Size)
	}
	if Digest(b) != a.Digest {
		return fmt.Errorf("%w: the artifact does not match its digest", ErrTampered)
	}
	return nil
}

// ArtifactSource fetches artifact bytes by digest (storage, a mirror, an
// online catalog). Its bytes are untrusted: callers use FetchArtifact,
// never Open directly.
type ArtifactSource interface {
	Open(ctx context.Context, a Artifact) (io.ReadCloser, error)
}

// FetchArtifact reads at most a.Size+1 bytes from src and checks them with
// CheckArtifact, so a source can neither substitute content nor stream an
// unbounded body.
func FetchArtifact(ctx context.Context, src ArtifactSource, a Artifact) ([]byte, error) {
	if a.Size < 1 || a.Size > MaxArtifactBytes {
		return nil, fmt.Errorf("%w: artifact size out of range", ErrTampered)
	}
	rc, err := src.Open(ctx, a)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, a.Size+1))
	if err != nil {
		return nil, err
	}
	if err := CheckArtifact(b, a); err != nil {
		return nil, err
	}
	return b, nil
}
