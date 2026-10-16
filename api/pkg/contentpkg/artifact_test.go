package contentpkg

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type memSource []byte

func (m memSource) Open(context.Context, Artifact) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m)), nil
}

func TestFetchArtifact(t *testing.T) {
	good := []byte("artifact bytes")
	a := Artifact{MediaType: MediaGzip, Digest: Digest(good), Size: int64(len(good))}
	if b, err := FetchArtifact(context.Background(), memSource(good), a); err != nil || !bytes.Equal(b, good) {
		t.Fatalf("good: %v", err)
	}
	for name, src := range map[string]memSource{
		"substituted": []byte("artifact bytez"),
		"longer":      append(append([]byte(nil), good...), 'x'),
		"shorter":     good[:3],
	} {
		if _, err := FetchArtifact(context.Background(), src, a); !errors.Is(err, ErrTampered) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
