package handler

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// zeros streams n zero bytes without allocating them.
type zeros struct{ n int64 }

func (z *zeros) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	clear(p)
	z.n -= int64(len(p))
	return len(p), nil
}

func zstdOf(t *testing.T, n int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(enc, &zeros{n}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipOf(t *testing.T, n int64) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := io.Copy(gz, &zeros{n}); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A tiny compressed chunk that expands far past the cap must be rejected
// without the decompressed bytes ever being held in memory. Before the fix,
// zstd DecodeAll expanded a 16 KB frame to 512 MiB and only then checked size.
func TestDecompressChunkRejectsBombs(t *testing.T) {
	const bomb = 512 << 20 // 512 MiB of zeros
	for name, data := range map[string][]byte{
		"zstd": zstdOf(t, bomb),
		"gzip": gzipOf(t, bomb),
	} {
		t.Run(name, func(t *testing.T) {
			if len(data) > 1<<20 {
				t.Fatalf("test bomb is %d bytes, expected a small payload", len(data))
			}
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			out, err := decompressChunk(name, data)

			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			if !errors.Is(err, errChunkTooLarge) {
				t.Fatalf("got err=%v (len %d), want errChunkTooLarge", err, len(out))
			}
			// Bounded by the cap plus decoder buffers, never the 512 MiB payload.
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 3*maxChunkDecompressed {
				t.Fatalf("decompression allocated %d MiB", grew>>20)
			}
		})
	}
}

func TestDecompressChunkRoundTrip(t *testing.T) {
	payload := []byte(`{"assets":[],"findings":[]}`)
	var zbuf bytes.Buffer
	enc, _ := zstd.NewWriter(&zbuf)
	_, _ = enc.Write(payload)
	_ = enc.Close()
	var gbuf bytes.Buffer
	gz := gzip.NewWriter(&gbuf)
	_, _ = gz.Write(payload)
	_ = gz.Close()

	for compression, data := range map[string][]byte{
		"zstd": zbuf.Bytes(), "": zbuf.Bytes(), "ZSTD": zbuf.Bytes(),
		"gzip": gbuf.Bytes(), "none": payload,
	} {
		out, err := decompressChunk(compression, data)
		if err != nil || !bytes.Equal(out, payload) {
			t.Errorf("%q: got %q, %v", compression, out, err)
		}
	}

	if _, err := decompressChunk("brotli", payload); !errors.Is(err, errUnsupportedChunkCompression) {
		t.Errorf("unsupported codec: got %v", err)
	}
	if _, err := decompressChunk("none", make([]byte, maxChunkDecompressed+1)); !errors.Is(err, errChunkTooLarge) {
		t.Errorf("oversized uncompressed chunk: got %v", err)
	}
	if _, err := decompressChunk("zstd", []byte("not zstd")); err == nil {
		t.Error("garbage zstd must fail")
	}
}
