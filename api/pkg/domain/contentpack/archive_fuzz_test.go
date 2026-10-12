package contentpack

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// FuzzCanonicalize: on any input Canonicalize either refuses with
// ErrArchive or returns a canonical archive that holds only clean relative
// paths within the limits and reads back to the same digest.
func FuzzCanonicalize(f *testing.F) {
	f.Add(makeTar(&testing.T{}, entry{name: "a.yaml", data: "a"}, entry{name: "d/b.txt", data: "b"}))
	f.Add(gz(&testing.T{}, makeTar(&testing.T{}, entry{name: "x", data: "y"})))
	f.Add([]byte{0x1f, 0x8b, 0, 0})
	f.Add([]byte("not a tar"))
	lim := Limits{MaxUpload: 1 << 20, MaxTotal: 1 << 20, MaxFiles: 64, MaxFileSize: 1 << 18, MaxDepth: 8, MaxPath: 128}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := Canonicalize(bytes.NewReader(data), lim)
		if err != nil {
			if !errors.Is(err, ErrArchive) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if len(a.Files) == 0 || len(a.Files) > lim.MaxFiles {
			t.Fatalf("%d files", len(a.Files))
		}
		var total int64
		for i, f := range a.Files {
			if strings.HasPrefix(f.Path, "/") || pathHasDotDot(f.Path) || strings.Contains(f.Path, `\`) {
				t.Fatalf("unsafe path %q", f.Path)
			}
			if i > 0 && a.Files[i-1].Path >= f.Path {
				t.Fatal("files not sorted and unique")
			}
			total += int64(len(f.Data))
		}
		if total > lim.MaxTotal {
			t.Fatalf("total %d", total)
		}
		back, err := ReadCanonical(a.Canonical, a.Digest)
		if err != nil || back.Digest != a.Digest {
			t.Fatalf("canonical form does not read back: %v", err)
		}
	})
}

func pathHasDotDot(p string) bool {
	for _, el := range strings.Split(p, "/") {
		if el == ".." {
			return true
		}
	}
	return false
}
