package contentpack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Limits bound what an uploaded archive may hold. Every limit is checked
// before the bytes it concerns are read, so an archive bomb fails early.
type Limits struct {
	MaxUpload   int64 // the uploaded (possibly gzip-compressed) bytes
	MaxTotal    int64 // the sum of the files' sizes
	MaxFiles    int
	MaxFileSize int64
	MaxDepth    int // directory levels of a path
	MaxPath     int // bytes of a path
}

// DefaultLimits are the limits of a tenant upload.
var DefaultLimits = Limits{ //nolint:gochecknoglobals // read-only defaults
	MaxUpload:   32 << 20,
	MaxTotal:    64 << 20,
	MaxFiles:    10000,
	MaxFileSize: 8 << 20,
	MaxDepth:    16,
	MaxPath:     255,
}

// File is one regular file of a pack.
type File struct {
	Path string
	Data []byte
}

// Archive is a pack's content in canonical form: its files sorted by path,
// and the canonical tar of them, whose SHA-256 is the pack's digest.
type Archive struct {
	Files     []File
	Canonical []byte
	Digest    string
}

// Size is the canonical archive's size in bytes.
func (a *Archive) Size() int64 { return int64(len(a.Canonical)) }

// ErrArchive is a refused archive.
var ErrArchive = fmt.Errorf("%w: invalid archive", shared.ErrValidation)

func archiveErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrArchive, fmt.Sprintf(format, args...))
}

// gzipMagic opens a gzip stream.
var gzipMagic = []byte{0x1f, 0x8b}

// Canonicalize reads a tar or tar.gz archive and returns its canonical form.
//
// Only regular files and directories are accepted: a symbolic or hard link,
// a device, a FIFO or any other entry type refuses the archive, as does an
// absolute path, a ".." element, a backslash, a control character, a path
// that is not in clean form, two entries that differ only in letter case, or
// any limit exceeded. Nothing is written to disk and nothing is executed.
//
// The canonical tar holds the files only (directories are implied), sorted by
// path, each with mode 0644, owner 0:0, no user or group names and the Unix
// epoch as modification time, so the same files always give the same digest.
func Canonicalize(r io.Reader, lim Limits) (*Archive, error) {
	br := bufio.NewReader(io.LimitReader(r, lim.MaxUpload+1))
	head, _ := br.Peek(2)
	counted := &countingReader{r: br}
	var src io.Reader
	if bytes.Equal(head, gzipMagic) {
		zr, err := gzip.NewReader(counted)
		if err != nil {
			return nil, archiveErr("not a gzip stream")
		}
		zr.Multistream(false)
		// The tar stream holds headers and padding besides the files.
		src = io.LimitReader(zr, lim.MaxTotal+int64(lim.MaxFiles+16)*2048)
	} else {
		src = counted
	}

	tr := tar.NewReader(src)
	var (
		files []File
		total int64
		seen  = map[string]string{} // case-folded path -> path
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if counted.n > lim.MaxUpload {
				return nil, archiveErr("the upload is larger than %d bytes", lim.MaxUpload)
			}
			return nil, archiveErr("not a tar archive (%v)", err)
		}
		name, err := cleanPath(hdr.Name, lim)
		if err != nil {
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg: // the reader reports old-style regular files (TypeRegA) as TypeReg
		default:
			return nil, archiveErr("%s: only regular files and directories are allowed (entry type %q)", name, hdr.Typeflag)
		}
		if hdr.Size < 0 || hdr.Size > lim.MaxFileSize {
			return nil, archiveErr("%s: larger than %d bytes", name, lim.MaxFileSize)
		}
		if total += hdr.Size; total > lim.MaxTotal {
			return nil, archiveErr("the files add up to more than %d bytes", lim.MaxTotal)
		}
		if len(files) >= lim.MaxFiles {
			return nil, archiveErr("more than %d files", lim.MaxFiles)
		}
		folded := strings.ToLower(name)
		if prev, dup := seen[folded]; dup {
			return nil, archiveErr("%s: duplicate of %s", name, prev)
		}
		seen[folded] = name
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, archiveErr("%s: truncated", name)
		}
		files = append(files, File{Path: name, Data: data})
	}
	if counted.n > lim.MaxUpload {
		return nil, archiveErr("the upload is larger than %d bytes", lim.MaxUpload)
	}
	if len(files) == 0 {
		return nil, archiveErr("the archive holds no files")
	}
	// A file may not also be a directory of another file's path.
	for folded := range seen {
		for dir := path.Dir(folded); dir != "."; dir = path.Dir(dir) {
			if f, clash := seen[dir]; clash {
				return nil, archiveErr("%s is both a file and a directory", f)
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	canonical, err := canonicalTar(files)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	return &Archive{Files: files, Canonical: canonical, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// ReadCanonical parses a stored canonical archive and checks it against
// digest, so tampered storage is never served.
func ReadCanonical(data []byte, digest string) (*Archive, error) {
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("%w: stored archive does not match its digest", shared.ErrInternal)
	}
	lim := DefaultLimits
	lim.MaxUpload = int64(len(data))
	a, err := Canonicalize(bytes.NewReader(data), lim)
	if err != nil {
		return nil, err
	}
	if a.Digest != digest {
		return nil, fmt.Errorf("%w: stored archive is not canonical", shared.ErrInternal)
	}
	return a, nil
}

// epoch is the modification time of every canonical entry.
var epoch = time.Unix(0, 0).UTC() //nolint:gochecknoglobals // constant

func canonicalTar(files []File) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.Path,
			Mode:     0o644,
			Size:     int64(len(f.Data)),
			ModTime:  epoch,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("canonical archive: %w", err)
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, fmt.Errorf("canonical archive: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("canonical archive: %w", err)
	}
	return buf.Bytes(), nil
}

// cleanPath accepts a relative, clean, printable path within the limits. A
// leading "./" is dropped and a trailing "/" (directory entries) ignored.
func cleanPath(name string, lim Limits) (string, error) {
	p := strings.TrimPrefix(name, "./")
	p = strings.TrimSuffix(p, "/")
	switch {
	case p == "" || p == ".":
		return "", archiveErr("an entry has an empty path")
	case !utf8.ValidString(p):
		return "", archiveErr("an entry path is not UTF-8")
	case len(p) > lim.MaxPath:
		return "", archiveErr("%.64s...: path longer than %d bytes", p, lim.MaxPath)
	case strings.HasPrefix(p, "/"):
		return "", archiveErr("%s: absolute path", p)
	case strings.Contains(p, `\`):
		return "", archiveErr("%s: backslash in path", p)
	case strings.IndexFunc(p, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) >= 0:
		return "", archiveErr("%q: control character in path", p)
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." {
			return "", archiveErr("%s: '..' in path", p)
		}
	}
	if path.Clean(p) != p {
		return "", archiveErr("%s: path is not in clean form", p)
	}
	if strings.Count(p, "/") >= lim.MaxDepth {
		return "", archiveErr("%s: deeper than %d directories", p, lim.MaxDepth)
	}
	return p, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
