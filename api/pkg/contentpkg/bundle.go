package contentpkg

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Bundle file names.
const (
	FileKeySet      = "keyset.dsse.json"
	FileIndex       = "index.dsse.json"
	FileRevocations = "revocations.dsse.json"
	FileManifest    = "package.yaml"
	FileArtifact    = "artifact"
	FilePublisher   = "publisher.sigstore.json"
	FileStatement   = "statement.dsse.json"
)

// Bundle limits: the whole bundle is read in memory, never extracted.
const (
	MaxBundleBytes   = 128 << 20
	MaxBundleEntries = 4096
)

// ErrBundle wraps every malformed-bundle error.
var ErrBundle = errors.New("invalid bundle")

func bundleErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBundle, fmt.Sprintf(format, args...))
}

// PackageDir is the directory of a package version inside a bundle,
// derived from the id and version (never read from data).
func PackageDir(id, version string) string { return "packages/" + id + "/" + version }

// Bundle is an offline bundle read into memory.
type Bundle struct {
	files map[string][]byte
}

// File returns a file of the bundle.
func (b *Bundle) File(name string) ([]byte, bool) { f, ok := b.files[name]; return f, ok }

// maxFileBytes bounds each file by its role.
func maxFileBytes(name string) int64 {
	switch path.Base(name) {
	case FileKeySet:
		return 64 << 10
	case FileIndex, FileRevocations:
		return 4 << 20
	case FileManifest:
		return MaxManifestBytes
	case FilePublisher:
		return MaxPublisherSignatureBytes
	case FileStatement:
		return maxStatementBytes
	case FileArtifact:
		return MaxBundleBytes
	}
	return 0
}

// ReadBundle reads a bundle (tar, optionally gzip-compressed) from r. Only
// regular files at the known paths are accepted; links, devices, absolute
// or unclean paths, duplicates and unknown files are refused.
func ReadBundle(r io.Reader) (*Bundle, error) {
	limited := &io.LimitedReader{R: r, N: MaxBundleBytes + 1}
	br := bufio.NewReader(limited)
	var src io.Reader = br
	if head, err := br.Peek(2); err == nil && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, bundleErr("gzip: %v", err)
		}
		defer func() { _ = gz.Close() }()
		src = &io.LimitedReader{R: gz, N: MaxBundleBytes + 1}
	}
	tr := tar.NewReader(src)
	b := &Bundle{files: map[string][]byte{}}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, bundleErr("tar: %v", err)
		}
		if n >= MaxBundleEntries {
			return nil, bundleErr("over %d entries", MaxBundleEntries)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, bundleErr("%q is not a regular file", name)
		}
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.Contains(name, "\\") || strings.Contains(name, "..") {
			return nil, bundleErr("path %q", name)
		}
		if !knownPath(name) {
			return nil, bundleErr("unexpected file %q", name)
		}
		limit := maxFileBytes(name)
		if h.Size < 0 || h.Size > limit {
			return nil, bundleErr("%q is over %d bytes", name, limit)
		}
		if _, dup := b.files[name]; dup {
			return nil, bundleErr("%q appears twice", name)
		}
		total += h.Size
		if total > MaxBundleBytes {
			return nil, bundleErr("over %d bytes", MaxBundleBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return nil, bundleErr("read %q: %v", name, err)
		}
		if int64(len(data)) != h.Size {
			return nil, bundleErr("%q is truncated", name)
		}
		b.files[name] = data
	}
	if limited.N <= 0 {
		return nil, bundleErr("over %d bytes", MaxBundleBytes)
	}
	return b, nil
}

// knownPath accepts the top-level metadata files and the files of
// packages/<ns>/<name>/<version>/.
func knownPath(name string) bool {
	switch name {
	case FileKeySet, FileIndex, FileRevocations:
		return true
	}
	parts := strings.Split(name, "/")
	if len(parts) != 5 || parts[0] != "packages" {
		return false
	}
	if !ValidID(parts[1]+"/"+parts[2]) || !semverPattern.MatchString(parts[3]) {
		return false
	}
	switch parts[4] {
	case FileManifest, FileArtifact, FilePublisher, FileStatement:
		return true
	}
	return false
}

// VerifyOptions is what an instance has applied and how it verifies
// publishers.
type VerifyOptions struct {
	Trust Trust
	// LastIndexSequence and LastIndexDigest are the applied index: a lower
	// sequence is refused, the same one only with the same bytes.
	LastIndexSequence uint64
	LastIndexDigest   string
	// LastRevocationsSequence is the applied revocation list.
	LastRevocationsSequence uint64
	// Revoked are the entries already applied; a package they name is
	// refused even when the bundle's own list no longer names it.
	Revoked   []RevocationEntry
	Publisher PublisherVerifier
	Now       time.Time
}

// VerifiedPackage is one package version that passed every check.
type VerifiedPackage struct {
	Manifest        *Manifest
	ManifestRaw     []byte
	Statement       *Statement
	StatementRaw    []byte
	PublisherRaw    []byte
	Artifact        []byte // nil for OCI and feed artifacts
	PublisherSigned time.Time
}

// Refused is a package of the bundle that is not imported, with why.
type Refused struct {
	ID      string
	Version string
	Reason  string
}

// Verified is a bundle that passed verification.
type Verified struct {
	KeySetVersion    uint64
	Index            *Index
	IndexDigest      string
	Revocations      *Revocations
	RevocationsStale bool
	// Unchanged: the same index was applied before (a repeated import).
	Unchanged bool
	Packages  []VerifiedPackage
	Refused   []Refused
}

// Verify checks a bundle: key set, index (sequence, expiry), revocation list
// (sequence), then each package (manifest, artifact digest, catalog
// statement, publisher signature, revocation). Any failure of the metadata
// or of a package's signatures refuses the whole bundle; a revoked package
// is left out and listed in Refused.
func Verify(b *Bundle, opt VerifyOptions) (*Verified, error) {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	ksRaw, ok := b.File(FileKeySet)
	if !ok {
		return nil, bundleErr("no %s", FileKeySet)
	}
	ks, err := opt.Trust.VerifyKeySet(ksRaw, now)
	if err != nil {
		return nil, fmt.Errorf("catalog key set: %w", err)
	}
	ixRaw, ok := b.File(FileIndex)
	if !ok {
		return nil, bundleErr("no %s", FileIndex)
	}
	ix, err := VerifyIndex(ks, ixRaw, now)
	if err != nil {
		return nil, err
	}
	ixDigest := Digest(ixRaw)
	out := &Verified{KeySetVersion: ks.Version, Index: ix, IndexDigest: ixDigest}
	switch {
	case ix.Sequence < opt.LastIndexSequence:
		return nil, fmt.Errorf("%w: index sequence %d is below the applied %d", ErrRollback, ix.Sequence, opt.LastIndexSequence)
	case ix.Sequence == opt.LastIndexSequence && ixDigest != opt.LastIndexDigest:
		return nil, fmt.Errorf("%w: index sequence %d was applied with other contents", ErrRollback, ix.Sequence)
	case ix.Sequence == opt.LastIndexSequence:
		out.Unchanged = true
	}
	rvRaw, ok := b.File(FileRevocations)
	if !ok {
		return nil, bundleErr("no %s", FileRevocations)
	}
	rv, err := VerifyRevocations(ks, rvRaw, now)
	if err != nil {
		return nil, err
	}
	if rv.Sequence < opt.LastRevocationsSequence {
		return nil, fmt.Errorf("%w: revocation list sequence %d is below the applied %d", ErrRollback, rv.Sequence, opt.LastRevocationsSequence)
	}
	out.Revocations, out.RevocationsStale = rv, rv.Stale(now)

	listed := map[string]bool{}
	for _, e := range ix.Packages {
		listed[PackageDir(e.ID, e.Version)] = true
	}
	for name := range b.files {
		if dir := path.Dir(name); strings.HasPrefix(name, "packages/") && !listed[dir] {
			return nil, bundleErr("%q is not in the index", dir)
		}
	}
	for _, e := range ix.Packages {
		if entry, revoked := revokedEither(rv.Entries, opt.Revoked, e.ID, e.Version, e.ArtifactDigest); revoked {
			out.Refused = append(out.Refused, Refused{ID: e.ID, Version: e.Version, Reason: "revoked: " + entry.Reason})
			continue
		}
		vp, err := verifyPackage(b, ks, e, opt.Publisher)
		if err != nil {
			return nil, fmt.Errorf("package %s@%s: %w", e.ID, e.Version, err)
		}
		out.Packages = append(out.Packages, *vp)
	}
	sort.Slice(out.Packages, func(i, j int) bool {
		a, c := out.Packages[i].Manifest, out.Packages[j].Manifest
		if a.ID != c.ID {
			return a.ID < c.ID
		}
		return CompareVersions(a.Version, c.Version) < 0
	})
	return out, nil
}

// ErrRollback: signed metadata older than what is applied.
var ErrRollback = errors.New("rollback refused")

func revokedEither(a, b []RevocationEntry, id, version, digest string) (RevocationEntry, bool) {
	if e, ok := RevokedBy(a, id, version, digest); ok {
		return e, true
	}
	return RevokedBy(b, id, version, digest)
}

func verifyPackage(b *Bundle, ks *feedsign.KeySet, e IndexEntry, pv PublisherVerifier) (*VerifiedPackage, error) {
	dir := PackageDir(e.ID, e.Version)
	manRaw, ok := b.File(dir + "/" + FileManifest)
	if !ok {
		return nil, bundleErr("no %s", FileManifest)
	}
	if Digest(manRaw) != e.ManifestDigest {
		return nil, errors.New("package.yaml does not match the index digest")
	}
	m, err := ParseManifest(manRaw)
	if err != nil {
		return nil, err
	}
	if m.ID != e.ID || m.Version != e.Version || m.Artifact.Digest != e.ArtifactDigest {
		return nil, errors.New("the manifest does not match the index")
	}
	stRaw, ok := b.File(dir + "/" + FileStatement)
	if !ok {
		return nil, errors.New("no catalog statement (unsigned package)")
	}
	st, err := verifyStatement(ks, stRaw)
	if err != nil {
		return nil, err
	}
	if err := st.Matches(m, manRaw); err != nil {
		return nil, err
	}
	vp := &VerifiedPackage{Manifest: m, ManifestRaw: manRaw, Statement: st, StatementRaw: stRaw}
	art, hasArt := b.File(dir + "/" + FileArtifact)
	fileArtifact := !IsOCI(m.Artifact.MediaType) && m.Type != TypeFeeds
	switch {
	case fileArtifact && !hasArt:
		return nil, errors.New("the artifact is missing")
	case !fileArtifact && hasArt:
		return nil, errors.New("this artifact type is not carried in a bundle")
	case fileArtifact:
		if int64(len(art)) != m.Artifact.Size || Digest(art) != m.Artifact.Digest {
			return nil, fmt.Errorf("%w: the artifact does not match its digest", ErrTampered)
		}
		vp.Artifact = art
	}
	pubRaw, hasPub := b.File(dir + "/" + FilePublisher)
	if fileArtifact {
		if !hasPub {
			return nil, fmt.Errorf("%w: missing", ErrPublisherSignature)
		}
		if pv == nil {
			return nil, errors.New("no publisher verifier configured")
		}
		at, err := pv.Verify(pubRaw, art, st.Publisher)
		if err != nil {
			return nil, err
		}
		vp.PublisherRaw, vp.PublisherSigned = pubRaw, at
	} else if hasPub {
		return nil, errors.New("this artifact type carries no publisher signature in a bundle")
	}
	return vp, nil
}

// ErrTampered: bytes do not match their signed digest.
var ErrTampered = errors.New("tampered")
