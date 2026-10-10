// Package programfeed reads the signed bundles of the public program feed
// (RFC-065 §16, collector openctemio/programfeed): a key set signed by the
// offline root, a signed pointer to the newest snapshot, its signed manifest
// and gzip JSON-lines record files. Verification follows the feed contract:
// pinned root, key-set version never lower than one accepted before,
// sequence newer than the applied one, not expired, every file's size and
// SHA-256 as the manifest says, every record valid (a bundle with one bad
// record is refused whole). Records are read through a RecordParser so the
// importer follows the collector's published schema.
package programfeed

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Format constants (must match the collector).
const (
	KeySetPayloadType   = "application/vnd.openctem.programfeed.keyset+json"
	KeySetKind          = "openctem.programfeed.keyset/v1"
	LatestPayloadType   = "application/vnd.openctem.programfeed.latest+json"
	LatestSchema        = "openctem.programfeed.latest/v1"
	ManifestPayloadType = "application/vnd.openctem.programfeed.manifest+json"
	ManifestSchema      = "openctem.programfeed/v1"
	KindSnapshot        = "snapshot"
	LatestFile          = "latest.dsse.json"
	KeySetFile          = "keyset.dsse.json"
	ProgramsFile        = "snapshot-programs.jsonl.gz"
)

// Bounds.
const (
	MaxBundleValidity    = 7 * 24 * time.Hour
	MaxManifestBytes     = 1 << 20
	MaxFileBytes         = 64 << 20
	MaxDecompressedBytes = 512 << 20
	MaxRecordBytes       = 1 << 20
	MaxPrograms          = 50000
)

var fileNameRE = regexp.MustCompile(`^[a-z0-9-]+\.jsonl\.gz$`)

// KeySetType is the program feed's key set.
var KeySetType = feedsign.KeySetType{PayloadType: KeySetPayloadType, Kind: KeySetKind}

// Source is one upstream source, with its terms and attribution.
type Source struct {
	Name        string    `json:"name"`
	AsOf        time.Time `json:"as_of"`
	Terms       string    `json:"terms"`
	Attribution string    `json:"attribution"`
}

// File is one record file of a manifest.
type File struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Records int    `json:"records"`
}

// Manifest describes a snapshot.
type Manifest struct {
	Schema    string    `json:"schema"`
	Sequence  uint64    `json:"sequence"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Sources   []Source  `json:"sources"`
	Files     []File    `json:"files"`
	Collector struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"collector"`
}

// Latest points at the newest snapshot.
type Latest struct {
	Schema    string    `json:"schema"`
	Sequence  uint64    `json:"sequence"`
	Snapshot  string    `json:"snapshot"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Options are the platform's state at verification.
type Options struct {
	PinnedRoot       string
	MinKeySetVersion uint64
	AppliedSequence  uint64
	Now              time.Time
}

// ErrNotNewer: the bundle is not newer than what was applied.
var ErrNotNewer = errors.New("bundle is not newer than the applied sequence")

// Verified is a bundle whose envelopes and files checked out.
type Verified struct {
	Dir      string
	KeySet   *feedsign.KeySet
	Latest   Latest
	Manifest Manifest
}

// VerifyDir verifies the bundle in dir.
//
//nolint:cyclop // one refusal per contract rule
func VerifyDir(dir string, opt Options) (*Verified, error) {
	raw, err := readCapped(filepath.Join(dir, KeySetFile), feedsign.MaxKeySetBytes)
	if err != nil {
		return nil, err
	}
	ks, err := feedsign.VerifyKeySet(raw, KeySetType, opt.PinnedRoot, opt.MinKeySetVersion, opt.Now)
	if err != nil {
		return nil, err
	}
	v := &Verified{Dir: dir, KeySet: ks}
	if raw, err = readCapped(filepath.Join(dir, LatestFile), MaxManifestBytes); err != nil {
		return nil, err
	}
	if err := feedsign.VerifyWith(ks, raw, LatestPayloadType, MaxManifestBytes, &v.Latest); err != nil {
		return nil, fmt.Errorf("pointer: %w", err)
	}
	l := v.Latest
	switch {
	case l.Schema != LatestSchema:
		return nil, fmt.Errorf("pointer: schema %q", l.Schema)
	case l.Sequence <= opt.AppliedSequence:
		return nil, ErrNotNewer
	case !opt.Now.Before(l.ExpiresAt) || l.ExpiresAt.Sub(l.CreatedAt) > MaxBundleValidity:
		return nil, errors.New("pointer: expired")
	case filepath.Base(l.Snapshot) != l.Snapshot || filepath.Ext(l.Snapshot) != ".json":
		return nil, errors.New("pointer: snapshot name")
	}
	if raw, err = readCapped(filepath.Join(dir, l.Snapshot), MaxManifestBytes); err != nil {
		return nil, err
	}
	if err := feedsign.VerifyWith(ks, raw, ManifestPayloadType, MaxManifestBytes, &v.Manifest); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	m := v.Manifest
	switch {
	case m.Schema != ManifestSchema:
		return nil, fmt.Errorf("manifest: schema %q", m.Schema)
	case m.Kind != KindSnapshot:
		return nil, fmt.Errorf("manifest: kind %q", m.Kind)
	case m.Sequence != l.Sequence:
		return nil, errors.New("manifest: sequence differs from the pointer")
	case !opt.Now.Before(m.ExpiresAt):
		return nil, errors.New("manifest: expired")
	case len(m.Files) != 1 || m.Files[0].Name != ProgramsFile:
		return nil, fmt.Errorf("manifest: files must be [%s]", ProgramsFile)
	}
	for _, f := range m.Files {
		if err := checkFile(dir, f); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func readCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is the bundle directory plus a checked base name
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s is over %d bytes", filepath.Base(path), maxBytes)
	}
	return b, nil
}

func checkFile(dir string, f File) error {
	if !fileNameRE.MatchString(f.Name) || f.Size <= 0 || f.Size > MaxFileBytes {
		return fmt.Errorf("file %q: name or size", f.Name)
	}
	fh, err := os.Open(filepath.Join(dir, f.Name)) //nolint:gosec // checked base name
	if err != nil {
		return fmt.Errorf("file %s: %w", f.Name, err)
	}
	defer func() { _ = fh.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(fh, MaxFileBytes+1))
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("file %s: size or sha256 differs from the manifest", f.Name)
	}
	return nil
}

// RecordParser reads one record line of the programs file.
type RecordParser interface {
	Parse(line []byte) (bp.PublicProgram, error)
}

// ReadPrograms reads and validates every program of a verified bundle.
func (v *Verified) ReadPrograms(p RecordParser) ([]bp.PublicProgram, error) {
	f := v.Manifest.Files[0]
	fh, err := os.Open(filepath.Join(v.Dir, f.Name)) //nolint:gosec // checked base name
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Name, err)
	}
	defer func() { _ = gz.Close() }()
	sc := bufio.NewScanner(io.LimitReader(gz, MaxDecompressedBytes))
	sc.Buffer(make([]byte, 64<<10), MaxRecordBytes)
	out := make([]bp.PublicProgram, 0, min(f.Records, MaxPrograms))
	seen := map[string]bool{}
	for line := 1; sc.Scan(); line++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		prog, err := p.Parse(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", line, err)
		}
		if err := prog.Validate(); err != nil {
			return nil, fmt.Errorf("record %d: %w", line, err)
		}
		if seen[prog.FeedID] {
			return nil, fmt.Errorf("record %d: duplicate %s", line, prog.FeedID)
		}
		seen[prog.FeedID] = true
		prog.Sequence = v.Manifest.Sequence
		out = append(out, prog)
		if len(out) > MaxPrograms {
			return nil, fmt.Errorf("more than %d programs", MaxPrograms)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("file %s: %w", f.Name, err)
	}
	if len(out) != f.Records {
		return nil, fmt.Errorf("file %s: %d records, the manifest says %d", f.Name, len(out), f.Records)
	}
	return out, nil
}
