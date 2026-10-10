// Package programfeed reads the signed bundles of the public program feed
// (RFC-065 §16, collector openctemio/programfeed, record schema
// openctem.programfeed/v1): a key set signed by the offline root, a signed
// pointer, a signed snapshot manifest and an optional signed delta manifest,
// each naming gzip JSON-lines files of programs and of changes.
//
// Verification follows the feed contract: pinned root, key-set version never
// lower than one accepted before, sequence newer than the applied one, a
// delta only when its base is the applied sequence (otherwise the snapshot),
// not expired and at most 7 days valid, every file's size and SHA-256 as the
// manifest says, every record re-validated (a bundle with one bad record is
// refused whole). Records are read through a RecordParser so the importer
// follows the collector's published schema.
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
	KindDelta           = "delta"
	LatestFile          = "latest.dsse.json"
	KeySetFile          = "keyset.dsse.json"
)

// Bounds.
const (
	MaxBundleValidity    = 7 * 24 * time.Hour
	MaxManifestBytes     = 1 << 20
	MaxFileBytes         = 64 << 20
	MaxDecompressedBytes = 512 << 20
	MaxRecordBytes       = 1 << 20
	MaxPrograms          = 100000
	MaxChanges           = 500000
)

// ManifestName is the manifest file of a kind.
func ManifestName(kind string) string { return kind + ".manifest.dsse.json" }

// FileName is a record file of a kind: programs or changes.
func FileName(kind, records string) string { return kind + "-" + records + ".jsonl.gz" }

// KeySetType is the program feed's key set.
var KeySetType = feedsign.KeySetType{PayloadType: KeySetPayloadType, Kind: KeySetKind}

// Source is one upstream source, with its license and attribution.
type Source struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	AsOf        time.Time `json:"as_of"`
	Terms       string    `json:"terms"`
	Licence     string    `json:"licence"` //nolint:misspell // the collector wire name
	Attribution string    `json:"attribution"`
	Programs    int       `json:"programs"`
}

// File is one record file of a manifest.
type File struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Records int    `json:"records"`
}

// Stats summarizes a manifest.
type Stats struct {
	Programs int `json:"programs"`
	Open     int `json:"open"`
	Bounty   int `json:"bounty"`
	Targets  int `json:"targets"`
	Rejected int `json:"rejected"`
	Changes  int `json:"changes"`
	Added    int `json:"added"`
	Closed   int `json:"closed"`
	Dropped  int `json:"dropped"`
}

// Collector names the build. LocalOnly marks an unsigned bundle a
// self-hoster built without the publish policy: never accepted on the
// signed-feed path.
type Collector struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	LocalOnly bool   `json:"local_only,omitempty"`
}

// Manifest describes a snapshot or a delta.
type Manifest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Kind         string    `json:"kind"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Sources      []Source  `json:"sources"`
	Files        []File    `json:"files"`
	Stats        Stats     `json:"stats"`
	Collector    Collector `json:"collector"`
}

// Latest points at the newest bundle.
type Latest struct {
	Schema       string    `json:"schema"`
	Sequence     uint64    `json:"sequence"`
	Tag          string    `json:"tag"`
	Snapshot     string    `json:"snapshot"`
	Delta        string    `json:"delta,omitempty"`
	BaseSequence uint64    `json:"base_sequence,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
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

// Verified is a bundle whose envelopes and the files to apply checked out.
type Verified struct {
	Dir    string
	KeySet *feedsign.KeySet
	Latest Latest
	// Use is the manifest to apply: the delta when its base is the applied
	// sequence, otherwise the snapshot.
	Use Manifest
}

// IsDelta reports whether the delta is applied.
func (v *Verified) IsDelta() bool { return v.Use.Kind == KindDelta }

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
		return nil, errors.New("pointer: expired or valid for more than 7 days")
	case l.Snapshot != ManifestName(KindSnapshot) || (l.Delta != "" && l.Delta != ManifestName(KindDelta)):
		return nil, errors.New("pointer: manifest names")
	}
	kind := KindSnapshot
	if l.Delta != "" && opt.AppliedSequence > 0 && l.BaseSequence == opt.AppliedSequence {
		kind = KindDelta
	}
	m, err := v.manifest(kind, opt)
	if err != nil {
		return nil, err
	}
	v.Use = *m
	for _, f := range m.Files {
		if err := checkFile(dir, f); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *Verified) manifest(kind string, opt Options) (*Manifest, error) {
	raw, err := readCapped(filepath.Join(v.Dir, ManifestName(kind)), MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := feedsign.VerifyWith(v.KeySet, raw, ManifestPayloadType, MaxManifestBytes, &m); err != nil {
		return nil, fmt.Errorf("%s manifest: %w", kind, err)
	}
	switch {
	case m.Schema != ManifestSchema:
		return nil, fmt.Errorf("%s manifest: schema %q", kind, m.Schema)
	case m.Kind != kind:
		return nil, fmt.Errorf("%s manifest: kind %q", kind, m.Kind)
	case m.Sequence != v.Latest.Sequence:
		return nil, fmt.Errorf("%s manifest: sequence differs from the pointer", kind)
	case m.Collector.LocalOnly:
		return nil, fmt.Errorf("%s manifest: a local-only bundle is never accepted from the signed feed", kind)
	case kind == KindDelta && m.BaseSequence != opt.AppliedSequence:
		return nil, errors.New("delta manifest: base is not the applied sequence")
	case !opt.Now.Before(m.ExpiresAt) || m.ExpiresAt.Sub(m.CreatedAt) > MaxBundleValidity:
		return nil, fmt.Errorf("%s manifest: expired or valid for more than 7 days", kind)
	case len(m.Files) != 2 || m.Files[0].Name != FileName(kind, "programs") || m.Files[1].Name != FileName(kind, "changes"):
		return nil, fmt.Errorf("%s manifest: files must be %s, %s", kind, FileName(kind, "programs"), FileName(kind, "changes"))
	}
	return &m, nil
}

func readCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the bundle directory plus a fixed or checked base name
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
	if f.Size <= 0 || f.Size > MaxFileBytes || f.Records < 0 {
		return fmt.Errorf("file %q: size", f.Name)
	}
	fh, err := os.Open(filepath.Join(dir, f.Name)) //nolint:gosec // a name the manifest check fixed
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

// RecordParser reads the record lines of the programs and changes files.
type RecordParser interface {
	Parse(line []byte) (bp.PublicProgram, error)
	ParseChange(line []byte) (bp.FeedChange, error)
}

func (v *Verified) eachLine(f File, limit int, fn func(line int, b []byte) error) error {
	fh, err := os.Open(filepath.Join(v.Dir, f.Name)) //nolint:gosec // a name the manifest check fixed
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return fmt.Errorf("file %s: %w", f.Name, err)
	}
	defer func() { _ = gz.Close() }()
	sc := bufio.NewScanner(io.LimitReader(gz, MaxDecompressedBytes))
	sc.Buffer(make([]byte, 64<<10), MaxRecordBytes)
	n := 0
	for line := 1; sc.Scan(); line++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		n++
		if n > limit {
			return fmt.Errorf("file %s: more than %d records", f.Name, limit)
		}
		if err := fn(line, sc.Bytes()); err != nil {
			return fmt.Errorf("file %s record %d: %w", f.Name, line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("file %s: %w", f.Name, err)
	}
	if n != f.Records {
		return fmt.Errorf("file %s: %d records, the manifest says %d", f.Name, n, f.Records)
	}
	return nil
}

// Read reads and validates the programs and changes of the manifest to
// apply.
func (v *Verified) Read(p RecordParser) ([]bp.PublicProgram, []bp.FeedChange, error) {
	programs := make([]bp.PublicProgram, 0, min(v.Use.Files[0].Records, MaxPrograms))
	seen := map[string]bool{}
	err := v.eachLine(v.Use.Files[0], MaxPrograms, func(_ int, b []byte) error {
		prog, err := p.Parse(b)
		if err != nil {
			return err
		}
		if err := prog.Validate(); err != nil {
			return err
		}
		if seen[prog.FeedID] {
			return fmt.Errorf("duplicate %s", prog.FeedID)
		}
		seen[prog.FeedID] = true
		prog.Sequence = v.Use.Sequence
		programs = append(programs, prog)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	var changes []bp.FeedChange
	err = v.eachLine(v.Use.Files[1], MaxChanges, func(_ int, b []byte) error {
		c, err := p.ParseChange(b)
		if err != nil {
			return err
		}
		if c.Sequence != v.Use.Sequence {
			return fmt.Errorf("change of %s has sequence %d, the bundle is %d", c.Program, c.Sequence, v.Use.Sequence)
		}
		if seen[c.Program] == (c.Kind == bp.FeedChangeDropped) {
			return fmt.Errorf("change %s of %s: a dropped program must be absent, any other present", c.Kind, c.Program)
		}
		changes = append(changes, c)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return programs, changes, nil
}
