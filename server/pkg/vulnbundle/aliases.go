package vulnbundle

// The alias dictionary (RFC-066 §5.6) travels next to each release as its
// own signed manifest: aliases.manifest.dsse.json names the entries file
// (and the collector's learner state, which the platform does not read)
// with SHA-256 and size, the bundle sequence it was built with and a
// dictionary version that grows whenever the entries change.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Alias dictionary format (must match the collector).
const (
	AliasesManifestPayloadType = "application/vnd.openctem.vulnfeed.aliases+json"
	AliasesSchema              = "openctem.vulnfeed.aliases/v1"
	AliasesManifestFile        = "aliases.manifest.dsse.json"
	AliasesEntriesFile         = "aliases.jsonl.gz"
	AliasesStateFile           = "aliases-state.jsonl.gz"
	// MaxAliasesEntriesBytes caps the compressed entries file; the
	// decompressed entries are capped at four times that.
	MaxAliasesEntriesBytes = 32 << 20
)

// AliasManifest describes one alias dictionary. Stats is informational and
// kept raw, so the collector can add figures without breaking platforms.
type AliasManifest struct {
	Schema    string          `json:"schema"`
	Sequence  uint64          `json:"sequence"`
	Version   uint64          `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Files     []File          `json:"files"`
	Stats     json.RawMessage `json:"stats"`
}

// AliasCoverage is the part of the stats the feed status shows.
type AliasCoverage struct {
	Published    int     `json:"published"`
	Resolved     int     `json:"resolved"`
	Unresolvable int     `json:"unresolvable"`
	Unresolved   int     `json:"unresolved"`
	Coverage     float64 `json:"coverage"`
}

// VerifyAliasManifest checks an alias manifest envelope against the
// verified key set: the signature, the schema, that it belongs to the
// release sequence the importer applied (a dictionary of another release
// is refused, so an old one cannot be replayed with a new bundle), its
// validity window and its file list.
func VerifyAliasManifest(ks *KeySet, raw []byte, sequence uint64, now time.Time) (*AliasManifest, error) {
	var m AliasManifest
	if err := feedsign.VerifyWith(ks, raw, AliasesManifestPayloadType, MaxManifestBytes, &m); err != nil {
		return nil, fmt.Errorf("alias manifest: %w", err)
	}
	switch {
	case m.Schema != AliasesSchema:
		return nil, fmt.Errorf("alias manifest: schema %q", m.Schema)
	case m.Sequence != sequence:
		return nil, fmt.Errorf("alias manifest: built for sequence %d, the applied release is %d", m.Sequence, sequence)
	case m.Version == 0:
		return nil, errors.New("alias manifest: version 0")
	case m.ExpiresAt.Sub(m.CreatedAt) > MaxBundleValidity || !now.Before(m.ExpiresAt) || m.CreatedAt.After(now.Add(time.Hour)):
		return nil, errors.New("alias manifest: expired or outside its validity window")
	case len(m.Files) != 2 || m.Files[0].Name != AliasesEntriesFile || m.Files[1].Name != AliasesStateFile:
		return nil, errors.New("alias manifest: unexpected files")
	case m.Files[0].Size < 0 || m.Files[0].Size > MaxAliasesEntriesBytes || m.Files[0].Records < 0 || m.Files[0].Records > software.MaxFeedAliases:
		return nil, errors.New("alias manifest: entries over the caps")
	}
	return &m, nil
}

// Coverage decodes the manifest's coverage figures (zero when absent).
func (m *AliasManifest) Coverage() AliasCoverage {
	var c AliasCoverage
	_ = json.Unmarshal(m.Stats, &c)
	return c
}

type aliasEntry struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Target  string `json:"target"`
	Basis   string `json:"basis"`
	Support int    `json:"support"`
}

// ParseAliasEntries checks the entries file against the verified manifest
// (size and SHA-256) and decodes it: every line strictly, the count as the
// manifest states. Entry contents are validated again when applied.
func ParseAliasEntries(gz []byte, m *AliasManifest) ([]software.FeedAlias, error) {
	f := m.Files[0]
	sum := sha256.Sum256(gz)
	if int64(len(gz)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return nil, errors.New("alias entries: size or SHA-256 does not match the manifest")
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("alias entries: %w", err)
	}
	defer zr.Close()
	out := make([]software.FeedAlias, 0, f.Records)
	err = scanLines(&limited{r: zr, left: 4 * MaxAliasesEntriesBytes}, func(line []byte) error {
		var e aliasEntry
		if err := feedsign.DecodeStrict(line, &e); err != nil {
			return err
		}
		if len(out) >= f.Records {
			return errors.New("more entries than the manifest states")
		}
		out = append(out, software.FeedAlias{Kind: e.Kind, Value: e.Value, Target: e.Target, Basis: e.Basis})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("alias entries: %w", err)
	}
	if len(out) != f.Records {
		return nil, fmt.Errorf("alias entries: %d entries, the manifest states %d", len(out), f.Records)
	}
	return out, nil
}
