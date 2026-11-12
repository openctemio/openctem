package vulnbundle

// The vulnerability id alias map (RFC-043 §17.2) travels next to each
// release as its own optional signed manifest: vulnids.manifest.dsse.json
// names the entries file with SHA-256, size and record count, the bundle
// sequence it was built with and a version that grows whenever the entries
// change. Each entry ties an advisory id (GHSA, or an OSV ecosystem id) to
// the one CVE it aliases.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/feedsign"
)

// Alias map format (must match the collector).
const (
	VulnIDsManifestPayloadType = "application/vnd.openctem.vulnfeed.vulnids+json"
	VulnIDsSchema              = "openctem.vulnfeed.vulnids/v1"
	VulnIDsManifestFile        = "vulnids.manifest.dsse.json"
	VulnIDsEntriesFile         = "vulnids.jsonl.gz"
	// MaxVulnIDsEntriesBytes caps the compressed entries file; the
	// decompressed entries are capped at eight times that.
	MaxVulnIDsEntriesBytes = 32 << 20
	// MaxVulnIDs caps the number of entries.
	MaxVulnIDs = 2_000_000
)

// VulnIDsManifest describes one alias map. Stats is informational and kept
// raw, so the collector can add figures without breaking platforms.
type VulnIDsManifest struct {
	Schema    string          `json:"schema"`
	Sequence  uint64          `json:"sequence"`
	Version   uint64          `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Files     []File          `json:"files"`
	Stats     json.RawMessage `json:"stats"`
}

// VerifyVulnIDsManifest checks an alias map manifest against the verified
// key set: the signature, the schema, that it was built for the release
// sequence the importer applied (an old map cannot be replayed with a new
// bundle), its validity window and its file list.
func VerifyVulnIDsManifest(ks *KeySet, raw []byte, sequence uint64, now time.Time) (*VulnIDsManifest, error) {
	var m VulnIDsManifest
	if err := feedsign.VerifyWith(ks, raw, VulnIDsManifestPayloadType, MaxManifestBytes, &m); err != nil {
		return nil, fmt.Errorf("vulnerability id manifest: %w", err)
	}
	switch {
	case m.Schema != VulnIDsSchema:
		return nil, fmt.Errorf("vulnerability id manifest: schema %q", m.Schema)
	case m.Sequence != sequence:
		return nil, fmt.Errorf("vulnerability id manifest: built for sequence %d, the applied release is %d", m.Sequence, sequence)
	case m.Version == 0:
		return nil, errors.New("vulnerability id manifest: version 0")
	case m.ExpiresAt.Sub(m.CreatedAt) > MaxBundleValidity || !now.Before(m.ExpiresAt) || m.CreatedAt.After(now.Add(time.Hour)):
		return nil, errors.New("vulnerability id manifest: expired or outside its validity window")
	case len(m.Files) < 1 || m.Files[0].Name != VulnIDsEntriesFile:
		return nil, errors.New("vulnerability id manifest: unexpected files")
	case m.Files[0].Size < 0 || m.Files[0].Size > MaxVulnIDsEntriesBytes || m.Files[0].Records < 0 || m.Files[0].Records > MaxVulnIDs:
		return nil, errors.New("vulnerability id manifest: entries over the caps")
	}
	return &m, nil
}

type vulnIDEntry struct {
	ID     string `json:"id"`
	CVE    string `json:"cve"`
	Source string `json:"source"`
}

// VulnIDsResult is what parsing kept and why it dropped the rest.
type VulnIDsResult struct {
	Entries []vulnerability.VulnIDAlias
	// Invalid counts malformed entries (skipped, not fatal).
	Invalid int
	// Conflicting counts ids listed with two different CVEs (dropped:
	// never fuse two CVEs).
	Conflicting int
}

// ParseVulnIDEntries checks the entries file against the verified manifest
// (size and SHA-256) and decodes it: every line strictly, the count as the
// manifest states. A malformed entry is skipped and counted; an id listed
// with two different CVEs is dropped entirely.
func ParseVulnIDEntries(gz []byte, m *VulnIDsManifest) (*VulnIDsResult, error) {
	f := m.Files[0]
	sum := sha256.Sum256(gz)
	if int64(len(gz)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return nil, errors.New("vulnerability id entries: size or SHA-256 does not match the manifest")
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("vulnerability id entries: %w", err)
	}
	defer zr.Close()
	res := &VulnIDsResult{}
	byID := map[string]int{}
	conflict := map[string]bool{}
	lines := 0
	err = scanLines(&limited{r: zr, left: 8 * MaxVulnIDsEntriesBytes}, func(line []byte) error {
		var e vulnIDEntry
		if err := feedsign.DecodeStrict(line, &e); err != nil {
			return err
		}
		lines++
		if lines > f.Records {
			return errors.New("more entries than the manifest states")
		}
		a := vulnerability.VulnIDAlias{ID: e.ID, CVE: e.CVE, Source: e.Source}
		if !a.Valid() {
			res.Invalid++
			return nil
		}
		if i, seen := byID[a.ID]; seen {
			if res.Entries[i].CVE != a.CVE {
				conflict[a.ID] = true
			}
			return nil
		}
		byID[a.ID] = len(res.Entries)
		res.Entries = append(res.Entries, a)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("vulnerability id entries: %w", err)
	}
	if lines != f.Records {
		return nil, fmt.Errorf("vulnerability id entries: %d entries, the manifest states %d", lines, f.Records)
	}
	if len(conflict) > 0 {
		kept := res.Entries[:0]
		for _, a := range res.Entries {
			if !conflict[a.ID] {
				kept = append(kept, a)
			}
		}
		res.Entries = kept
		res.Conflicting = len(conflict)
	}
	return res, nil
}
