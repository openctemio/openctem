// Package builtin holds the curated wordlist packs of the current release,
// embedded in the API so subdomain enumeration works on a fresh install
// with no import and no internet access (docs/architecture/wordlists.md).
//
// The files are the output of `go run ./cmd/wordlists-build -out
// internal/app/contentpin/builtin`: the reproducible build of the pinned
// upstream files in cmd/wordlists-build/sources.yaml. The test of this
// package checks every archive against release.json, and the release
// workflow compares the published assets with these bytes, so the embedded
// packs can only be that build.
package builtin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

//go:embed release.json wordlists-*.tar.gz
var files embed.FS

// Pack is one embedded release asset.
type Pack struct {
	// Name is the platform pack name (wordlists-s, wordlists-m).
	Name string
	// Release is the pack version.
	Release string
	// Asset is the file name of the release asset.
	Asset string
	// ArchiveSHA256 is sha256:<hex> of Archive.
	ArchiveSHA256 string
	// PackDigest is the canonical digest the platform computes on ingest.
	PackDigest string
	// Lines is the line count of each list in the pack.
	Lines map[string]int
	// Archive is the tar.gz release asset.
	Archive []byte
}

type summary struct {
	Pack          string         `json:"pack"`
	Release       string         `json:"release"`
	Asset         string         `json:"asset"`
	ArchiveSHA256 string         `json:"archive_sha256"`
	PackDigest    string         `json:"pack_digest"`
	Lines         map[string]int `json:"lines"`
}

// Packs returns the embedded packs, each checked against its recorded
// sha256. An archive that does not match is an error: nothing is installed
// from a seed that is not the recorded build.
func Packs() ([]Pack, error) {
	raw, err := files.ReadFile("release.json")
	if err != nil {
		return nil, fmt.Errorf("builtin wordlists: %w", err)
	}
	var sums []summary
	if err := json.Unmarshal(raw, &sums); err != nil {
		return nil, fmt.Errorf("builtin wordlists: release.json: %w", err)
	}
	out := make([]Pack, 0, len(sums))
	for _, s := range sums {
		data, err := files.ReadFile(s.Asset)
		if err != nil {
			return nil, fmt.Errorf("builtin wordlists: %w", err)
		}
		sum := sha256.Sum256(data)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != s.ArchiveSHA256 {
			return nil, fmt.Errorf("builtin wordlists: %s has digest %s, release.json records %s", s.Asset, got, s.ArchiveSHA256)
		}
		out = append(out, Pack{
			Name: s.Pack, Release: s.Release, Asset: s.Asset, ArchiveSHA256: s.ArchiveSHA256,
			PackDigest: s.PackDigest, Lines: s.Lines, Archive: data,
		})
	}
	return out, nil
}
