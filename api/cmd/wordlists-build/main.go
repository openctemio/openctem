// Command wordlists-build builds the first-party wordlist packs (S and M)
// from pinned upstream files (research/294). Each file is read at a pinned
// commit, checked against its sha256 and its own license, normalised for the
// list's purpose, ranked, deduplicated and capped. The packs are written as
// deterministic tar.gz release assets next to a manifest of digests; the
// same pins always give the same bytes.
//
// The lists are release assets, not committed files. A super admin imports a
// release with POST /api/v1/admin/content-packs/import (url + sha256).
//
// Upstream files are untrusted data: they are only read, checked and
// counted. Nothing from them is executed or interpreted beyond line text.
//
// Usage (from api/):
//
//	go run ./cmd/wordlists-build -out dist/wordlists
//	go run ./cmd/wordlists-build -sources cmd/wordlists-build/sources.yaml -cache dir -out dist
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

//go:embed sources.yaml
var embeddedSources []byte

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wordlists-build:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("wordlists-build", flag.ContinueOnError)
	srcPath := fs.String("sources", "", "sources.yaml (default: the one built in)")
	cache := fs.String("cache", "", "directory of files named by file id, used instead of the network")
	out := fs.String("out", "", "directory for the release assets (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	data := embeddedSources
	if *srcPath != "" {
		var err error
		if data, err = os.ReadFile(*srcPath); err != nil {
			return err
		}
	}
	s, err := ParseSources(data)
	if err != nil {
		return err
	}
	var fetch Fetcher = HTTPFetcher{}
	if *cache != "" {
		fetch = DirFetcher{Dir: *cache}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	packs, err := Build(ctx, s, fetch)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		return err
	}
	type summary struct {
		Pack          string         `json:"pack"`
		Release       string         `json:"release"`
		Asset         string         `json:"asset"`
		ArchiveSHA256 string         `json:"archive_sha256"`
		PackDigest    string         `json:"pack_digest"`
		Bytes         int            `json:"bytes"`
		Lines         map[string]int `json:"lines"`
	}
	sums := make([]summary, 0, len(packs))
	for _, p := range packs {
		asset := fmt.Sprintf("%s-%s.tar.gz", p.Name, s.Release)
		if err := os.WriteFile(filepath.Join(*out, asset), p.Archive, 0o600); err != nil {
			return err
		}
		sums = append(sums, summary{p.Name, s.Release, asset, "sha256:" + p.ArchiveSHA256, p.Digest, len(p.Archive), p.Lines})
		fmt.Printf("%s  %s  %d bytes  pack %s\n", "sha256:"+p.ArchiveSHA256, asset, len(p.Archive), p.Digest)
	}
	b, err := json.MarshalIndent(sums, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "release.json"), append(b, '\n'), 0o600)
}
