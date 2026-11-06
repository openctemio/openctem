package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/app/contentpin/builtin"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

const fixtureSources = `
release: "2026.01.1"
sources:
  - id: up
    name: Upstream
    repo: https://example.org/up
    commit: 0123456789abcdef0123456789abcdef01234567
    raw: https://raw.githubusercontent.com/o/r/{commit}/{path}
    copyright: "Copyright (c) Someone"
    files:
      - {id: a, path: a.txt, sha256: %s, spdx: MIT, evidence: "LICENSE is MIT"}
      - {id: b, path: dir/b.txt, sha256: %s, spdx: Apache-2.0, evidence: "LICENSE is Apache-2.0"}
%s
excluded:
  - {source: Upstream, path: gpl.txt, spdx: GPL-3.0-only, reason: "GPL upstream"}
packs:
  - name: wordlists-s
    class: s
    lists:
      - {path: dns/labels-s.txt, purpose: dns-labels, cap: 4, from: [a, b]}
`

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// fixture writes the cache dir and returns the parsed sources.
func fixture(t *testing.T, a, b string, extra string) (*Sources, DirFetcher) {
	t.Helper()
	dir := t.TempDir()
	for id, data := range map[string]string{"a": a, "b": b} {
		if err := os.WriteFile(filepath.Join(dir, id), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := strings.Replace(fixtureSources, "%s", sum([]byte(a)), 1)
	src = strings.Replace(src, "%s", sum([]byte(b)), 1)
	src = strings.Replace(src, "%s", extra, 1)
	s, err := ParseSources([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return s, DirFetcher{Dir: dir}
}

func TestBuildRanksDedupsCapsAndIsReproducible(t *testing.T) {
	s, f := fixture(t, "www\nmail\napi\nwww\n", "dev\nwww\nmail\nstaging\n", "")
	p1, err := Build(context.Background(), s, f)
	if err != nil {
		t.Fatal(err)
	}
	got := string(p1[0].Files["dns/labels-s.txt"])
	// Positions: www0 mail1 api2 (a); dev0 www1 mail2 staging3 (b). Best
	// position wins, ties go to the earlier input, then the cap of 4.
	if want := "www\ndev\nmail\napi\n"; got != want {
		t.Fatalf("list = %q, want %q", got, want)
	}
	p2, err := Build(context.Background(), s, f)
	if err != nil {
		t.Fatal(err)
	}
	if p1[0].ArchiveSHA256 != p2[0].ArchiveSHA256 || p1[0].Digest != p2[0].Digest {
		t.Fatal("two builds of the same pins differ")
	}
	notice := string(p1[0].Files[contentpack.WordlistNoticeFile])
	for _, want := range []string{"0123456789abcdef0123456789abcdef01234567", "a.txt", "dir/b.txt", "Apache-2.0", "gpl.txt", "GPL upstream"} {
		if !strings.Contains(notice, want) {
			t.Errorf("NOTICE lacks %q", want)
		}
	}
	// The platform accepts the archive as it is.
	arc, err := dom.Canonicalize(bytes.NewReader(p1[0].Archive), dom.PlatformLimits)
	if err != nil {
		t.Fatal(err)
	}
	if rep := contentpack.Lint(context.Background(), dom.KindWordlist, arc.Files); len(rep.Errors) > 0 {
		t.Fatalf("lint: %+v", rep.Errors)
	}
}

func TestBuildDropsURLsNULAndInvalidEntries(t *testing.T) {
	s, f := fixture(t, "www\nhttp://evil.example/x\n*.wild\nbad_label\nok\x00nul\nUPPER\n", "mail\n", "")
	p, err := Build(context.Background(), s, f)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(p[0].Files["dns/labels-s.txt"]), "www\nmail\nupper\n"; got != want {
		t.Fatalf("list = %q, want %q", got, want)
	}
	if p[0].Dropped["dns/labels-s.txt"] != 4 {
		t.Fatalf("dropped = %d, want 4", p[0].Dropped["dns/labels-s.txt"])
	}
}

func TestBuildRefusesAChangedUpstreamFile(t *testing.T) {
	s, f := fixture(t, "www\n", "mail\n", "")
	if err := os.WriteFile(filepath.Join(f.Dir, "a"), []byte("www\nevil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), s, f); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("a changed file must fail its pin, got %v", err)
	}
}

// A copyleft file inside a permissively licensed repository is refused per
// file, whatever the repository says.
func TestBuildRefusesAFileWithACopyleftLicense(t *testing.T) {
	gpl := `      - {id: c, path: gpl.txt, sha256: ` + sum([]byte("x\n")) + `, spdx: GPL-3.0-only, evidence: "upstream is GPL"}`
	s, f := fixture(t, "www\n", "mail\n", gpl)
	if err := os.WriteFile(filepath.Join(f.Dir, "c"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), s, f)
	if err == nil || !strings.Contains(err.Error(), "allow-list") {
		t.Fatalf("GPL file must be refused, got %v", err)
	}
	for _, lic := range []string{"AGPL-3.0-only", "NOASSERTION", "", "CC-BY-SA-4.0"} {
		if contentpack.LicenseAllowed(lic, false) {
			t.Errorf("%q must not be allowed in a default pack", lic)
		}
	}
	if !contentpack.LicenseAllowed("CC-BY-SA-4.0", true) || !contentpack.LicenseAllowed("MIT", false) {
		t.Error("allow-list wrong")
	}
}

func TestParseSourcesRejectsBadPins(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"short commit":     func(s string) string { return strings.Replace(s, "0123456789abcdef0123456789abcdef01234567", "abc", 1) },
		"undeclared input": func(s string) string { return strings.Replace(s, "from: [a, b]", "from: [a, zz]", 1) },
		"unknown purpose":  func(s string) string { return strings.Replace(s, "dns-labels", "passwords", 1) },
		"path traversal":   func(s string) string { return strings.Replace(s, "path: dir/b.txt", "path: ../b.txt", 1) },
		"no evidence":      func(s string) string { return strings.Replace(s, `evidence: "LICENSE is MIT"`, `evidence: ""`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			src := strings.NewReplacer("%s", strings.Repeat("a", 64)).Replace(edit(fixtureSources))
			if _, err := ParseSources([]byte(src)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestHTTPFetcherOnlyAllowedHostsOverHTTPS(t *testing.T) {
	for _, raw := range []string{"http://raw.githubusercontent.com/{commit}/{path}", "https://evil.example/{commit}/{path}", "https://user@raw.githubusercontent.com/{commit}/{path}"} {
		_, err := HTTPFetcher{}.Fetch(context.Background(), Source{Commit: strings.Repeat("a", 40), Raw: raw}, SourceFile{ID: "x", Path: "p"})
		if err == nil || !strings.Contains(err.Error(), "allowed host") {
			t.Errorf("%s: got %v", raw, err)
		}
	}
}

// The release the repository ships parses and every file it names is
// licensed on the allow-list.
func TestEmbeddedSourcesAreValid(t *testing.T) {
	s, err := ParseSources(embeddedSources)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range s.Sources {
		for _, f := range src.Files {
			if !contentpack.LicenseAllowed(f.SPDX, false) {
				t.Errorf("%s: %s is not allowed", f.ID, f.SPDX)
			}
		}
	}
	if len(s.Excluded) == 0 {
		t.Error("the excluded list must not be empty")
	}
}

// The packs the API embeds are of the release sources.yaml names: a change
// to the pins raises `release` and must rebuild the embedded packs
// (go run ./cmd/wordlists-build -out internal/app/contentpin/builtin); the
// release workflow then checks the published assets are those bytes.
func TestBuiltinPacksMatchTheRelease(t *testing.T) {
	s, err := ParseSources(embeddedSources)
	if err != nil {
		t.Fatal(err)
	}
	packs, err := builtin.Packs()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) == 0 {
		t.Fatal("no built-in packs")
	}
	for _, p := range packs {
		if p.Release != s.Release {
			t.Errorf("built-in %s is release %s, sources.yaml names %s: rebuild the built-in packs", p.Name, p.Release, s.Release)
		}
	}
}
