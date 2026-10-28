package contentpack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
)

const goodCommit = "0123456789abcdef0123456789abcdef01234567"

func manifestPack(list string, mutate func(*WordlistManifest)) map[string][]byte {
	sum := sha256.Sum256([]byte(list))
	lines := 0
	for _, l := range strings.Split(list, "\n") {
		if l != "" {
			lines++
		}
	}
	m := WordlistManifest{Version: 1, Release: "1", Pack: "wordlists-s", Class: "s", Files: []WordlistFileEntry{{
		Path: "dns/labels-s.txt", Purpose: PurposeDNSLabels, Class: "s", Lines: lines, SHA256: hex.EncodeToString(sum[:]),
		Sources: []WordlistSource{{Name: "Up", URL: "https://example.org/up", Commit: goodCommit, Path: "a.txt", SPDX: "MIT"}},
	}}}
	if mutate != nil {
		mutate(&m)
	}
	raw := fmt.Sprintf("version: %d\nrelease: %q\npack: %s\nclass: %s\nfiles:\n", m.Version, m.Release, m.Pack, m.Class)
	for _, f := range m.Files {
		raw += fmt.Sprintf("  - path: %s\n    purpose: %s\n    class: %s\n    lines: %d\n    sha256: %s\n    sources:\n", f.Path, f.Purpose, f.Class, f.Lines, f.SHA256)
		for _, s := range f.Sources {
			raw += fmt.Sprintf("      - {name: %q, url: %q, commit: %q, path: %q, spdx: %q}\n", s.Name, s.URL, s.Commit, s.Path, s.SPDX)
		}
	}
	notice := ""
	for _, f := range m.Files {
		for _, s := range f.Sources {
			notice += s.Commit + " " + s.Path + " " + s.SPDX + "\n"
		}
	}
	return map[string][]byte{"dns/labels-s.txt": []byte(list), WordlistManifestFile: []byte(raw), WordlistNoticeFile: []byte(notice)}
}

func codes(is []ManifestIssue) string {
	var c []string
	for _, i := range is {
		c = append(c, i.Code)
	}
	return strings.Join(c, ",")
}

func TestCheckWordlistPack(t *testing.T) {
	if is := CheckWordlistPack(manifestPack("www\nmail\n", nil)); len(is) != 0 {
		t.Fatalf("a true manifest is refused: %v", is)
	}
	cases := map[string]struct {
		pack map[string][]byte
		want string
	}{
		"license GPL":                   {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Sources[0].SPDX = "GPL-3.0-only" }), "WORDLIST_LICENSE_REFUSED"},
		"no license":                    {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Sources[0].SPDX = "" }), "WORDLIST_LICENSE_REFUSED"},
		"share-alike in a default pack": {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Sources[0].SPDX = "CC-BY-SA-4.0" }), "WORDLIST_LICENSE_REFUSED"},
		"unpinned":                      {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Sources[0].Commit = "master" }), "WORDLIST_SOURCE_INVALID"},
		"line count lies":               {manifestPack("www\nmail\n", func(m *WordlistManifest) { m.Files[0].Lines = 5 }), "WORDLIST_MANIFEST_MISMATCH"},
		"sha lies":                      {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].SHA256 = strings.Repeat("0", 64) }), "WORDLIST_MANIFEST_MISMATCH"},
		"url entry":                     {manifestPack("www\nhttp://evil/x\n", nil), "WORDLIST_NOT_NORMALISED"},
		"duplicate":                     {manifestPack("www\nmail\nwww\n", nil), "WORDLIST_DUPLICATE"},
		"wildcard marker":               {manifestPack("*.www\n", nil), "WORDLIST_NOT_NORMALISED"},
		"unknown purpose":               {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Purpose = "passwords" }), "WORDLIST_MANIFEST_INVALID"},
		"no sources":                    {manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Sources = nil }), "WORDLIST_SOURCE_MISSING"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := codes(CheckWordlistPack(c.pack)); !strings.Contains(got, c.want) {
				t.Fatalf("codes = %q, want %q", got, c.want)
			}
		})
	}
	t.Run("unlisted file", func(t *testing.T) {
		p := manifestPack("www\n", nil)
		p["extra.txt"] = []byte("x\n")
		if got := codes(CheckWordlistPack(p)); !strings.Contains(got, "WORDLIST_UNLISTED") {
			t.Fatal(got)
		}
	})
	t.Run("notice must record the source", func(t *testing.T) {
		p := manifestPack("www\n", nil)
		p[WordlistNoticeFile] = []byte("nothing here")
		if got := codes(CheckWordlistPack(p)); !strings.Contains(got, "WORDLIST_NOTICE_INCOMPLETE") {
			t.Fatal(got)
		}
		delete(p, WordlistNoticeFile)
		if got := codes(CheckWordlistPack(p)); !strings.Contains(got, "WORDLIST_NOTICE_MISSING") {
			t.Fatal(got)
		}
	})
}

func toFiles(m map[string][]byte) []dom.File {
	var fs []dom.File
	for p, d := range m {
		fs = append(fs, dom.File{Path: p, Data: d})
	}
	return fs
}

// A platform ingest needs the manifest; a tenant upload without one stays
// accepted; a tenant upload with a false one is refused.
func TestLintWordlistManifestPlatformAndTenant(t *testing.T) {
	ctx := context.Background()
	good := manifestPack("www\nmail\n", nil)
	if rep, _ := LintExcluding(ctx, dom.KindWordlist, toFiles(good)); len(rep.Errors) != 0 || rep.Items != 2 {
		t.Fatalf("a true pack: items=%d errors=%v", rep.Items, rep.Errors)
	}
	bare := map[string][]byte{"dns.txt": []byte("www\nmail\n")}
	if rep, _ := LintExcluding(ctx, dom.KindWordlist, toFiles(bare)); !strings.Contains(fmt.Sprint(rep.Errors), "WORDLIST_MANIFEST_MISSING") {
		t.Fatalf("a platform wordlist pack without a manifest must be refused: %v", rep.Errors)
	}
	if rep := Lint(ctx, dom.KindWordlist, toFiles(bare)); len(rep.Errors) != 0 {
		t.Fatalf("a tenant pack without a manifest stays accepted: %v", rep.Errors)
	}
	bad := manifestPack("www\n", func(m *WordlistManifest) { m.Files[0].Sources[0].SPDX = "GPL-3.0-only" })
	if rep := Lint(ctx, dom.KindWordlist, toFiles(bad)); !strings.Contains(fmt.Sprint(rep.Errors), "WORDLIST_LICENSE_REFUSED") {
		t.Fatalf("a tenant pack with a false manifest must be refused: %v", rep.Errors)
	}
}

func TestNormalizeWordlistLine(t *testing.T) {
	for _, c := range []struct {
		purpose, in, want string
		ok                bool
	}{
		{PurposeDNSLabels, "WWW", "www", true},
		{PurposeDNSLabels, "a.b.c", "a.b.c", true},
		{PurposeDNSLabels, "a.b.c.d", "", false},
		{PurposeDNSLabels, "-x", "", false},
		{PurposeDNSLabels, "*.x", "", false},
		{PurposeDNSLabels, "x_y", "", false},
		{PurposeParams, "user[id]", "user[id]", true},
		{PurposeParams, "a b", "", false},
		{PurposeWebPaths, "/admin/login", "admin/login", true},
		{PurposeWebPaths, "http://evil/x", "", false},
		{PurposeWebPaths, "../etc/passwd", "", false},
		{PurposeWebPaths, "# comment", "", false},
		{PurposeWebPaths, "a\x00b", "", false},
	} {
		got, ok := NormalizeWordlistLine(c.purpose, c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s %q = %q,%v want %q,%v", c.purpose, c.in, got, ok, c.want, c.ok)
		}
	}
}
