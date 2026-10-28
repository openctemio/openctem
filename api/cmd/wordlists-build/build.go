package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/internal/app/contentpack"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Sources is sources.yaml: what the packs are built from.
type Sources struct {
	Release  string       `yaml:"release"`
	Sources  []Source     `yaml:"sources"`
	Excluded []Excluded   `yaml:"excluded"`
	Packs    []PackConfig `yaml:"packs"`
}

// Source is one upstream repository, pinned to a commit.
type Source struct {
	ID        string       `yaml:"id"`
	Name      string       `yaml:"name"`
	Repo      string       `yaml:"repo"`
	Commit    string       `yaml:"commit"`
	Raw       string       `yaml:"raw"`
	Copyright string       `yaml:"copyright"`
	Files     []SourceFile `yaml:"files"`
}

// SourceFile is one upstream file: pinned by sha256, with its own license.
type SourceFile struct {
	ID       string `yaml:"id"`
	Path     string `yaml:"path"`
	SHA256   string `yaml:"sha256"`
	SPDX     string `yaml:"spdx"`
	Evidence string `yaml:"evidence"`
}

// Excluded is a file left out of every pack, with the reason.
type Excluded struct {
	Source string `yaml:"source"`
	Path   string `yaml:"path"`
	SPDX   string `yaml:"spdx"`
	Reason string `yaml:"reason"`
}

// PackConfig is one pack of the release.
type PackConfig struct {
	Name  string       `yaml:"name"`
	Class string       `yaml:"class"`
	OptIn bool         `yaml:"opt_in"`
	Lists []ListConfig `yaml:"lists"`
}

// ListConfig is one list of a pack.
type ListConfig struct {
	Path    string   `yaml:"path"`
	Purpose string   `yaml:"purpose"`
	Cap     int      `yaml:"cap"`
	From    []string `yaml:"from"`
}

// ParseSources reads sources.yaml (unknown keys are an error) and checks it
// before anything is fetched: pins well formed, licenses on the allow-list,
// every list drawn from declared files.
func ParseSources(data []byte) (*Sources, error) {
	var s Sources
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("sources.yaml: %w", err)
	}
	if s.Release == "" {
		return nil, errors.New("sources.yaml: release is required")
	}
	files := map[string]bool{}
	for _, src := range s.Sources {
		if src.ID == "" || src.Name == "" || len(src.Commit) != 40 || !strings.Contains(src.Raw, "{commit}") || !strings.Contains(src.Raw, "{path}") {
			return nil, fmt.Errorf("sources.yaml: source %q needs id, name, a 40-hex commit and a raw url template", src.ID)
		}
		if u, err := url.Parse(src.Repo); err != nil || u.Scheme != "https" {
			return nil, fmt.Errorf("sources.yaml: source %q: repo must be an https url", src.ID)
		}
		for _, f := range src.Files {
			if f.ID == "" || files[f.ID] {
				return nil, fmt.Errorf("sources.yaml: file id %q is empty or repeated", f.ID)
			}
			files[f.ID] = true
			if len(f.SHA256) != 64 || !cleanSourcePath(f.Path) || f.Evidence == "" {
				return nil, fmt.Errorf("sources.yaml: file %q needs a clean path, a sha256 and evidence of its license", f.ID)
			}
		}
	}
	for _, p := range s.Packs {
		if !contains(contentpack.WordlistClasses, p.Class) {
			return nil, fmt.Errorf("sources.yaml: pack %q has unknown class %q", p.Name, p.Class)
		}
		for _, l := range p.Lists {
			if !contains(contentpack.WordlistPurposes, l.Purpose) || l.Cap <= 0 || len(l.From) == 0 || !cleanSourcePath(l.Path) {
				return nil, fmt.Errorf("sources.yaml: list %q of %s needs a known purpose, a cap and inputs", l.Path, p.Name)
			}
			for _, id := range l.From {
				if !files[id] {
					return nil, fmt.Errorf("sources.yaml: list %q draws from undeclared file %q", l.Path, id)
				}
			}
		}
	}
	return &s, nil
}

func cleanSourcePath(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, "..") && path.Clean(p) == p
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// Fetcher returns the bytes of an upstream file. Nothing it returns is
// trusted: the caller checks the pinned sha256 before reading a line.
type Fetcher interface {
	Fetch(ctx context.Context, src Source, f SourceFile) ([]byte, error)
}

// maxUpstreamFile bounds one upstream file (the platform's per-file limit).
const maxUpstreamFile = 32 << 20

// HTTPFetcher reads files over https from the hosts a sources.yaml may use.
type HTTPFetcher struct {
	Client *http.Client
	// Hosts are the hosts allowed (default: raw.githubusercontent.com).
	Hosts []string
}

// Fetch implements Fetcher.
func (h HTTPFetcher) Fetch(ctx context.Context, src Source, f SourceFile) ([]byte, error) {
	raw := strings.NewReplacer("{commit}", src.Commit, "{path}", f.Path).Replace(src.Raw)
	u, err := url.Parse(raw)
	hosts := h.Hosts
	if len(hosts) == 0 {
		hosts = []string{"raw.githubusercontent.com"}
	}
	if err != nil || u.Scheme != "https" || u.User != nil || !contains(hosts, u.Host) {
		return nil, fmt.Errorf("%s: %q is not an https url on an allowed host", f.ID, raw)
	}
	cl := h.Client
	if cl == nil {
		cl = httpsec.SafeHTTPClient(2 * time.Minute)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", f.ID, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUpstreamFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", f.ID, maxUpstreamFile)
	}
	return data, nil
}

// DirFetcher reads files from a directory laid out as <dir>/<file id>: a
// cache of files fetched earlier, or a fixture. They are checked like any
// other download.
type DirFetcher struct{ Dir string }

// Fetch implements Fetcher.
func (d DirFetcher) Fetch(_ context.Context, _ Source, f SourceFile) ([]byte, error) {
	if strings.ContainsAny(f.ID, `/\`) {
		return nil, fmt.Errorf("bad file id %q", f.ID)
	}
	return os.ReadFile(filepath.Join(d.Dir, f.ID)) //nolint:gosec // the id has no separator; the content is checked against its pin
}

// Pack is one built pack.
type Pack struct {
	Name string
	// Files are the pack's files by path.
	Files map[string][]byte
	// Archive is the deterministic tar.gz release asset; ArchiveSHA256 its
	// digest (what the import route takes), Digest the pack's own content
	// digest once imported.
	Archive       []byte
	ArchiveSHA256 string
	Digest        string
	Lines         map[string]int
	// Refused lists upstream entries dropped by normalisation, by list.
	Dropped map[string]int
}

// Build fetches every pinned file, checks its sha256 and license, builds
// the packs and lints each with the platform's wordlist linter.
func Build(ctx context.Context, s *Sources, fetch Fetcher) ([]Pack, error) {
	type loaded struct {
		src  Source
		file SourceFile
		data []byte
	}
	byID := map[string]loaded{}
	for _, src := range s.Sources {
		for _, f := range src.Files {
			if !contentpack.LicenseAllowed(f.SPDX, false) {
				// Refused before it is fetched: a file whose own license is
				// not on the allow-list never enters a build.
				return nil, fmt.Errorf("%s (%s): license %q is not on the allow-list; move it to excluded", f.ID, f.Path, f.SPDX)
			}
			data, err := fetch.Fetch(ctx, src, f)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(data)
			if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
				return nil, fmt.Errorf("%s: sha256 is %s, pinned %s (upstream changed or the download was altered)", f.ID, got, f.SHA256)
			}
			byID[f.ID] = loaded{src, f, data}
		}
	}
	out := make([]Pack, 0, len(s.Packs))
	for _, pc := range s.Packs {
		p := Pack{Name: pc.Name, Files: map[string][]byte{}, Lines: map[string]int{}, Dropped: map[string]int{}}
		m := contentpack.WordlistManifest{Version: 1, Release: s.Release, Pack: pc.Name, Class: pc.Class, OptIn: pc.OptIn}
		var usedSources []contentpack.WordlistSource
		for _, lc := range pc.Lists {
			inputs := make([][]byte, len(lc.From))
			var srcs []contentpack.WordlistSource
			for i, id := range lc.From {
				l := byID[id]
				inputs[i] = l.data
				srcs = append(srcs, contentpack.WordlistSource{
					Name: l.src.Name, URL: l.src.Repo, Commit: l.src.Commit, Path: l.file.Path, SPDX: l.file.SPDX,
				})
			}
			list, dropped := RankMerge(lc.Purpose, inputs, lc.Cap)
			p.Files[lc.Path] = list
			sum := sha256.Sum256(list)
			n := bytes.Count(list, []byte("\n"))
			p.Lines[lc.Path] = n
			p.Dropped[lc.Path] = dropped
			m.Files = append(m.Files, contentpack.WordlistFileEntry{
				Path: lc.Path, Purpose: lc.Purpose, Class: pc.Class, Lines: n, SHA256: hex.EncodeToString(sum[:]), Sources: srcs,
			})
			usedSources = append(usedSources, srcs...)
		}
		mb, err := yaml.Marshal(&m)
		if err != nil {
			return nil, err
		}
		p.Files[contentpack.WordlistManifestFile] = mb
		p.Files[contentpack.WordlistNoticeFile] = []byte(Notice(s, pc, usedSources))
		if err := finishPack(ctx, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", pc.Name, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// finishPack lints the pack as the platform will, builds the release
// archive and checks the platform accepts it.
func finishPack(ctx context.Context, p *Pack) error {
	files := make([]dom.File, 0, len(p.Files))
	for name, data := range p.Files {
		files = append(files, dom.File{Path: name, Data: data})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	rep, excluded := contentpack.LintExcluding(ctx, dom.KindWordlist, files)
	if len(rep.Errors) > 0 || len(excluded) > 0 {
		return fmt.Errorf("lint refused the pack: %+v %+v", rep.Errors, rep.Warnings)
	}
	archive, err := deterministicTarGz(files)
	if err != nil {
		return err
	}
	arc, err := dom.Canonicalize(bytes.NewReader(archive), dom.PlatformLimits)
	if err != nil {
		return fmt.Errorf("the platform would refuse the archive: %w", err)
	}
	sum := sha256.Sum256(archive)
	p.Archive, p.ArchiveSHA256, p.Digest = archive, hex.EncodeToString(sum[:]), arc.Digest
	return nil
}

// deterministicTarGz writes the files sorted by path with fixed metadata and
// no gzip header time: the same files give the same bytes.
func deterministicTarGz(files []dom.File) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.ModTime = time.Time{}
	tw := tar.NewWriter(zw)
	for _, f := range files {
		h := &tar.Header{Name: f.Path, Mode: 0o644, Size: int64(len(f.Data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RankMerge merges lists into one: every raw line is normalised for the
// purpose, a repeated entry keeps its best position, entries are ordered by
// that position (ties go to the earlier input) and the first cap are kept.
// It returns the list, one entry per line, and how many raw lines were
// dropped as invalid.
func RankMerge(purpose string, inputs [][]byte, limit int) ([]byte, int) {
	type entry struct{ pos, input int }
	best := map[string]entry{}
	dropped := 0
	for i, in := range inputs {
		pos := 0
		for _, line := range strings.Split(string(in), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			n, ok := contentpack.NormalizeWordlistLine(purpose, line)
			if !ok {
				dropped++
				continue
			}
			if e, seen := best[n]; !seen || pos < e.pos {
				best[n] = entry{pos, i}
			}
			pos++
		}
	}
	names := make([]string, 0, len(best))
	for n := range best {
		names = append(names, n)
	}
	sort.Slice(names, func(a, b int) bool {
		ea, eb := best[names[a]], best[names[b]]
		if ea.pos != eb.pos {
			return ea.pos < eb.pos
		}
		if ea.input != eb.input {
			return ea.input < eb.input
		}
		return names[a] < names[b]
	})
	if len(names) > limit {
		names = names[:limit]
	}
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte('\n')
	}
	return []byte(b.String()), dropped
}

// Notice is the pack's NOTICE: every source with its commit and license, the
// files used, and the files that were left out and why.
func Notice(s *Sources, pc PackConfig, used []contentpack.WordlistSource) string {
	var b strings.Builder
	fmt.Fprintf(&b, "NOTICE for %s release %s\n\n", pc.Name, s.Release)
	b.WriteString("These lists are built from the upstream files below, each read at the commit\nshown and checked against a pinned sha256. The license of each file is the\nlicense of that file's own upstream, decided per file.\n\n")
	b.WriteString("Sources used\n------------\n")
	seen := map[string]bool{}
	for _, src := range s.Sources {
		for _, u := range used {
			if u.Name != src.Name || u.Commit != src.Commit || seen[u.Path+"@"+u.Commit] {
				continue
			}
			seen[u.Path+"@"+u.Commit] = true
			fmt.Fprintf(&b, "%s\n  repository: %s\n  commit:     %s\n  file:       %s\n  license:    %s\n  copyright:  %s\n\n", src.Name, src.Repo, src.Commit, u.Path, u.SPDX, src.Copyright)
		}
	}
	b.WriteString("Files left out\n--------------\n")
	b.WriteString("Not bundled, because the file's license is not on the allow-list (MIT, Apache-2.0,\nBSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0, Unlicense, WTFPL, CC-BY-4.0) or is\nnot established:\n\n")
	for _, e := range s.Excluded {
		fmt.Fprintf(&b, "- %s: %s (%s): %s\n", e.Source, e.Path, e.SPDX, e.Reason)
	}
	return b.String()
}
