package contentpack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Wordlist packs carry a manifest (wordlists.yaml) and a NOTICE next to
// their lists. The manifest says, for every list, what it is for, how big it
// is and which upstream files it was built from under which license; lint
// checks that it is true. The build that writes it is cmd/wordlists-build
// (research/294, owner decision O2: licenses are decided per file).

// Names of the two metadata files of a wordlist pack.
const (
	WordlistManifestFile = "wordlists.yaml"
	WordlistNoticeFile   = "NOTICE"
)

// Purposes of a wordlist. They match the runtime that composes a job's list
// (sdk-go pkg/tool/wordlist), which normalises the same way.
const (
	PurposeDNSLabels = "dns-labels"
	PurposeWebPaths  = "web-paths"
	PurposeWebFiles  = "web-files"
	PurposeAPIRoutes = "api-routes"
	PurposeParams    = "params"
	PurposeExt       = "extensions"
	PurposeVHosts    = "vhosts"
)

// WordlistPurposes lists the known purposes.
var WordlistPurposes = []string{PurposeDNSLabels, PurposeWebPaths, PurposeWebFiles, PurposeAPIRoutes, PurposeParams, PurposeExt, PurposeVHosts} //nolint:gochecknoglobals // read-only

// Size classes of a list.
var WordlistClasses = []string{"s", "m", "l"} //nolint:gochecknoglobals // read-only

// Licenses a file may carry into a pack (owner decision O2). Everything
// else, GPL and AGPL included, and a file with no or an unknown license, is
// refused. ShareAlike licenses are allowed only in an opt-in pack, with
// attribution.
var (
	allowedLicenses = map[string]bool{ //nolint:gochecknoglobals // read-only
		"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "ISC": true,
		"CC0-1.0": true, "Unlicense": true, "WTFPL": true, "CC-BY-4.0": true,
	}
	optInLicenses = map[string]bool{"CC-BY-SA-3.0": true, "CC-BY-SA-4.0": true} //nolint:gochecknoglobals // read-only
)

// LicenseAllowed reports whether a file of this SPDX license may be bundled
// (optIn: the pack is an opt-in pack that also takes the ShareAlike set).
func LicenseAllowed(spdx string, optIn bool) bool {
	return allowedLicenses[spdx] || optIn && optInLicenses[spdx]
}

// WordlistManifest is the parsed wordlists.yaml.
type WordlistManifest struct {
	Version int    `yaml:"version"`
	Release string `yaml:"release"`
	Pack    string `yaml:"pack"`
	Class   string `yaml:"class"`
	// OptIn marks a pack the organization turns on; it may carry
	// ShareAlike lists.
	OptIn bool                `yaml:"opt_in,omitempty"`
	Files []WordlistFileEntry `yaml:"files"`
}

// WordlistFileEntry describes one list of the pack.
type WordlistFileEntry struct {
	Path    string           `yaml:"path"`
	Purpose string           `yaml:"purpose"`
	Class   string           `yaml:"class"`
	Lines   int              `yaml:"lines"`
	SHA256  string           `yaml:"sha256"`
	Sources []WordlistSource `yaml:"sources"`
}

// WordlistSource is one upstream file a list was built from.
type WordlistSource struct {
	Name   string `yaml:"name"`
	URL    string `yaml:"url"`
	Commit string `yaml:"commit"`
	Path   string `yaml:"path"`
	SPDX   string `yaml:"spdx"`
}

// ParseWordlistManifest reads a wordlists.yaml; unknown keys are an error.
func ParseWordlistManifest(data []byte) (*WordlistManifest, error) {
	var m WordlistManifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

var (
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	paramRE    = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)
	extRE      = regexp.MustCompile(`^\.?[A-Za-z0-9_-]{1,16}$`)
	commitRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	packNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Limits of an entry (the same as the runtime's).
const (
	maxEntryBytes   = 255
	maxEntrySegment = 16
	maxDNSLabels    = 3
)

// NormalizeWordlistLine returns the entry a raw line stands for under a
// purpose, or false when the line is dropped: empty, a comment, control
// characters, or invalid for the purpose. A path-like list drops absolute
// URLs, ".." and anything longer than 255 bytes, so a list can never name a
// host of its own.
func NormalizeWordlistLine(purpose, line string) (string, bool) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if line == "" || strings.HasPrefix(line, "#") || len(line) > maxWordlistLine {
		return "", false
	}
	for _, r := range line {
		if r < 0x20 || r == 0x7f || r > 0x7e && r < 0xa0 || r == 0xfffd {
			return "", false
		}
	}
	switch purpose {
	case PurposeDNSLabels, PurposeVHosts:
		line = strings.ToLower(line)
		limit := maxDNSLabels
		if purpose == PurposeVHosts {
			limit = 6
		}
		labels := strings.Split(line, ".")
		if len(labels) > limit {
			return "", false
		}
		for _, l := range labels {
			if !dnsLabelRE.MatchString(l) {
				return "", false
			}
		}
		return line, true
	case PurposeParams:
		if !paramRE.MatchString(line) {
			return "", false
		}
		return line, true
	case PurposeExt:
		if !extRE.MatchString(line) {
			return "", false
		}
		return line, true
	default:
		line = strings.TrimLeft(line, "/")
		if line == "" || len(line) > maxEntryBytes || strings.Contains(line, "://") || strings.ContainsAny(line, " \t") {
			return "", false
		}
		segs := strings.Split(strings.TrimRight(line, "/"), "/")
		if len(segs) > maxEntrySegment {
			return "", false
		}
		for _, s := range segs {
			if s == ".." {
				return "", false
			}
		}
		return line, true
	}
}

func knownPurpose(p string) bool {
	for _, k := range WordlistPurposes {
		if k == p {
			return true
		}
	}
	return false
}

func knownClass(c string) bool {
	for _, k := range WordlistClasses {
		if k == c {
			return true
		}
	}
	return false
}

// ManifestIssue is one reason a wordlist manifest is wrong.
type ManifestIssue struct{ Path, Code, Message string }

// CheckWordlistPack checks a wordlist pack against its manifest: the
// manifest parses and is complete, every list in the pack is described, and
// each description is true (line count, sha256, entries valid and unique for
// the purpose, every source on the license allow-list with a pinned commit).
// NOTICE must name every source and its commit. The files are only parsed
// and counted, never executed.
func CheckWordlistPack(files map[string][]byte) []ManifestIssue {
	var out []ManifestIssue
	add := func(p, code, format string, args ...any) {
		out = append(out, ManifestIssue{p, code, fmt.Sprintf(format, args...)})
	}
	raw, ok := files[WordlistManifestFile]
	if !ok {
		add(WordlistManifestFile, "WORDLIST_MANIFEST_MISSING", "a platform wordlist pack needs a %s", WordlistManifestFile)
		return out
	}
	m, err := ParseWordlistManifest(raw)
	if err != nil {
		add(WordlistManifestFile, "WORDLIST_MANIFEST_INVALID", "%v", err)
		return out
	}
	if m.Version != 1 {
		add(WordlistManifestFile, "WORDLIST_MANIFEST_INVALID", "version must be 1")
	}
	if !packNameRE.MatchString(m.Pack) || m.Release == "" || len(m.Release) > 32 {
		add(WordlistManifestFile, "WORDLIST_MANIFEST_INVALID", "pack and release are required")
	}
	if !knownClass(m.Class) {
		add(WordlistManifestFile, "WORDLIST_MANIFEST_INVALID", "class must be one of s, m, l")
	}
	if len(m.Files) == 0 {
		add(WordlistManifestFile, "WORDLIST_MANIFEST_INVALID", "no lists")
	}
	notice, hasNotice := files[WordlistNoticeFile]
	if !hasNotice {
		add(WordlistNoticeFile, "WORDLIST_NOTICE_MISSING", "a wordlist pack needs a %s naming every source and license", WordlistNoticeFile)
	}
	listed := map[string]bool{}
	for _, e := range m.Files {
		listed[e.Path] = true
		data, ok := files[e.Path]
		switch {
		case !ok:
			add(e.Path, "WORDLIST_MANIFEST_FILE_MISSING", "listed in the manifest but not in the pack")
			continue
		case !knownPurpose(e.Purpose):
			add(e.Path, "WORDLIST_MANIFEST_INVALID", "unknown purpose %q", e.Purpose)
			continue
		case !knownClass(e.Class):
			add(e.Path, "WORDLIST_MANIFEST_INVALID", "unknown class %q", e.Class)
		case e.Class != m.Class:
			add(e.Path, "WORDLIST_MANIFEST_INVALID", "class %s in a %s pack", e.Class, m.Class)
		}
		sum := sha256.Sum256(data)
		if !sha256RE.MatchString(e.SHA256) || hex.EncodeToString(sum[:]) != e.SHA256 {
			add(e.Path, "WORDLIST_MANIFEST_MISMATCH", "sha256 does not match the file")
		}
		lines, bad, dup := countList(e.Purpose, data)
		if lines != e.Lines {
			add(e.Path, "WORDLIST_MANIFEST_MISMATCH", "the manifest says %d lines, the file has %d", e.Lines, lines)
		}
		if bad != "" {
			add(e.Path, "WORDLIST_NOT_NORMALISED", "%q is not a valid %s entry", clip(bad), e.Purpose)
		}
		if dup != "" {
			add(e.Path, "WORDLIST_DUPLICATE", "%q appears more than once", clip(dup))
		}
		if len(e.Sources) == 0 {
			add(e.Path, "WORDLIST_SOURCE_MISSING", "a list names the upstream files it was built from")
		}
		for _, s := range e.Sources {
			checkSource(e.Path, s, m.OptIn, string(notice), hasNotice, add)
		}
	}
	for p := range files {
		if p != WordlistManifestFile && p != WordlistNoticeFile && !listed[p] {
			add(p, "WORDLIST_UNLISTED", "a file of the pack is not described in %s", WordlistManifestFile)
		}
	}
	return out
}

func checkSource(path string, s WordlistSource, optIn bool, notice string, hasNotice bool, add func(p, code, format string, args ...any)) {
	if !LicenseAllowed(s.SPDX, optIn) {
		add(path, "WORDLIST_LICENSE_REFUSED", "source %s/%s has license %q, which is not on the allow-list", s.Name, s.Path, s.SPDX)
	}
	u, err := url.Parse(s.URL)
	if s.Name == "" || s.Path == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !commitRE.MatchString(s.Commit) {
		add(path, "WORDLIST_SOURCE_INVALID", "source %q needs a name, an https url, a path and a 40-hex commit", s.Name)
		return
	}
	if hasNotice && (!strings.Contains(notice, s.Commit) || !strings.Contains(notice, s.Path) || !strings.Contains(notice, s.SPDX)) {
		add(WordlistNoticeFile, "WORDLIST_NOTICE_INCOMPLETE", "%s does not record %s at %s under %s", WordlistNoticeFile, s.Path, s.Commit[:12], s.SPDX)
	}
}

// countList counts the non-empty lines of a list, and returns the first
// line that is not a valid, already-normalised entry and the first
// repeated one.
func countList(purpose string, data []byte) (lines int, bad, dup string) {
	seen := map[string]struct{}{}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		lines++
		n, ok := NormalizeWordlistLine(purpose, l)
		if !ok || n != strings.TrimRight(l, "\r") {
			if bad == "" {
				bad = l
			}
			continue
		}
		if _, d := seen[n]; d && dup == "" {
			dup = n
		}
		seen[n] = struct{}{}
	}
	return lines, bad, dup
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
