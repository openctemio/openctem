package webendpoint

// The derived candidate list of path discovery (docs/architecture/web-discovery.md):
// paths worth one request each on an origin, built only from one
// organization's own inventory. It is a pure function of its input, so
// retries of one run agree and a test can pin every rule.

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/contract/webpath"
)

// BackupExtensions are the backup and editor-copy suffixes a derived list
// tries on an observed file, in the order tried.
var BackupExtensions = []string{".bak", "~", ".old", ".orig", ".swp", ".save", ".tmp", ".zip", ".tar.gz", ".sql"}

// MaxBackupMutationsPerFile bounds the suffixes tried on one observed file.
const MaxBackupMutationsPerFile = 8

// maxVersion bounds the API version a version sibling is built for.
const maxVersion = 20

// Candidate sources, also the rank classes of a derived list.
const (
	DerivedBackup  = "backup"
	DerivedVersion = "version"
	DerivedSibling = "sibling"
	DerivedSpec    = "spec"
)

// DerivedRow is one active endpoint the origin already has.
type DerivedRow struct {
	Template string
	// Catalog: the template matches the sensitive-path catalog.
	Catalog  bool
	LastSeen time.Time
}

// SiblingPath is a path template seen on Origins other origins of the same
// organization (path_hash), never on this one.
type SiblingPath struct {
	Template string
	Origins  int
}

// DerivedInput is what one origin's derived list is built from. Every field
// comes from the same organization's rows.
type DerivedInput struct {
	Own       []DerivedRow
	Siblings  []SiblingPath
	SpecPaths []string
}

// Derived is a ranked candidate list.
type Derived struct {
	Paths []string
	// Truncated: candidates beyond the limit were dropped.
	Truncated bool
	// Dropped counts candidates refused by a rule (templated, destructive,
	// excluded, malformed, already known).
	Dropped int
}

var versionSegRE = regexp.MustCompile(`^v([0-9]{1,2})$`)

// DerivedCandidates builds the candidate paths of one origin, in rank order,
// at most limit. A candidate is dropped when it holds a templated segment,
// names a state-changing action (webpath.Destructive), falls under a deny
// path (webpath.Denied, the sensor's reading), does not read as a clean path,
// or is a path the origin already has. Classes are interleaved so each keeps
// a share of a short list: backup copies of the newest and sensitive files,
// older and next API versions, paths the organization's other origins
// serve, then declared paths never seen.
func DerivedCandidates(in DerivedInput, deny []string, limit int) Derived {
	known := map[string]bool{}
	for _, r := range in.Own {
		known[strings.ToLower(r.Template)] = true
	}
	var out Derived
	seen := map[string]bool{}
	accept := func(p string) (string, bool) {
		if p == "" || p[0] != '/' || len(p) > MaxPathBytes || strings.ContainsAny(p, "{}?#") {
			return "", false
		}
		clean, err := webpath.CleanPath(p)
		if err != nil || clean != p || webpath.Destructive(clean) {
			return "", false
		}
		if _, denied := webpath.Denied(clean, deny); denied {
			return "", false
		}
		key := strings.ToLower(clean)
		if known[key] || seen[key] {
			return "", false
		}
		seen[key] = true
		return clean, true
	}
	classes := [][]string{backupCandidates(in.Own), versionCandidates(in.Own), siblingCandidates(in.Siblings), slices.Clone(in.SpecPaths)}
	queues := make([][]string, 0, len(classes))
	for _, c := range classes {
		var q []string
		for _, p := range c {
			if v, ok := accept(p); ok {
				q = append(q, v)
			} else {
				out.Dropped++
			}
		}
		queues = append(queues, q)
	}
	for {
		progressed := false
		for i := range queues {
			if len(queues[i]) == 0 {
				continue
			}
			progressed = true
			if limit > 0 && len(out.Paths) >= limit {
				out.Truncated = true
				return out
			}
			out.Paths = append(out.Paths, queues[i][0])
			queues[i] = queues[i][1:]
		}
		if !progressed {
			return out
		}
	}
}

// backupCandidates are the backup copies of the origin's file endpoints:
// sensitive (catalog) files first, then the newest.
func backupCandidates(own []DerivedRow) []string {
	rows := slices.Clone(own)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Catalog != rows[j].Catalog {
			return rows[i].Catalog
		}
		if !rows[i].LastSeen.Equal(rows[j].LastSeen) {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return rows[i].Template < rows[j].Template
	})
	var out []string
	for _, r := range rows {
		last := r.Template[strings.LastIndex(r.Template, "/")+1:]
		dot := strings.LastIndex(last, ".")
		if dot <= 0 || dot == len(last)-1 || strings.Contains(last, "{") || isBackupName(last) {
			continue
		}
		for _, ext := range BackupExtensions[:MaxBackupMutationsPerFile] {
			out = append(out, r.Template+ext)
		}
	}
	return out
}

func isBackupName(name string) bool {
	for _, ext := range BackupExtensions {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			return true
		}
	}
	return false
}

// versionCandidates are the version siblings of every template with a
// /v<n>/ segment: each lower version and the next one.
func versionCandidates(own []DerivedRow) []string {
	var out []string
	for _, r := range own {
		segs := strings.Split(r.Template, "/")
		for i, s := range segs {
			m := versionSegRE.FindStringSubmatch(s)
			if m == nil {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			if n < 1 || n > maxVersion {
				continue
			}
			for v := 1; v <= n+1; v++ {
				if v == n {
					continue
				}
				c := slices.Clone(segs)
				c[i] = "v" + strconv.Itoa(v)
				out = append(out, strings.Join(c, "/"))
			}
			break
		}
	}
	return out
}

// siblingCandidates are the other origins' paths, the most widespread first.
func siblingCandidates(sib []SiblingPath) []string {
	rows := slices.Clone(sib)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Origins != rows[j].Origins {
			return rows[i].Origins > rows[j].Origins
		}
		return rows[i].Template < rows[j].Template
	})
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Origins >= 2 {
			out = append(out, r.Template)
		}
	}
	return out
}
