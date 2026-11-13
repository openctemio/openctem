package version

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// GitInfo is what a checkout's .git says about the code it holds.
type GitInfo struct {
	// Head is the full SHA HEAD points at ("" if it cannot be resolved).
	Head string
	// LatestTag is the highest vX.Y.Z tag in the repository ("" if none).
	// Not "the tag HEAD descends from": release tags live on release branches,
	// so on develop the highest tag is the honest base for "<tag>-dev".
	LatestTag string
}

var (
	semverTag = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)
	fullSHA   = regexp.MustCompile(`^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$`)
)

// maxParentWalk bounds the search for .git upwards from the start directory.
const maxParentWalk = 8

// ReadGit reads HEAD and the tags of the git checkout containing dir, straight
// from the filesystem (no git binary: the dev container's checkout belongs to
// another user, which git refuses as "dubious ownership"). It handles loose
// and packed refs, a detached HEAD, and a worktree's ".git" file (gitdir: +
// commondir). ok is false when no .git is found.
func ReadGit(dir string) (GitInfo, bool) {
	gitDir, ok := findGitDir(dir)
	if !ok {
		return GitInfo{}, false
	}
	commonDir := gitDir
	if b, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		c := strings.TrimSpace(string(b))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gitDir, c)
		}
		commonDir = filepath.Clean(c)
	}

	packed := readPackedRefs(commonDir)
	return GitInfo{
		Head:      resolveHead(gitDir, commonDir, packed),
		LatestTag: latestTag(commonDir, packed),
	}, true
}

// findGitDir walks up from dir to the first ".git" (a directory, or a file
// "gitdir: <path>" as in a linked worktree or submodule).
func findGitDir(dir string) (string, bool) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for range maxParentWalk {
		p := filepath.Join(d, ".git")
		if fi, err := os.Stat(p); err == nil {
			if fi.IsDir() {
				return p, true
			}
			if b, err := os.ReadFile(p); err == nil { //nolint:gosec // G304: fixed name under the process's own working tree
				line := strings.TrimSpace(string(b))
				if rest, ok := strings.CutPrefix(line, "gitdir:"); ok {
					g := strings.TrimSpace(rest)
					if !filepath.IsAbs(g) {
						g = filepath.Join(d, g)
					}
					if fi, err := os.Stat(g); err == nil && fi.IsDir() {
						return filepath.Clean(g), true
					}
				}
			}
			return "", false
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return "", false
}

// readPackedRefs maps ref name to SHA from packed-refs (peeled "^" lines are
// skipped: the tag object's own SHA is not needed, only the tag names).
func readPackedRefs(commonDir string) map[string]string {
	refs := map[string]string{}
	f, err := os.Open(filepath.Join(commonDir, "packed-refs"))
	if err != nil {
		return refs
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' || line[0] == '^' {
			continue
		}
		sha, name, ok := strings.Cut(line, " ")
		if ok && fullSHA.MatchString(sha) {
			refs[strings.TrimSpace(name)] = sha
		}
	}
	return refs
}

// resolveHead follows HEAD through symbolic refs to a SHA. Per-worktree refs
// (HEAD itself) live in gitDir; branches live in commonDir.
func resolveHead(gitDir, commonDir string, packed map[string]string) string {
	b, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	content := strings.TrimSpace(string(b))
	for range 5 { // a symbolic ref chain longer than this is broken
		ref, ok := strings.CutPrefix(content, "ref:")
		if !ok {
			if fullSHA.MatchString(content) {
				return strings.ToLower(content)
			}
			return ""
		}
		ref = strings.TrimSpace(ref)
		if !validRefName(ref) {
			return ""
		}
		if b, err := os.ReadFile(filepath.Join(commonDir, filepath.FromSlash(ref))); err == nil {
			content = strings.TrimSpace(string(b))
			continue
		}
		if sha, ok := packed[ref]; ok {
			return strings.ToLower(sha)
		}
		return "" // unborn branch
	}
	return ""
}

// validRefName keeps a ref read from HEAD inside the git directory.
func validRefName(ref string) bool {
	return strings.HasPrefix(ref, "refs/") && !strings.Contains(ref, "..") && !strings.ContainsRune(ref, 0)
}

// latestTag returns the highest vX.Y.Z tag among loose and packed tags.
func latestTag(commonDir string, packed map[string]string) string {
	names := map[string]struct{}{}
	for name := range packed {
		if t, ok := strings.CutPrefix(name, "refs/tags/"); ok {
			names[t] = struct{}{}
		}
	}
	if entries, err := os.ReadDir(filepath.Join(commonDir, "refs", "tags")); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				names[e.Name()] = struct{}{}
			}
		}
	}

	best, bestKey := "", [3]int{-1, -1, -1}
	for name := range names {
		m := semverTag.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		var key [3]int
		valid := true
		for i := range key {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				valid = false
				break
			}
			key[i] = n
		}
		if valid && lessKey(bestKey, key) {
			best, bestKey = name, key
		}
	}
	return best
}

func lessKey(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
