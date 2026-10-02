package fetchers

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// A file that passes the nuclei validator, so if the fetcher returns it the
// syncer would store it as a downloadable template.
const leakedTemplate = "id: server-secret\ninfo:\n  name: SERVER-ONLY CONTENT\n  severity: info\n"

// climb walks from anywhere in a checkout up to "/".
const climb = "../../../../../../../../../../../../../../../.."

const goodTemplate = "id: ok\ninfo:\n  name: ok\n  severity: info\n"

// makeRepo builds a local git repository with the given regular files and
// symlinks (name -> target) committed on "master", and returns its path.
func makeRepo(t *testing.T, files map[string]string, symlinks map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range symlinks {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.AddGlob("."); err != nil {
		t.Fatalf("add: %v", err)
	}
	_, err = wt.Commit("templates", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dir
}

// allowLocalClone lets a test clone from a local path. Production refuses
// local repositories (see TestGitFetcher_RefusesLocalRepositoryURLs).
func allowLocalClone(t *testing.T) {
	t.Helper()
	prev := allowLocalRepos
	allowLocalRepos = true
	t.Cleanup(func() { allowLocalRepos = prev })
}

func fetchAll(t *testing.T, cfg GitConfig) (*FetchResult, error) {
	t.Helper()
	f, err := NewGitFetcher(cfg)
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f.Fetch(context.Background(), FetchOptions{Extensions: []string{".yaml", ".yml"}, MaxFileSize: 1 << 20})
}

func containsLeak(res *FetchResult) (string, bool) {
	if res == nil {
		return "", false
	}
	for name, content := range res.Files {
		if strings.Contains(string(content), "SERVER-ONLY CONTENT") {
			return name, true
		}
	}
	return "", false
}

// TestGitFetcher_PathEscapesCloneRoot: git_config.path "../<dir>" walked a
// directory outside the clone and returned its files as templates.
func TestGitFetcher_PathEscapesCloneRoot(t *testing.T) {
	allowLocalClone(t)

	// The clone directory is created under TMPDIR; put a server-side
	// directory next to it.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, "server-data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "server-data", "secret.yaml"), []byte(leakedTemplate), 0o600); err != nil {
		t.Fatal(err)
	}

	repo := makeRepo(t, map[string]string{"templates/ok.yaml": goodTemplate}, nil)

	for _, path := range []string{"../server-data", "templates/../../server-data", "/" + filepath.Join(tmp, "server-data")} {
		t.Run(path, func(t *testing.T) {
			res, err := fetchAll(t, GitConfig{URL: repo, Branch: "master", Path: path})
			if name, leaked := containsLeak(res); leaked {
				t.Fatalf("path %q returned a file from outside the clone: %s", path, name)
			}
			if err == nil {
				t.Fatalf("path %q escaping the clone must be refused", path)
			}
		})
	}
}

// TestGitFetcher_SymlinkedTemplateFollowed: a committed symlink
// evil.yaml -> /some/server/file was read through and returned as a template.
func TestGitFetcher_SymlinkedTemplateFollowed(t *testing.T) {
	allowLocalClone(t)

	outside := filepath.Join(t.TempDir(), "server-secret.yaml")
	if err := os.WriteFile(outside, []byte(leakedTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "inner.yaml"), []byte(leakedTemplate), 0o600); err != nil {
		t.Fatal(err)
	}

	// Relative targets that climb to "/" and back down: what an attacker
	// commits, since they do not know where the server clones to. (go-git
	// rewrites ABSOLUTE symlink targets into the checkout directory, so those
	// only dangle; relative ones are written as-is.)
	repo := makeRepo(t,
		map[string]string{"ok.yaml": goodTemplate},
		map[string]string{
			"evil.yaml":    climb + outside,    // file symlink out of the repo
			"linkdir":      climb + outsideDir, // directory symlink out of the repo
			"nested/x.yml": climb + outside,
			"dangling.yml": "/does/not/exist", // must not abort the sync
		},
	)

	res, err := fetchAll(t, GitConfig{URL: repo, Branch: "master"})
	if err != nil {
		t.Fatalf("fetch of a repo containing symlinks should still succeed (they are skipped): %v", err)
	}
	if name, leaked := containsLeak(res); leaked {
		t.Fatalf("symlink %s was followed out of the repository", name)
	}
	if _, ok := res.Files["ok.yaml"]; !ok {
		t.Fatalf("regular template missing from result: %v", keys(res.Files))
	}

	// git_config.path pointing at a directory symlink must not escape either.
	res, err = fetchAll(t, GitConfig{URL: repo, Branch: "master", Path: "linkdir"})
	if name, leaked := containsLeak(res); leaked {
		t.Fatalf("path through a directory symlink escaped the repository: %s", name)
	}
	if err == nil {
		t.Fatalf("path resolving outside the clone through a symlink must be refused")
	}
}

// TestGitFetcher_ReadFileRefusesSymlinks: ReadFile's prefix check compared
// unresolved paths, so a symlink inside the repo was opened and followed.
func TestGitFetcher_ReadFileRefusesSymlinks(t *testing.T) {
	allowLocalClone(t)

	outside := filepath.Join(t.TempDir(), "server-secret.yaml")
	if err := os.WriteFile(outside, []byte(leakedTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := makeRepo(t, map[string]string{"ok.yaml": goodTemplate}, map[string]string{"evil.yaml": climb + outside})

	f, err := NewGitFetcher(GitConfig{URL: repo, Branch: "master"})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Fetch(context.Background(), FetchOptions{}); err != nil {
		t.Fatal(err)
	}

	rc, err := f.ReadFile(context.Background(), "evil.yaml")
	if err == nil {
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		t.Fatalf("ReadFile followed a symlink out of the repository: %q", b)
	}

	rc, err = f.ReadFile(context.Background(), "ok.yaml")
	if err != nil {
		t.Fatalf("ReadFile of a regular file failed: %v", err)
	}
	_ = rc.Close()

	files, err := f.ListFiles(context.Background(), []string{".yaml"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if name == "evil.yaml" {
			t.Fatalf("ListFiles listed a symlink: %v", files)
		}
	}
}

// TestGitFetcher_RefusesLocalRepositoryURLs: go-git serves file:// and bare
// local paths in-process, so a tenant URL like file:///srv/other-repo cloned
// a repository from the API server's own disk.
func TestGitFetcher_RefusesLocalRepositoryURLs(t *testing.T) {
	repo := makeRepo(t, map[string]string{"ok.yaml": goodTemplate}, nil)

	for _, u := range []string{"file://" + repo, repo, "git://127.0.0.1:9418/repo.git"} {
		t.Run(u, func(t *testing.T) {
			res, err := fetchAll(t, GitConfig{URL: u, Branch: "master"})
			if err == nil {
				t.Fatalf("clone of %q must be refused, got %d files", u, len(res.Files))
			}
		})
	}
}

// TestGitFetcher_LegitimateRepository is the ordinary case: a subdirectory of
// a normal repository is fetched, with relative names.
func TestGitFetcher_LegitimateRepository(t *testing.T) {
	allowLocalClone(t)
	repo := makeRepo(t, map[string]string{
		"templates/a.yaml":     goodTemplate,
		"templates/sub/b.yml":  goodTemplate,
		"templates/readme.txt": "x",
		"other/c.yaml":         goodTemplate,
	}, nil)

	for _, p := range []string{"templates", "templates/", "./templates"} {
		res, err := fetchAll(t, GitConfig{URL: repo, Branch: "master", Path: p})
		if err != nil {
			t.Fatalf("path %q: %v", p, err)
		}
		if len(res.Files) != 2 || res.Files["a.yaml"] == nil || res.Files[filepath.Join("sub", "b.yml")] == nil {
			t.Fatalf("path %q: unexpected files %v", p, keys(res.Files))
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
