package fetchers

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	gitfile "github.com/go-git/go-git/v5/plumbing/transport/file"
)

var sig = &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(1700000000, 0)}

// makeRepo commits files (and symlinks) on "main" and tags the commit v1.
func makeRepo(t *testing.T, files, symlinks map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInitWithOptions(dir, &git.PlainInitOptions{
		InitOptions: git.InitOptions{DefaultBranch: plumbing.NewBranchReferenceName("main")},
	})
	if err != nil {
		t.Fatal(err)
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
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.AddGlob("."); err != nil {
		t.Fatal(err)
	}
	h, err := wt.Commit("rules", &git.CommitOptions{Author: sig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateTag("v1", h, &git.CreateTagOptions{Tagger: sig, Message: "v1"}); err != nil {
		t.Fatal(err)
	}
	return dir, h.String()
}

func allowLocal(t *testing.T) {
	t.Helper()
	prev := allowLocalRepos
	allowLocalRepos = true
	// Production removes the file transport; these tests clone a local path.
	client.InstallProtocol("file", gitfile.DefaultClient)
	t.Cleanup(func() {
		allowLocalRepos = prev
		client.InstallProtocol("file", nil)
	})
}

func paths(s *GitSnapshot) string {
	out := make([]string, 0, len(s.Files))
	for _, f := range s.Files {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestSnapshotGit_RefsAndPath(t *testing.T) {
	allowLocal(t)
	dir, commit := makeRepo(t, map[string]string{
		"LICENSE":        "MIT License",
		"rules/a.yaml":   "rules: []\n",
		"rules/x/b.yaml": "rules: []\n",
		"other/c.yaml":   "rules: []\n",
	}, nil)
	ctx := context.Background()
	for _, ref := range []string{"main", "v1", commit} {
		s, err := SnapshotGit(ctx, GitRequest{URL: dir, Ref: ref, Path: "rules"})
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if s.Commit != commit || paths(s) != "a.yaml,x/b.yaml" || string(s.License) != "MIT License" {
			t.Fatalf("%s: commit %s files %s license %q", ref, s.Commit, paths(s), s.License)
		}
	}
	if _, err := SnapshotGit(ctx, GitRequest{URL: dir, Ref: "nope"}); !errors.Is(err, ErrRefNotFound) {
		t.Fatalf("missing ref: %v", err)
	}
	if _, err := SnapshotGit(ctx, GitRequest{URL: dir, Ref: "main", Path: "missing"}); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("missing path: %v", err)
	}
	if _, err := SnapshotGit(ctx, GitRequest{URL: dir, Ref: "main", MaxFiles: 2}); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("file limit: %v", err)
	}
	if _, err := SnapshotGit(ctx, GitRequest{URL: dir, Ref: "main", MaxTotal: 10}); !errors.Is(err, ErrTooMuchContent) {
		t.Fatalf("size limit: %v", err)
	}
}

// SECURITY: a committed symlink is never followed (it would read the API
// server's disk); it is reported as skipped. Content comes from git objects
// only, never from a checkout.
func TestSnapshotGit_SymlinksAreSkipped(t *testing.T) {
	allowLocal(t)
	dir, _ := makeRepo(t, map[string]string{"a.yaml": "rules: []\n"}, map[string]string{"passwd.yaml": "/etc/passwd"})
	s, err := SnapshotGit(context.Background(), GitRequest{URL: dir, Ref: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if paths(s) != "a.yaml" || len(s.Skipped) != 1 || s.Skipped[0].Path != "passwd.yaml" {
		t.Fatalf("files %s skipped %+v", paths(s), s.Skipped)
	}
	for _, f := range s.Files {
		if strings.Contains(string(f.Data), "root:") {
			t.Fatal("symlink target read")
		}
	}
}

func TestSnapshotGit_RefusesLFS(t *testing.T) {
	allowLocal(t)
	dir, _ := makeRepo(t, map[string]string{"big.yaml": "version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 1\n"}, nil)
	if _, err := SnapshotGit(context.Background(), GitRequest{URL: dir, Ref: "main"}); !errors.Is(err, ErrLFSPointer) {
		t.Fatalf("LFS pointer: %v", err)
	}
}

// SECURITY: outside tests only https to an allowed host is fetched.
func TestSnapshotGit_RemoteGuard(t *testing.T) {
	dir, _ := makeRepo(t, map[string]string{"a.yaml": "x"}, nil)
	for _, u := range []string{dir, "file://" + dir, "http://example.com/r.git", "ssh://git@example.com/r.git",
		"https://127.0.0.1/r.git", "https://169.254.169.254/r.git", "https://localhost/r.git"} {
		if _, err := SnapshotGit(context.Background(), GitRequest{URL: u, Ref: "main"}); err == nil {
			t.Errorf("%s fetched", u)
		}
	}
	if _, err := RemoteIsPrivate("https://127.0.0.1/r.git"); err == nil {
		t.Error("loopback accepted as a remote")
	}
}

// SECURITY: a server low on disk fetches nothing (a full disk stops the
// database), and an unreadable free-space figure refuses too.
func TestSnapshotGit_RefusesOnLowDisk(t *testing.T) {
	allowLocal(t)
	dir, _ := makeRepo(t, map[string]string{"a.yaml": "rules: []\n"}, nil)
	prev := freeDiskBytes
	t.Cleanup(func() { freeDiskBytes = prev })

	freeDiskBytes = func(string) (uint64, error) { return uint64(MaxCloneBytes) + MinFreeDiskBytes - 1, nil }
	if _, err := SnapshotGit(context.Background(), GitRequest{URL: dir, Ref: "main"}); !errors.Is(err, ErrLowDisk) {
		t.Fatalf("low disk: %v", err)
	}
	freeDiskBytes = func(string) (uint64, error) { return 0, errors.New("statfs failed") }
	if _, err := SnapshotGit(context.Background(), GitRequest{URL: dir, Ref: "main"}); err == nil {
		t.Fatal("an unreadable free space must refuse")
	}
	freeDiskBytes = func(string) (uint64, error) { return uint64(MaxCloneBytes) + MinFreeDiskBytes, nil }
	if _, err := SnapshotGit(context.Background(), GitRequest{URL: dir, Ref: "main"}); err != nil {
		t.Fatalf("enough disk: %v", err)
	}
}

// SECURITY: clones in flight count against the free disk, so concurrent
// fetches cannot each pass a check that only fits one.
func TestReserveDisk_CountsClonesInFlight(t *testing.T) {
	prev := freeDiskBytes
	t.Cleanup(func() { freeDiskBytes = prev })
	freeDiskBytes = func(string) (uint64, error) { return 2*uint64(MaxCloneBytes) + MinFreeDiskBytes, nil }
	r1, err := reserveDisk(".")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := reserveDisk(".")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserveDisk("."); !errors.Is(err, ErrLowDisk) {
		t.Fatalf("third clone fits no more: %v", err)
	}
	r1()
	r3, err := reserveDisk(".")
	if err != nil {
		t.Fatalf("a released reservation frees room: %v", err)
	}
	r2()
	r3()
}

// TestGitTransports_OnlyGuardedHTTP: a rule source is fetched over the
// guarded HTTP transport only. ssh and git:// would dial with their own
// unguarded dialer and file:// would read the server disk, so none of them
// is registered, whatever URL reaches go-git.
func TestGitTransports_OnlyGuardedHTTP(t *testing.T) {
	for _, raw := range []string{"ssh://git@example.com/r.git", "git://example.com/r.git", "file:///etc", "git@example.com:r.git", "/var/lib"} {
		ep, err := transport.NewEndpoint(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if _, err := client.NewClient(ep); err == nil {
			t.Errorf("%s: go-git has a transport for scheme %q", raw, ep.Protocol)
		}
	}
	for _, raw := range []string{"https://example.com/r.git", "http://example.com/r.git"} {
		ep, _ := transport.NewEndpoint(raw)
		if _, err := client.NewClient(ep); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}
