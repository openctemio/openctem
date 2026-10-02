package version

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	shaA = "4d2f4b02aa11bb22cc33dd44ee55ff6677889900"
	shaB = "0123456789abcdef0123456789abcdef01234567"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resetFallback lets a test run Get() again with different ldflags values.
func resetFallback(t *testing.T, v, c, bt string) {
	t.Helper()
	oldV, oldC, oldT := Version, Commit, BuildTime
	Version, Commit, BuildTime = v, c, bt
	fallbackOnce = sync.Once{}
	t.Cleanup(func() {
		Version, Commit, BuildTime = oldV, oldC, oldT
		fallbackOnce = sync.Once{}
	})
}

func TestGet_ReleaseLdflags(t *testing.T) {
	resetFallback(t, "v0.9.0", shaA, "2026-10-02T10:00:00Z")
	got := Get()
	want := Info{Version: "v0.9.0", Commit: "4d2f4b02", BuildTime: "2026-10-02T10:00:00Z", Channel: ChannelRelease}
	if got != want {
		t.Fatalf("Get() = %+v, want %+v", got, want)
	}
}

func TestGet_DevLdflags(t *testing.T) {
	resetFallback(t, "v0.8.0-dev", "4d2f4b0", "")
	got := Get()
	if got.Version != "v0.8.0-dev" || got.Commit != "4d2f4b0" || got.Channel != ChannelDevelopment {
		t.Fatalf("Get() = %+v", got)
	}
}

func TestGet_NoLdflagsFallsBackToCheckout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/develop\n")
	writeFile(t, filepath.Join(dir, ".git", "refs", "heads", "develop"), shaA+"\n")
	writeFile(t, filepath.Join(dir, ".git", "refs", "tags", "v0.8.0"), shaB+"\n")
	t.Chdir(dir)

	resetFallback(t, "", "", "")
	got := Get()
	want := Info{Version: "v0.8.0-dev", Commit: "4d2f4b02", Channel: ChannelDevelopment}
	if got != want {
		t.Fatalf("Get() = %+v, want %+v", got, want)
	}
}

func TestGet_NoLdflagsNoGit(t *testing.T) {
	t.Chdir(t.TempDir())
	resetFallback(t, "", "", "")
	got := Get()
	want := Info{Version: DevVersion, Commit: UnknownCommit, Channel: ChannelDevelopment}
	if got != want {
		t.Fatalf("Get() = %+v, want %+v", got, want)
	}
}

func TestChannelOf(t *testing.T) {
	cases := map[string]string{
		"v0.9.0":         ChannelRelease,
		"v1.2.3-rc.1":    ChannelRelease,
		"v0.9.0-staging": ChannelRelease,
		"v0.8.0-dev":     ChannelDevelopment,
		"dev":            ChannelDevelopment,
		"":               ChannelDevelopment,
		"main":           ChannelDevelopment,
	}
	for v, want := range cases {
		if got := channelOf(v); got != want {
			t.Errorf("channelOf(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestReadGit_LooseRefsAndPackedTags(t *testing.T) {
	dir := t.TempDir()
	g := filepath.Join(dir, ".git")
	writeFile(t, filepath.Join(g, "HEAD"), "ref: refs/heads/develop\n")
	writeFile(t, filepath.Join(g, "refs", "heads", "develop"), shaA+"\n")
	writeFile(t, filepath.Join(g, "packed-refs"), strings.Join([]string{
		"# pack-refs with: peeled fully-peeled sorted",
		shaB + " refs/tags/v0.10.0",
		"^" + shaA,
		shaB + " refs/tags/v0.9.0",
		shaB + " refs/tags/v0.11.0-rc1", // pre-release: not a base
		shaB + " refs/tags/latest",
		shaB + " refs/remotes/origin/develop",
	}, "\n")+"\n")
	writeFile(t, filepath.Join(g, "refs", "tags", "v0.2.1"), shaB+"\n")

	// Started from a subdirectory: .git is found by walking up.
	sub := filepath.Join(dir, "cmd", "server")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadGit(sub)
	if !ok {
		t.Fatal("ReadGit: not found")
	}
	if got.Head != shaA {
		t.Errorf("Head = %q, want %q", got.Head, shaA)
	}
	if got.LatestTag != "v0.10.0" {
		t.Errorf("LatestTag = %q, want v0.10.0 (numeric, not lexical, ordering)", got.LatestTag)
	}
}

func TestReadGit_PackedBranch(t *testing.T) {
	dir := t.TempDir()
	g := filepath.Join(dir, ".git")
	writeFile(t, filepath.Join(g, "HEAD"), "ref: refs/heads/develop\n")
	writeFile(t, filepath.Join(g, "packed-refs"), shaA+" refs/heads/develop\n")
	got, ok := ReadGit(dir)
	if !ok || got.Head != shaA {
		t.Fatalf("ReadGit = %+v, %v", got, ok)
	}
	if got.LatestTag != "" {
		t.Errorf("LatestTag = %q, want empty", got.LatestTag)
	}
}

func TestReadGit_DetachedHead(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), strings.ToUpper(shaB)+"\n")
	got, ok := ReadGit(dir)
	if !ok || got.Head != shaB {
		t.Fatalf("ReadGit = %+v, %v", got, ok)
	}
}

func TestReadGit_WorktreeGitdirFile(t *testing.T) {
	root := t.TempDir()
	common := filepath.Join(root, "main", ".git")
	wtGit := filepath.Join(common, "worktrees", "feature")
	writeFile(t, filepath.Join(wtGit, "HEAD"), "ref: refs/heads/feature\n")
	writeFile(t, filepath.Join(wtGit, "commondir"), "../..\n")
	writeFile(t, filepath.Join(common, "refs", "heads", "feature"), shaB+"\n")
	writeFile(t, filepath.Join(common, "packed-refs"), shaA+" refs/tags/v0.8.0\n")

	wt := filepath.Join(root, "wt")
	writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+wtGit+"\n")

	got, ok := ReadGit(wt)
	if !ok {
		t.Fatal("ReadGit: not found")
	}
	if got.Head != shaB || got.LatestTag != "v0.8.0" {
		t.Fatalf("ReadGit = %+v", got)
	}
}

func TestReadGit_RelativeGitdir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "real", "HEAD"), shaA+"\n")
	writeFile(t, filepath.Join(root, "wt", ".git"), "gitdir: ../real\n")
	got, ok := ReadGit(filepath.Join(root, "wt"))
	if !ok || got.Head != shaA {
		t.Fatalf("ReadGit = %+v, %v", got, ok)
	}
}

func TestReadGit_Missing(t *testing.T) {
	if _, ok := ReadGit(t.TempDir()); ok {
		t.Fatal("ReadGit found a repository in an empty temp dir")
	}
}

func TestReadGit_RefEscapeRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/../../secret\n")
	writeFile(t, filepath.Join(dir, "secret"), shaA+"\n")
	got, ok := ReadGit(dir)
	if !ok {
		t.Fatal("ReadGit: not found")
	}
	if got.Head != "" {
		t.Fatalf("Head = %q, want empty for a ref outside refs/", got.Head)
	}
}

func TestReadGit_UnbornBranch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n")
	got, ok := ReadGit(dir)
	if !ok || got.Head != "" {
		t.Fatalf("ReadGit = %+v, %v", got, ok)
	}
	if fromCheckout(dir) != (Info{Version: DevVersion, Commit: UnknownCommit}) {
		t.Fatalf("fromCheckout = %+v", fromCheckout(dir))
	}
}
