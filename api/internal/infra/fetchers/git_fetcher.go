package fetchers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"

	"github.com/openctemio/openctem/api/pkg/domain/templatesource"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// allowLocalRepos lets tests clone from a local path. Production never sets
// it: go-git serves file:// URLs and bare paths in-process, which would let a
// tenant clone any repository on the API server's own disk.
var allowLocalRepos = false

const defaultBranch = "main"

// gitCloneTimeout bounds a single HTTP git operation. It is generous
// (template repos are shallow, depth=1) so large legitimate clones are not
// cut short, while still capping a hung/slow-loris remote.
const gitCloneTimeout = 5 * time.Minute

// Repository size limits for a template-source clone. The clone lands on the
// API server's disk; an oversized repository could fill it (a full disk has
// already stopped Postgres once), so the clone is aborted past maxCloneBytes
// and a checkout with more than maxRepoFiles files is refused.
var (
	maxCloneBytes int64 = 200 * 1024 * 1024 // 200MB on disk
	maxRepoFiles        = 20000
	cloneSizePoll       = 250 * time.Millisecond
)

// ErrRepositoryTooLarge: the repository exceeds the clone size or file limit.
var ErrRepositoryTooLarge = errors.New("repository exceeds the template source size limit")

// dirSize returns the bytes used by regular files under dir.
func dirSize(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// cloneWithSizeCap runs clone while watching the target directory; once it
// grows past maxCloneBytes the clone is cancelled and ErrRepositoryTooLarge
// returned.
func cloneWithSizeCap(ctx context.Context, dir string, clone func(context.Context) (*git.Repository, error)) (*git.Repository, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var tooLarge atomic.Bool
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(cloneSizePoll)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if dirSize(dir) > maxCloneBytes {
					tooLarge.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	repo, err := clone(cctx)
	close(done)
	if tooLarge.Load() || (err == nil && dirSize(dir) > maxCloneBytes) {
		return nil, ErrRepositoryTooLarge
	}
	return repo, err
}

// init routes go-git's HTTP/HTTPS transport through an SSRF-guarded
// *http.Client whose dialer rejects internal / cloud-metadata addresses.
// go-git's protocol registry is process-global and not safe to mutate
// concurrently with clones, so we install once at package init — before any
// fetcher can run — rather than per-clone. ssh:// and file:// keep their
// upstream transports (rejected where unsafe by go-git itself).
func init() {
	safeTransport := http.NewClient(httpsec.SafeHTTPClient(gitCloneTimeout))
	client.InstallProtocol("https", safeTransport)
	client.InstallProtocol("http", safeTransport)
}

// GitConfig contains configuration for Git fetcher.
type GitConfig struct {
	URL        string
	Branch     string
	Path       string // Subdirectory to fetch from
	AuthType   string // none, token, ssh
	Token      string
	SSHKey     []byte
	SSHKeyPass string
}

// GitFetcher fetches templates from a Git repository.
// This fetcher is thread-safe and can be used concurrently.
type GitFetcher struct {
	config   GitConfig
	auth     transport.AuthMethod
	mu       sync.Mutex // Protects tempDir, repo, worktree
	tempDir  string
	repo     *git.Repository
	worktree *git.Worktree
}

// NewGitFetcher creates a new Git fetcher.
func NewGitFetcher(config GitConfig) (*GitFetcher, error) {
	f := &GitFetcher{config: config}

	// Setup authentication
	switch config.AuthType {
	case "token":
		f.auth = &http.BasicAuth{
			Username: "x-access-token", // GitHub/GitLab convention
			Password: config.Token,
		}
	case "ssh":
		keys, err := ssh.NewPublicKeys("git", config.SSHKey, config.SSHKeyPass)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH auth: %w", err)
		}
		f.auth = keys
	}

	return f, nil
}

// Fetch clones/pulls the repository and returns matching files.
// This method is thread-safe.
func (f *GitFetcher) Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var err error

	// Create temp directory if not exists
	if f.tempDir == "" {
		f.tempDir, err = os.MkdirTemp("", "git-fetch-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
	}

	// Clone or open existing repo
	if f.repo == nil {
		f.repo, err = f.cloneRepo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to clone repository: %w", err)
		}
	} else {
		// Pull latest changes
		if err := f.pullRepo(ctx); err != nil {
			return nil, fmt.Errorf("failed to pull repository: %w", err)
		}
	}

	// Get current commit hash
	ref, err := f.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}
	currentHash := ref.Hash().String()

	// Check if hash changed
	if opts.LastHash != "" && opts.LastHash == currentHash {
		return &FetchResult{
			Hash:      currentHash,
			FetchedAt: time.Now(),
			Files:     make(map[string][]byte),
		}, nil
	}

	// Collect files
	basePath, err := f.contentRoot()
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte)
	var totalSize int64
	seen := 0

	err = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip .git directory
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files are templates. Walk reports entries with
		// Lstat, so a committed symlink shows up here as a symlink; reading
		// it would follow it to wherever it points on the server.
		if !info.Mode().IsRegular() {
			return nil
		}
		seen++
		if seen > maxRepoFiles {
			return ErrRepositoryTooLarge
		}

		// Check extension filter
		if len(opts.Extensions) > 0 {
			ext := filepath.Ext(path)
			matched := false
			for _, e := range opts.Extensions {
				if strings.EqualFold(ext, e) {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}

		// Check file size
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			return nil
		}

		// Check total size
		if opts.MaxTotalSize > 0 && totalSize+info.Size() > opts.MaxTotalSize {
			return fmt.Errorf("total size exceeds limit")
		}

		// Read file
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		// Store with relative path
		relPath, _ := filepath.Rel(basePath, path)
		files[relPath] = content
		totalSize += info.Size()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &FetchResult{
		Files:      files,
		Hash:       currentHash,
		FetchedAt:  time.Now(),
		TotalFiles: len(files),
		TotalSize:  totalSize,
	}, nil
}

// CheckForUpdates checks if the remote has new commits.
// This method is thread-safe.
func (f *GitFetcher) CheckForUpdates(ctx context.Context, lastHash string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.repo == nil {
		// Need to clone first
		return "", true, nil
	}

	// Fetch remote refs
	err := f.repo.FetchContext(ctx, &git.FetchOptions{
		Auth:       f.auth,
		RemoteName: "origin",
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return "", false, fmt.Errorf("failed to fetch: %w", err)
	}

	// Get remote branch ref
	branch := f.config.Branch
	if branch == "" {
		branch = defaultBranch
	}

	remoteRef, err := f.repo.Reference(plumbing.NewRemoteReferenceName("origin", branch), true)
	if err != nil {
		// Try master if main doesn't exist
		if branch == defaultBranch {
			remoteRef, err = f.repo.Reference(plumbing.NewRemoteReferenceName("origin", "master"), true)
		}
		if err != nil {
			return "", false, fmt.Errorf("failed to get remote ref: %w", err)
		}
	}

	currentHash := remoteRef.Hash().String()
	hasChanges := lastHash == "" || lastHash != currentHash

	return currentHash, hasChanges, nil
}

// Close cleans up resources.
// This method is thread-safe.
func (f *GitFetcher) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.tempDir != "" {
		err := os.RemoveAll(f.tempDir)
		f.tempDir = ""
		f.repo = nil
		f.worktree = nil
		return err
	}
	return nil
}

// ReadFile reads a single file from the repository.
// This method is thread-safe and protected against path traversal attacks.
func (f *GitFetcher) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	f.mu.Lock()
	if f.repo == nil {
		f.mu.Unlock()
		return nil, fmt.Errorf("repository not cloned")
	}
	tempDir := f.tempDir
	configPath := f.config.Path
	f.mu.Unlock()

	basePath, err := contentRootOf(tempDir, configPath)
	if err != nil {
		return nil, err
	}
	fullPath, err := confinedRegularFile(basePath, path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

// ListFiles returns all files matching the extensions.
// This method is thread-safe.
func (f *GitFetcher) ListFiles(ctx context.Context, extensions []string) ([]string, error) {
	f.mu.Lock()
	if f.repo == nil {
		f.mu.Unlock()
		return nil, fmt.Errorf("repository not cloned")
	}
	tempDir, configPath := f.tempDir, f.config.Path
	f.mu.Unlock()
	basePath, err := contentRootOf(tempDir, configPath)
	if err != nil {
		return nil, err
	}
	var files []string

	err = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil // symlinks and special files are never templates
		}

		if len(extensions) > 0 {
			ext := filepath.Ext(path)
			for _, e := range extensions {
				if strings.EqualFold(ext, e) {
					relPath, _ := filepath.Rel(basePath, path)
					files = append(files, relPath)
					break
				}
			}
		} else {
			relPath, _ := filepath.Rel(basePath, path)
			files = append(files, relPath)
		}

		return nil
	})

	return files, err
}

func (f *GitFetcher) cloneRepo(ctx context.Context) (*git.Repository, error) {
	if err := checkCloneURL(ctx, f.config.URL); err != nil {
		return nil, fmt.Errorf("git clone blocked: %w", err)
	}

	branch := f.config.Branch
	if branch == "" {
		branch = defaultBranch
	}

	opts := &git.CloneOptions{
		URL:           f.config.URL,
		Auth:          f.auth,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,
		Depth:         1, // Shallow clone for efficiency
	}

	clone := func(c context.Context) (*git.Repository, error) {
		return git.PlainCloneContext(c, f.tempDir, false, opts)
	}
	repo, err := cloneWithSizeCap(ctx, f.tempDir, clone)
	if err != nil && !errors.Is(err, ErrRepositoryTooLarge) {
		// Try master if main fails
		if branch == defaultBranch {
			_ = os.RemoveAll(f.tempDir)
			_ = os.MkdirAll(f.tempDir, 0o700)
			opts.ReferenceName = plumbing.NewBranchReferenceName("master")
			repo, err = cloneWithSizeCap(ctx, f.tempDir, clone)
		}
	}
	if err != nil {
		if errors.Is(err, ErrRepositoryTooLarge) {
			_ = os.RemoveAll(f.tempDir)
		}
		return nil, err
	}

	f.worktree, _ = repo.Worktree()
	return repo, nil
}

func (f *GitFetcher) pullRepo(ctx context.Context) error {
	if f.worktree == nil {
		var err error
		f.worktree, err = f.repo.Worktree()
		if err != nil {
			return err
		}
	}

	err := f.worktree.PullContext(ctx, &git.PullOptions{
		Auth:       f.auth,
		RemoteName: "origin",
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return err
	}

	return nil
}

// checkCloneURL refuses repository URLs the server must not clone: anything
// but https, http and ssh (file://, a bare local path and git:// would read
// the server's own disk or open an unguarded TCP connection), and any host
// that resolves into a blocked range. http(s) is additionally pinned at dial
// time by the SSRF-guarded transport installed in init. ssh is checked here
// only: go-git's ssh transport dials on its own, so a rebinding DNS answer
// between this check and the dial is not covered for ssh.
func checkCloneURL(ctx context.Context, rawURL string) error {
	if allowLocalRepos {
		return nil
	}
	host, err := templatesource.GitURLHost(rawURL)
	if err != nil {
		return err
	}
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		_, err = httpsec.ValidateURL(rawURL)
		return err
	}
	return httpsec.ValidateHost(ctx, host)
}

// contentRoot returns the directory templates are read from: the clone
// directory joined with the configured sub-path, with symlinks resolved and
// confirmed to still be inside the clone.
func (f *GitFetcher) contentRoot() (string, error) {
	return contentRootOf(f.tempDir, f.config.Path)
}

func contentRootOf(cloneDir, subPath string) (string, error) {
	rel, err := templatesource.CleanRepoPath(subPath)
	if err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(cloneDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve clone directory: %w", err)
	}
	base, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", fmt.Errorf("repository path %q not found", rel)
	}
	if !isWithin(root, base) {
		return "", fmt.Errorf("repository path %q resolves outside the repository", rel)
	}
	return base, nil
}

// confinedRegularFile resolves name inside root and returns its path only if
// it is a regular file that is still inside root once every symlink on the
// way (including parent directories) is resolved.
func confinedRegularFile(root, name string) (string, error) {
	rel, err := templatesource.CleanRepoPath(name)
	if err != nil || rel == "" {
		return "", fmt.Errorf("invalid path: path traversal not allowed")
	}
	full := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(full)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("invalid path: not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil || !isWithin(root, resolved) {
		return "", fmt.Errorf("invalid path: path traversal not allowed")
	}
	return resolved, nil
}

// isWithin reports whether path is root or below it. Both must be cleaned,
// symlink-resolved absolute paths.
func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}
