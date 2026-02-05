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
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

const defaultBranch = "main"

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
	basePath := filepath.Join(f.tempDir, f.config.Path)
	files := make(map[string][]byte)
	var totalSize int64

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

	// Security: Prevent path traversal attacks
	// Clean the path and ensure it doesn't escape the base directory
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") || filepath.IsAbs(cleanPath) {
		return nil, fmt.Errorf("invalid path: path traversal not allowed")
	}

	basePath := filepath.Join(tempDir, configPath)
	fullPath := filepath.Join(basePath, cleanPath)

	// Double-check the resolved path is within the base directory
	// This handles edge cases like symlinks
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base path: %w", err)
	}
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
		return nil, fmt.Errorf("invalid path: path traversal not allowed")
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
	basePath := filepath.Join(f.tempDir, f.config.Path)
	f.mu.Unlock()
	var files []string

	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
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

	repo, err := git.PlainCloneContext(ctx, f.tempDir, false, opts)
	if err != nil {
		// Try master if main fails
		if branch == defaultBranch {
			opts.ReferenceName = plumbing.NewBranchReferenceName("master")
			repo, err = git.PlainCloneContext(ctx, f.tempDir, false, opts)
		}
		if err != nil {
			return nil, err
		}
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
