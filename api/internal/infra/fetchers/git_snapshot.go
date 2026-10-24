// Package fetchers fetches rule source content for the platform, which is
// the only fetcher of rules (docs/architecture/content-sources.md).
package fetchers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// gitTimeout bounds one git operation over HTTP: generous for a large
// repository, still a cap on a hung or slow remote.
const gitTimeout = 5 * time.Minute

// init routes go-git's https transport through the SSRF-guarded client
// whose dialer refuses internal and cloud-metadata addresses. Whether the
// private ranges the installation allows are reachable is decided per
// connection at dial time from the fetch's context (GitRequest.PrivateOK):
// an organization without the private-network feature reaches public hosts
// only, even where the installation opened private ranges. The protocol
// registry is process-global and not safe to change during a clone, so it is
// set once. A per-source CA bundle is applied by go-git on a clone of this
// transport, which keeps the guarded dialer.
func init() {
	guarded := githttp.NewClient(httpsec.RequestPolicyHTTPClient(gitTimeout))
	client.InstallProtocol("https", guarded)
	client.InstallProtocol("http", guarded)
}

// allowLocalRepos lets tests clone from a local path. Production never sets
// it: go-git serves file:// URLs and bare paths in-process, which would read
// the API server's own disk.
var allowLocalRepos = false

// Limits of one snapshot fetch. The bare clone lands on the API server's
// disk; it is aborted past MaxCloneBytes.
var (
	MaxCloneBytes int64 = 200 << 20
	cloneSizePoll       = 250 * time.Millisecond
	// MinFreeDiskBytes is the free space that must remain on the clone
	// directory's disk beyond one clone: a full disk stops the database.
	MinFreeDiskBytes uint64 = 1 << 30
	// freeDiskBytes reads the free space of a directory's disk (tests).
	freeDiskBytes = diskFree
)

// Errors.
var (
	ErrRepositoryTooLarge = errors.New("the repository exceeds the rule source size limit")
	ErrRefNotFound        = errors.New("the ref was not found in the repository")
	ErrPathNotFound       = errors.New("the path was not found in the repository")
	ErrLFSPointer         = errors.New("the repository stores files in Git LFS, which rule sources do not support")
	ErrTooManyFiles       = errors.New("the path holds more files than a rule source may")
	ErrTooMuchContent     = errors.New("the path holds more content than a rule source may")
	ErrLowDisk            = errors.New("the server is low on free disk space and does not fetch repositories right now")
)

// GitRequest is one snapshot fetch.
type GitRequest struct {
	URL      string // https
	Ref      string // branch, tag or full commit SHA
	Path     string // cleaned sub-directory, "" for the root
	Username string
	Token    string // "" for a public repository
	CABundle []byte // extra trusted roots for this source only
	// PrivateOK lets the connection reach the private ranges the
	// installation allows (the organization has the private-network
	// feature). Otherwise only public addresses are reachable, decided at
	// dial time.
	PrivateOK bool
	MaxFiles  int
	MaxFile   int64 // bytes per file
	MaxTotal  int64 // bytes of all files
}

// File is one fetched file, its path relative to Path.
type File struct {
	Path string
	Data []byte
}

// Skipped is an entry left out of the snapshot (a symlink or submodule).
type Skipped struct {
	Path   string
	Reason string
}

// GitSnapshot is the content of a ref at one commit.
type GitSnapshot struct {
	Commit  string
	Files   []File
	Skipped []Skipped
	License []byte // the repository's LICENSE or COPYING file, if any
}

var lfsPointer = []byte("version https://git-lfs.github.com/spec/v1")

// SnapshotGit clones ref (bare: nothing is checked out), resolves it to a
// commit and reads the files under Path from the commit's tree. Only
// regular blobs are read; a symlink or submodule is skipped and reported,
// so nothing on the server's disk is ever read through the repository. A Git
// LFS pointer refuses the snapshot. The canonical content is a function of
// the commit and path only.
func SnapshotGit(ctx context.Context, req GitRequest) (*GitSnapshot, error) {
	if err := checkRemote(ctx, req.URL); err != nil {
		return nil, err
	}
	if req.PrivateOK {
		ctx = httpsec.WithInstancePrivate(ctx)
	}
	dir, err := os.MkdirTemp("", "rule-source-*")
	if err != nil {
		return nil, fmt.Errorf("create clone directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := checkFreeDisk(dir); err != nil {
		return nil, err
	}

	repo, commit, err := cloneRef(ctx, dir, req)
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read commit tree: %w", err)
	}
	out := &GitSnapshot{Commit: commit.Hash.String()}
	out.License = licenseOf(tree)
	if req.Path != "" {
		sub, err := tree.Tree(req.Path)
		if err != nil {
			return nil, ErrPathNotFound
		}
		tree = sub
	}
	var total int64
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		name, entry, err := walker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("walk tree: %w", err)
		}
		switch entry.Mode {
		case filemode.Dir:
			continue
		case filemode.Regular, filemode.Executable, filemode.Deprecated:
		default: // symlink, submodule
			out.Skipped = append(out.Skipped, Skipped{Path: name, Reason: "not a regular file"})
			continue
		}
		if req.MaxFiles > 0 && len(out.Files) >= req.MaxFiles {
			return nil, ErrTooManyFiles
		}
		blob, err := repo.BlobObject(entry.Hash)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if req.MaxFile > 0 && blob.Size > req.MaxFile {
			return nil, fmt.Errorf("%s is larger than %d bytes", name, req.MaxFile)
		}
		total += blob.Size
		if req.MaxTotal > 0 && total > req.MaxTotal {
			return nil, ErrTooMuchContent
		}
		data, err := readBlob(blob)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if bytes.HasPrefix(data, lfsPointer) {
			return nil, ErrLFSPointer
		}
		out.Files = append(out.Files, File{Path: name, Data: data})
	}
	return out, nil
}

// checkFreeDisk refuses a fetch when the clone directory's disk would be
// left with less than MinFreeDiskBytes after a clone of MaxCloneBytes. It
// fails closed when the free space cannot be read.
func checkFreeDisk(dir string) error {
	free, err := freeDiskBytes(dir)
	if err != nil {
		return fmt.Errorf("check free disk space: %w", err)
	}
	if free < uint64(MaxCloneBytes)+MinFreeDiskBytes { //nolint:gosec // MaxCloneBytes is positive
		return ErrLowDisk
	}
	return nil
}

func readBlob(b *object.Blob) ([]byte, error) {
	r, err := b.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, b.Size+1))
}

// licenseOf returns the root LICENSE/COPYING file (at most 64 KiB).
func licenseOf(tree *object.Tree) []byte {
	for _, e := range tree.Entries {
		n := strings.ToUpper(e.Name)
		if !e.Mode.IsFile() || !(strings.HasPrefix(n, "LICEN") || strings.HasPrefix(n, "COPYING")) {
			continue
		}
		f, err := tree.TreeEntryFile(&e)
		if err != nil || f.Size > 64<<10 {
			continue
		}
		s, err := f.Contents()
		if err != nil {
			continue
		}
		return []byte(s)
	}
	return nil
}

// cloneRef clones the ref into dir and returns its commit. A branch or tag
// is cloned shallow; a commit SHA needs the history that contains it.
func cloneRef(ctx context.Context, dir string, req GitRequest) (*git.Repository, *object.Commit, error) {
	opts := &git.CloneOptions{URL: req.URL, CABundle: req.CABundle, Tags: git.NoTags}
	if req.Token != "" {
		opts.Auth = &githttp.BasicAuth{Username: req.Username, Password: req.Token}
	}
	if isSHA(req.Ref) {
		repo, err := cloneSized(ctx, dir, opts)
		if err != nil {
			return nil, nil, err
		}
		c, err := repo.CommitObject(plumbing.NewHash(req.Ref))
		if err != nil {
			return nil, nil, ErrRefNotFound
		}
		return repo, c, nil
	}
	opts.SingleBranch, opts.Depth = true, 1
	var lastErr error // the last missing-ref error, for debugging
	for _, name := range []plumbing.ReferenceName{plumbing.NewBranchReferenceName(req.Ref), plumbing.NewTagReferenceName(req.Ref)} {
		opts.ReferenceName = name
		repo, err := cloneSized(ctx, dir, opts)
		if err != nil {
			if errors.Is(err, ErrRepositoryTooLarge) || !isRefMissing(err) {
				return nil, nil, err
			}
			lastErr = err
			if rerr := resetDir(dir); rerr != nil {
				return nil, nil, rerr
			}
			continue
		}
		head, err := repo.Head()
		if err != nil {
			return nil, nil, fmt.Errorf("resolve %s: %w", req.Ref, err)
		}
		c, err := repo.CommitObject(head.Hash())
		if err != nil {
			// An annotated tag: HEAD names the tag object.
			tag, terr := repo.TagObject(head.Hash())
			if terr != nil {
				return nil, nil, fmt.Errorf("resolve %s: %w", req.Ref, err)
			}
			if c, err = tag.Commit(); err != nil {
				return nil, nil, fmt.Errorf("resolve %s: %w", req.Ref, err)
			}
		}
		return repo, c, nil
	}
	_ = lastErr
	return nil, nil, ErrRefNotFound
}

func isRefMissing(err error) bool {
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "couldn't find remote ref") || strings.Contains(msg, "reference not found")
}

func resetDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func isSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func cloneSized(ctx context.Context, dir string, opts *git.CloneOptions) (*git.Repository, error) {
	limit, poll := MaxCloneBytes, cloneSizePoll
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var tooLarge atomic.Bool
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(poll)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if dirSize(dir) > limit {
					tooLarge.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	repo, err := git.PlainCloneContext(cctx, dir, true, opts)
	close(done)
	<-stopped
	if tooLarge.Load() || (err == nil && dirSize(dir) > limit) {
		return nil, ErrRepositoryTooLarge
	}
	return repo, err
}

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

// checkRemote refuses anything but an https URL whose host is allowed by
// the SSRF guard (public, or in the installation's allowed private ranges).
// The dial is checked again by the guarded transport.
func checkRemote(ctx context.Context, rawURL string) error {
	if allowLocalRepos {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		return errors.New("rule sources are fetched over https only")
	}
	if _, err := httpsec.ValidateURL(rawURL); err != nil {
		return fmt.Errorf("the repository host is not allowed: %w", err)
	}
	return nil
}

// RemoteIsPrivate reports whether an https URL's host resolves into a
// private range (reachable only where the installation allows it). It
// fails closed: a host the guard refuses, or that does not resolve, is an
// error.
func RemoteIsPrivate(rawURL string) (bool, error) {
	if allowLocalRepos {
		return false, nil
	}
	res, err := httpsec.ValidateURL(rawURL)
	if err != nil {
		return false, fmt.Errorf("the repository host is not allowed: %w", err)
	}
	for _, ip := range res.ResolvedIPs {
		if httpsec.IsPrivateIP(ip) {
			return true, nil
		}
	}
	return false, nil
}
