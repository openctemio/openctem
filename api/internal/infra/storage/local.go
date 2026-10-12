// Package storage provides FileStorage implementations.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// LocalStorage stores files on the local filesystem.
// Directory layout: {basePath}/{tenantID}/{storageKey}
//
// Suits single-node deployments: put basePath on a persistent volume and back
// it up. Several API replicas need a shared (ReadWriteMany) volume or S3.
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a local filesystem storage provider.
func NewLocalStorage(basePath string) *LocalStorage {
	return &LocalStorage{basePath: basePath}
}

// Upload streams the content to a temporary file in the tenant directory,
// syncs it and renames it to its key, so a crash or a failed read never
// leaves a partial file under a key. Directories are 0700 and files 0600:
// only the API's own user reads them.
func (s *LocalStorage) Upload(_ context.Context, tenantID, filename, _ string, reader io.Reader) (string, error) {
	if err := checkNamespace(tenantID); err != nil {
		return "", err
	}
	// Storage key = UUID prefix + sanitized filename (unique, human-readable in filesystem)
	key := fmt.Sprintf("%s_%s", shared.NewID().String(), sanitizeFilename(filename))

	dir := filepath.Join(s.basePath, tenantID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create tenant dir: %w", err)
	}

	path, err := s.safePath(tenantID, key)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := io.Copy(tmp, reader); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("failed to sync file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("failed to close file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("failed to store file: %w", err)
	}
	committed = true
	return key, nil
}

func (s *LocalStorage) Download(_ context.Context, tenantID, storageKey string) (io.ReadCloser, string, error) {
	path, err := s.safePath(tenantID, storageKey)
	if err != nil {
		return nil, "", err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", attachment.ErrNotFound
		}
		return nil, "", fmt.Errorf("failed to open file: %w", err)
	}
	return f, path, nil
}

func (s *LocalStorage) Delete(_ context.Context, tenantID, storageKey string) error {
	path, err := s.safePath(tenantID, storageKey)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}

// EraseTenant removes the tenant directory {basePath}/{tenantID} and every
// file in it. A tenant directory that is a symlink is unlinked, never followed,
// so nothing outside the tenant namespace is touched.
func (s *LocalStorage) EraseTenant(_ context.Context, tenantID string) (int, error) {
	if err := attachment.ValidateTenantNamespace(tenantID); err != nil {
		return 0, err
	}
	baseAbs, err := filepath.Abs(s.basePath)
	if err != nil {
		return 0, fmt.Errorf("resolve base path: %w", err)
	}
	dir := filepath.Join(baseAbs, tenantID)
	st, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("stat tenant dir: %w", err)
	}
	if !st.IsDir() {
		// A symlink (or stray file) in place of the directory: remove the
		// entry itself; os.Remove does not follow a symlink.
		if err := os.Remove(dir); err != nil {
			return 0, fmt.Errorf("remove tenant entry: %w", err)
		}
		return 0, nil
	}
	n := 0
	// WalkDir does not follow symlinks; it only counts what is removed.
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	if err := os.RemoveAll(dir); err != nil {
		return 0, fmt.Errorf("remove tenant dir: %w", err)
	}
	return n, nil
}

// safePath joins basePath/tenantID/key and verifies the result (after
// resolving any existing symlinks on the tenant dir) stays within
// basePath. If an attacker manages to pre-place a symlink
// `basePath/tenantA/link -> /etc` they must not be able to drive a
// read/write outside basePath via this method.
//
// Defense: compute the absolute basePath once, resolve symlinks on
// the PARENT of the target (tenant dir) — which must exist already —
// and reject if it escapes. The leaf file is not resolved because a
// fresh upload creates it; symlink-racing the leaf between stat and
// open is out of scope (defender would also need to drop privileges
// and tighten umask for that threat).
func (s *LocalStorage) safePath(tenantID, key string) (string, error) {
	if strings.ContainsAny(tenantID, "/\\") || strings.ContainsAny(key, "/\\") {
		return "", fmt.Errorf("invalid path component")
	}
	baseAbs, err := filepath.Abs(s.basePath)
	if err != nil {
		return "", fmt.Errorf("resolve base path: %w", err)
	}
	tenantDir := filepath.Join(baseAbs, tenantID)
	// EvalSymlinks requires the path to exist; for Upload the tenant
	// dir was just MkdirAll'd, so it exists. For Download/Delete a
	// missing tenant dir is a legitimate not-found case, so fall back
	// to a textual prefix check in that narrow window.
	resolved := tenantDir
	if st, statErr := os.Stat(tenantDir); statErr == nil && st.IsDir() {
		resolved, err = filepath.EvalSymlinks(tenantDir)
		if err != nil {
			return "", fmt.Errorf("resolve tenant dir: %w", err)
		}
	}
	if resolved != baseAbs && !strings.HasPrefix(resolved+string(filepath.Separator), baseAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("tenant dir escapes base path")
	}
	return filepath.Join(resolved, key), nil
}

// checkNamespace refuses a namespace (a tenant id, or a fixed platform
// namespace such as content packs') that is empty, a dot segment or holds a
// path separator, so a key can never be written outside its namespace.
func checkNamespace(ns string) error {
	if ns == "" || ns == "." || ns == ".." || strings.ContainsAny(ns, "/\\\x00") {
		return fmt.Errorf("invalid storage namespace %q", ns)
	}
	return nil
}

// sanitizeFilename strips path separators and control characters.
func sanitizeFilename(name string) string {
	// Remove directory components
	name = filepath.Base(name)
	// Replace problematic characters
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == '/' || r == '\\' || r == ':' || r == '"' || r == '|' || r == '?' || r == '*' {
			return '_'
		}
		return r
	}, name)
	// Limit length
	if len(name) > 200 {
		ext := filepath.Ext(name)
		name = name[:200-len(ext)] + ext
	}
	if name == "" || name == "." {
		name = "unnamed"
	}
	return name
}
