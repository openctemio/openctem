// Package storage provides FileStorage implementations.
package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
)

// LocalStorage stores files on the local filesystem.
// Directory layout: {basePath}/{tenantID}/{storageKey}
//
// Intended for development and small self-hosted deployments.
// For production, use S3Storage or MinIOStorage (implement the same interface).
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a local filesystem storage provider.
func NewLocalStorage(basePath string) *LocalStorage {
	return &LocalStorage{basePath: basePath}
}

func (s *LocalStorage) Upload(_ context.Context, tenantID, filename, _ string, reader io.Reader) (string, error) {
	// Sanitize filename — strip path separators, limit length
	safe := sanitizeFilename(filename)

	// Storage key = UUID prefix + sanitized filename (unique, human-readable in filesystem)
	key := fmt.Sprintf("%s_%s", shared.NewID().String(), safe)

	dir := filepath.Join(s.basePath, tenantID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create tenant dir: %w", err)
	}

	path, err := s.safePath(tenantID, key)
	if err != nil {
		return "", err
	}
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, reader); err != nil {
		_ = os.Remove(path) // cleanup partial
		return "", fmt.Errorf("failed to write file: %w", err)
	}

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
