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

	path := filepath.Join(dir, key)
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
	path := filepath.Join(s.basePath, tenantID, storageKey)
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
	path := filepath.Join(s.basePath, tenantID, storageKey)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
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
