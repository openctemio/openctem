// Package fetchers provides template fetching from various sources (Git, S3, HTTP).
package fetchers

import (
	"context"
	"io"
	"time"
)

// FetchResult contains the result of a fetch operation.
type FetchResult struct {
	// Files contains the fetched files (path -> content)
	Files map[string][]byte

	// Hash is a unique identifier for this version (commit hash, ETag, etc.)
	Hash string

	// FetchedAt is when the fetch completed
	FetchedAt time.Time

	// TotalFiles is the number of files found
	TotalFiles int

	// TotalSize is the total size of all files in bytes
	TotalSize int64
}

// FetchOptions contains options for fetching.
type FetchOptions struct {
	// LastHash is the previous hash to check for changes
	// If current hash matches, fetch can be skipped
	LastHash string

	// Extensions filters files by extension (e.g., []string{".yaml", ".yml"})
	Extensions []string

	// MaxFileSize limits individual file size (0 = no limit)
	MaxFileSize int64

	// MaxTotalSize limits total download size (0 = no limit)
	MaxTotalSize int64
}

// Fetcher is the interface for template source fetchers.
type Fetcher interface {
	// Fetch downloads files from the source
	Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error)

	// CheckForUpdates returns the current hash without downloading
	// Returns nil if unable to determine (fetch required)
	CheckForUpdates(ctx context.Context, lastHash string) (string, bool, error)

	// Close releases any resources
	Close() error
}

// FileReader provides streaming access to individual files.
type FileReader interface {
	// ReadFile reads a single file by path
	ReadFile(ctx context.Context, path string) (io.ReadCloser, error)

	// ListFiles returns all file paths matching the criteria
	ListFiles(ctx context.Context, extensions []string) ([]string, error)
}
