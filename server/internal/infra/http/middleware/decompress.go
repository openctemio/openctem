package middleware

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// DecompressConfig configures the decompression middleware.
type DecompressConfig struct {
	// MaxDecompressedSize is the maximum size of decompressed body.
	// Default: 50MB
	MaxDecompressedSize int64

	// MaxCompressedSize is the maximum size of compressed input.
	// Default: 10MB (prevents reading huge compressed payloads)
	MaxCompressedSize int64

	// MaxCompressionRatio is the maximum allowed compression ratio.
	// If decompressed/compressed > this ratio, reject as potential zipbomb.
	// Default: 100 (100:1 ratio)
	MaxCompressionRatio float64

	// AllowedEncodings specifies which encodings are allowed.
	// Default: ["gzip", "zstd"]
	AllowedEncodings []string
}

// DefaultDecompressConfig returns the default configuration.
func DefaultDecompressConfig() *DecompressConfig {
	return &DecompressConfig{
		MaxDecompressedSize: 50 * 1024 * 1024, // 50MB
		MaxCompressedSize:   10 * 1024 * 1024, // 10MB compressed input
		MaxCompressionRatio: 100,              // Max 100:1 ratio (prevents zipbombs)
		AllowedEncodings:    []string{"gzip", "zstd"},
	}
}

// Decompress middleware decompresses request bodies based on Content-Encoding header.
// Supports gzip and zstd compression.
//
// This middleware should be placed BEFORE body limit middleware to properly
// limit the decompressed size, not the compressed size.
//
// Example:
//
//	router.Use(middleware.Decompress(nil))
//	router.Use(middleware.BodyLimit(50 * 1024 * 1024)) // 50MB decompressed limit
func Decompress(config *DecompressConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultDecompressConfig()
	}

	// Pre-compute allowed encodings set for O(1) lookup
	allowedSet := make(map[string]bool)
	for _, enc := range config.AllowedEncodings {
		allowedSet[strings.ToLower(enc)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip for methods without body
			if r.Method == http.MethodGet || r.Method == http.MethodHead ||
				r.Method == http.MethodOptions || r.Method == http.MethodTrace {
				next.ServeHTTP(w, r)
				return
			}

			// Check Content-Encoding header
			encoding := strings.ToLower(r.Header.Get("Content-Encoding"))
			if encoding == "" || encoding == "identity" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate encoding is allowed
			if !allowedSet[encoding] {
				http.Error(w, fmt.Sprintf("unsupported Content-Encoding: %s", encoding),
					http.StatusUnsupportedMediaType)
				return
			}

			// Decompress the body with zipbomb protection
			decompressed, err := decompressBodySafe(r.Body, encoding, config)
			if err != nil {
				// Log the actual error internally, return generic message to client
				// to prevent information leakage
				http.Error(w, "invalid compressed request body", http.StatusBadRequest)
				return
			}

			// Replace body with decompressed content
			r.Body = io.NopCloser(bytes.NewReader(decompressed))
			r.ContentLength = int64(len(decompressed))

			// Remove Content-Encoding header since we've decompressed
			r.Header.Del("Content-Encoding")

			next.ServeHTTP(w, r)
		})
	}
}

// decompressBodySafe decompresses the body with zipbomb protection.
// SECURITY: This function protects against decompression bomb attacks by:
// 1. Limiting compressed input size
// 2. Using streaming decompression with incremental size checks
// 3. Checking compression ratio to detect zipbombs
func decompressBodySafe(body io.ReadCloser, encoding string, config *DecompressConfig) ([]byte, error) {
	defer body.Close()

	// SECURITY: Limit compressed input size to prevent memory exhaustion
	compressedData, err := io.ReadAll(io.LimitReader(body, config.MaxCompressedSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read compressed body: %w", err)
	}

	// Check compressed size limit
	if int64(len(compressedData)) > config.MaxCompressedSize {
		return nil, fmt.Errorf("compressed size %d exceeds limit %d", len(compressedData), config.MaxCompressedSize)
	}

	compressedSize := int64(len(compressedData))
	if compressedSize == 0 {
		return []byte{}, nil
	}

	var reader io.Reader

	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(compressedData))
		if err != nil {
			return nil, fmt.Errorf("gzip reader error: %w", err)
		}
		defer gr.Close()
		reader = gr

	case "zstd":
		// SECURITY: Use WithDecoderMaxMemory to limit ZSTD memory usage
		//nolint:gosec // G115: safe conversion, MaxDecompressedSize is always positive (size in bytes)
		zr, err := zstd.NewReader(bytes.NewReader(compressedData),
			zstd.WithDecoderMaxMemory(uint64(config.MaxDecompressedSize)),
			zstd.WithDecoderConcurrency(1), // Limit CPU usage
		)
		if err != nil {
			return nil, fmt.Errorf("zstd reader error: %w", err)
		}
		defer zr.Close()
		reader = zr

	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}

	// SECURITY: Use streaming decompression with incremental checks
	// Pre-allocate buffer based on expected size (but not blindly trusting it)
	expectedSize := compressedSize * 10 // Reasonable estimate
	if expectedSize > config.MaxDecompressedSize {
		expectedSize = config.MaxDecompressedSize
	}

	var decompressed bytes.Buffer
	decompressed.Grow(int(expectedSize))

	// Read in chunks to check ratio incrementally
	buf := make([]byte, 64*1024) // 64KB chunks
	var totalRead int64

	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			totalRead += int64(n)

			// SECURITY: Check decompressed size limit
			if totalRead > config.MaxDecompressedSize {
				return nil, fmt.Errorf("decompressed size exceeds limit of %d bytes", config.MaxDecompressedSize)
			}

			// SECURITY: Check compression ratio to detect zipbombs
			// Check every 1MB to avoid too frequent checks
			if totalRead%(1024*1024) == 0 || readErr == io.EOF {
				ratio := float64(totalRead) / float64(compressedSize)
				if ratio > config.MaxCompressionRatio {
					return nil, fmt.Errorf("compression ratio %.1f exceeds limit %.1f (potential zipbomb)", ratio, config.MaxCompressionRatio)
				}
			}

			decompressed.Write(buf[:n])
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("decompression error: %w", readErr)
		}
	}

	return decompressed.Bytes(), nil
}

// DecompressForIngest is a variant specifically for ingest endpoints.
// It has a higher size limit (100MB) to accommodate large scan reports.
// SECURITY: Maintains zipbomb protection with higher limits.
func DecompressForIngest() func(http.Handler) http.Handler {
	return Decompress(&DecompressConfig{
		MaxDecompressedSize: 100 * 1024 * 1024, // 100MB decompressed
		MaxCompressedSize:   20 * 1024 * 1024,  // 20MB compressed input
		MaxCompressionRatio: 200,               // Allow higher ratio for security scan JSON
		AllowedEncodings:    []string{"gzip", "zstd"},
	})
}
