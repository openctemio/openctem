package fetchers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Security: URL Validation (SSRF Prevention)
// =============================================================================

// blockedIPRanges contains IP ranges that should never be accessed.
// This prevents SSRF attacks against internal services and cloud metadata.
var blockedIPRanges = []string{
	"127.0.0.0/8",        // Loopback
	"10.0.0.0/8",         // Private class A
	"172.16.0.0/12",      // Private class B
	"192.168.0.0/16",     // Private class C
	"169.254.0.0/16",     // Link-local (includes AWS metadata 169.254.169.254)
	"100.64.0.0/10",      // Carrier-grade NAT
	"0.0.0.0/8",          // "This" network
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Broadcast
	"::1/128",            // IPv6 loopback
	"fc00::/7",           // IPv6 unique local
	"fe80::/10",          // IPv6 link-local
}

// blockedCIDRs is the parsed version of blockedIPRanges.
var blockedCIDRs []*net.IPNet

func init() {
	for _, cidr := range blockedIPRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, ipNet)
		}
	}
}

// isIPBlocked checks if an IP address is in a blocked range.
func isIPBlocked(ip net.IP) bool {
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// urlValidationResult contains the result of URL validation including resolved IPs.
// This is used to prevent DNS rebinding attacks by pinning IPs at validation time.
type urlValidationResult struct {
	parsedURL   *url.URL
	resolvedIPs []net.IP // Pinned IPs from DNS resolution at validation time
}

// validateURL checks if a URL is safe to fetch (SSRF prevention).
// Returns an error if the URL points to a blocked destination.
func validateURL(rawURL string) error {
	_, err := validateURLWithIPs(rawURL)
	return err
}

// validateURLWithIPs validates a URL and returns the resolved IPs.
// This prevents DNS rebinding attacks by pinning IPs at validation time.
// The returned IPs should be used when making the actual HTTP request.
func validateURLWithIPs(rawURL string) (*urlValidationResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTP(S) schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s (only http/https allowed)", parsed.Scheme)
	}

	// Block common dangerous hostnames
	hostname := strings.ToLower(parsed.Hostname())
	dangerousHosts := []string{
		"localhost",
		"metadata",
		"metadata.google.internal",
		"metadata.google",
		"169.254.169.254", // AWS/GCP/Azure metadata
	}
	for _, blocked := range dangerousHosts {
		if hostname == blocked {
			return nil, fmt.Errorf("blocked hostname: %s", hostname)
		}
	}

	// Resolve hostname and check IP addresses
	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		// If DNS fails, we can't validate - fail closed
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", parsed.Hostname(), err)
	}

	// Filter and validate IPs
	validIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if isIPBlocked(ip) {
			return nil, fmt.Errorf("blocked IP address: %s resolves to %s", parsed.Hostname(), ip.String())
		}
		validIPs = append(validIPs, ip)
	}

	if len(validIPs) == 0 {
		return nil, fmt.Errorf("no valid IP addresses for %s", parsed.Hostname())
	}

	return &urlValidationResult{
		parsedURL:   parsed,
		resolvedIPs: validIPs,
	}, nil
}

// =============================================================================
// Security: Archive Extraction Limits
// =============================================================================

const (
	// maxArchiveEntries is the maximum number of files in an archive.
	// Prevents denial of service via archives with millions of small files.
	maxArchiveEntries = 1000

	// maxDecompressedSize is the maximum total decompressed size.
	// Prevents zip bomb attacks where small archives expand to huge sizes.
	maxDecompressedSize = 100 * 1024 * 1024 // 100MB

	// maxPathLength is the maximum allowed path length in archives.
	maxPathLength = 256
)

// sanitizeArchivePath validates and sanitizes a file path from an archive.
// Returns an error if the path is dangerous (path traversal attempt).
func sanitizeArchivePath(name string) (string, error) {
	// Check path length
	if len(name) > maxPathLength {
		return "", fmt.Errorf("path too long: %d > %d", len(name), maxPathLength)
	}

	// Clean the path
	cleaned := filepath.Clean(name)

	// Reject absolute paths
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute path not allowed: %s", name)
	}

	// Reject paths that escape the directory
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "/../") {
		return "", fmt.Errorf("path traversal not allowed: %s", name)
	}

	// Reject paths with backslashes (Windows-style)
	if strings.Contains(name, "\\") {
		return "", fmt.Errorf("backslash in path not allowed: %s", name)
	}

	// Use only the base filename for storage (flatten directory structure)
	return filepath.Base(cleaned), nil
}

// HTTPConfig contains configuration for HTTP fetcher.
type HTTPConfig struct {
	URL      string
	AuthType string            // none, bearer, basic, api_key
	Token    string            // Bearer token or API key
	Username string            // For basic auth
	Password string            // For basic auth
	Headers  map[string]string // Additional headers
	Timeout  time.Duration
}

// HTTPFetcher fetches templates from HTTP URLs.
// This fetcher is thread-safe and can be used concurrently.
type HTTPFetcher struct {
	config     HTTPConfig
	httpClient *http.Client
	pinnedIPs  []net.IP   // Pinned IPs to prevent DNS rebinding attacks
	mu         sync.Mutex // Protects lastETag
	lastETag   string
}

// NewHTTPFetcher creates a new HTTP fetcher.
// Returns an error if the URL is blocked (SSRF prevention).
// The fetcher pins DNS resolution at creation time to prevent DNS rebinding attacks.
func NewHTTPFetcher(config HTTPConfig) (*HTTPFetcher, error) {
	// Validate URL and get pinned IPs before creating fetcher (SSRF prevention)
	validationResult, err := validateURLWithIPs(config.URL)
	if err != nil {
		return nil, fmt.Errorf("URL validation failed: %w", err)
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	// Limit timeout to prevent hanging connections
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}

	// Create a custom dialer that uses pinned IPs to prevent DNS rebinding
	pinnedIPs := validationResult.resolvedIPs
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Custom transport that pins DNS resolution
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract host and port from addr
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address: %w", err)
			}

			// If this is our target host, use pinned IPs
			if host == validationResult.parsedURL.Hostname() {
				// Re-validate IP before connecting (defense in depth)
				for _, ip := range pinnedIPs {
					if isIPBlocked(ip) {
						return nil, fmt.Errorf("blocked IP: %s", ip.String())
					}
				}
				// Use the first valid pinned IP
				addr = net.JoinHostPort(pinnedIPs[0].String(), port)
			} else {
				// For redirects, validate the new host
				newIPs, err := net.LookupIP(host)
				if err != nil {
					return nil, fmt.Errorf("DNS lookup failed: %w", err)
				}
				for _, ip := range newIPs {
					if isIPBlocked(ip) {
						return nil, fmt.Errorf("redirect to blocked IP: %s", ip.String())
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &HTTPFetcher{
		config:    config,
		pinnedIPs: pinnedIPs,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Limit redirects and validate each redirect URL
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				// Validate redirect URL (with full DNS resolution for redirect target)
				if err := validateURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect blocked: %w", err)
				}
				return nil
			},
		},
	}, nil
}

// Fetch downloads files from the HTTP URL.
// Supports single files, .zip, .tar.gz, and .tgz archives.
func (f *HTTPFetcher) Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.config.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication
	f.addAuth(req)

	// Add ETag for conditional request
	if opts.LastHash != "" {
		req.Header.Set("If-None-Match", opts.LastHash)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	// Handle not modified
	if resp.StatusCode == http.StatusNotModified {
		return &FetchResult{
			Hash:      opts.LastHash,
			FetchedAt: time.Now(),
			Files:     make(map[string][]byte),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Get ETag for caching (thread-safe)
	etag := resp.Header.Get("ETag")
	f.mu.Lock()
	f.lastETag = etag
	f.mu.Unlock()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check total size
	if opts.MaxTotalSize > 0 && int64(len(body)) > opts.MaxTotalSize {
		return nil, fmt.Errorf("response exceeds size limit")
	}

	// Determine content type
	contentType := resp.Header.Get("Content-Type")
	url := f.config.URL

	var files map[string][]byte

	// Handle different content types
	switch {
	case strings.HasSuffix(url, ".zip") || strings.Contains(contentType, "application/zip"):
		files, err = f.extractZip(body, opts)
	case strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tgz") ||
		strings.Contains(contentType, "application/gzip") ||
		strings.Contains(contentType, "application/x-gzip"):
		files, err = f.extractTarGz(body, opts)
	default:
		// Single file
		filename := filepath.Base(url)
		if filename == "" || filename == "/" {
			filename = "template"
		}
		files = map[string][]byte{filename: body}
	}

	if err != nil {
		return nil, err
	}

	// Calculate total size
	var totalSize int64
	for _, content := range files {
		totalSize += int64(len(content))
	}

	// Generate hash from ETag or content
	hash := etag
	if hash == "" {
		hash = computeContentHash(files)
	}

	return &FetchResult{
		Files:      files,
		Hash:       hash,
		FetchedAt:  time.Now(),
		TotalFiles: len(files),
		TotalSize:  totalSize,
	}, nil
}

// CheckForUpdates uses HEAD request with If-None-Match.
func (f *HTTPFetcher) CheckForUpdates(ctx context.Context, lastHash string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", f.config.URL, nil)
	if err != nil {
		return "", false, fmt.Errorf("failed to create request: %w", err)
	}

	f.addAuth(req)

	if lastHash != "" {
		req.Header.Set("If-None-Match", lastHash)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("failed to check updates: %w", err)
	}
	resp.Body.Close()

	etag := resp.Header.Get("ETag")

	// 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		return lastHash, false, nil
	}

	// Has changes if status is 200 and ETag differs
	if resp.StatusCode == http.StatusOK {
		hasChanges := lastHash == "" || (etag != "" && etag != lastHash)
		return etag, hasChanges, nil
	}

	return "", false, fmt.Errorf("unexpected status: %d", resp.StatusCode)
}

// Close releases resources.
func (f *HTTPFetcher) Close() error {
	return nil
}

// ReadFile reads a single file (only works for single-file URLs).
func (f *HTTPFetcher) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.config.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	f.addAuth(req)

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// ListFiles returns file names (limited for HTTP).
func (f *HTTPFetcher) ListFiles(ctx context.Context, extensions []string) ([]string, error) {
	// For HTTP, we need to fetch to know the files
	result, err := f.Fetch(ctx, FetchOptions{Extensions: extensions})
	if err != nil {
		return nil, err
	}

	files := make([]string, 0, len(result.Files))
	for name := range result.Files {
		files = append(files, name)
	}

	return files, nil
}

func (f *HTTPFetcher) addAuth(req *http.Request) {
	switch f.config.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+f.config.Token)
	case "basic":
		req.SetBasicAuth(f.config.Username, f.config.Password)
	case "api_key":
		req.Header.Set("X-API-Key", f.config.Token)
	}

	// Add custom headers
	for k, v := range f.config.Headers {
		req.Header.Set(k, v)
	}
}

func (f *HTTPFetcher) extractZip(data []byte, opts FetchOptions) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to read zip: %w", err)
	}

	// Security: Limit number of archive entries
	if len(reader.File) > maxArchiveEntries {
		return nil, fmt.Errorf("too many files in archive: %d > %d", len(reader.File), maxArchiveEntries)
	}

	files := make(map[string][]byte)
	var totalDecompressedSize int64

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		// Security: Validate and sanitize path (path traversal prevention)
		safeName, err := sanitizeArchivePath(file.Name)
		if err != nil {
			// Skip files with dangerous paths instead of failing
			continue
		}

		// Check extension filter
		if len(opts.Extensions) > 0 {
			ext := filepath.Ext((safeName))
			matched := false
			for _, e := range opts.Extensions {
				if strings.EqualFold(ext, e) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Security: Check uncompressed size against zip bomb limit
		if file.UncompressedSize64 > uint64(maxDecompressedSize) {
			return nil, fmt.Errorf("file %s exceeds max size: %d > %d", safeName, file.UncompressedSize64, maxDecompressedSize)
		}

		// Check per-file size limit
		// Safe conversion: already validated against maxDecompressedSize which fits in int64
		//nolint:gosec // G115: safe conversion, size already validated above
		fileSize := int64(file.UncompressedSize64)
		if opts.MaxFileSize > 0 && fileSize > opts.MaxFileSize {
			continue
		}

		// Security: Track total decompressed size (zip bomb prevention)
		totalDecompressedSize += fileSize
		if totalDecompressedSize > maxDecompressedSize {
			return nil, fmt.Errorf("total decompressed size exceeds limit: %d > %d", totalDecompressedSize, maxDecompressedSize)
		}

		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", safeName, err)
		}

		// Security: Use LimitReader to prevent reading more than declared
		//nolint:gosec // G115: safe conversion, size already validated above
		content, err := io.ReadAll(io.LimitReader(rc, int64(file.UncompressedSize64)+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", safeName, err)
		}

		// Security: Verify actual size matches declared size
		//nolint:gosec // G115: safe conversion, size already validated above
		if len(content) > int(file.UncompressedSize64) {
			return nil, fmt.Errorf("file %s actual size exceeds declared size", safeName)
		}

		files[safeName] = content
	}

	return files, nil
}

func (f *HTTPFetcher) extractTarGz(data []byte, opts FetchOptions) (map[string][]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	files := make(map[string][]byte)
	var totalDecompressedSize int64
	entryCount := 0

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar: %w", err)
		}

		// Security: Limit number of archive entries
		entryCount++
		if entryCount > maxArchiveEntries {
			return nil, fmt.Errorf("too many files in archive: %d > %d", entryCount, maxArchiveEntries)
		}

		// Security: Only allow regular files (block symlinks, hard links, devices)
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Security: Validate and sanitize path (path traversal prevention)
		safeName, err := sanitizeArchivePath(header.Name)
		if err != nil {
			// Skip files with dangerous paths instead of failing
			continue
		}

		// Check extension filter
		if len(opts.Extensions) > 0 {
			ext := filepath.Ext((safeName))
			matched := false
			for _, e := range opts.Extensions {
				if strings.EqualFold(ext, e) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Security: Check file size against limit (tar bomb prevention)
		if header.Size > maxDecompressedSize {
			return nil, fmt.Errorf("file %s exceeds max size: %d > %d", safeName, header.Size, maxDecompressedSize)
		}

		// Check per-file size limit
		if opts.MaxFileSize > 0 && header.Size > opts.MaxFileSize {
			continue
		}

		// Security: Track total decompressed size
		totalDecompressedSize += header.Size
		if totalDecompressedSize > maxDecompressedSize {
			return nil, fmt.Errorf("total decompressed size exceeds limit: %d > %d", totalDecompressedSize, maxDecompressedSize)
		}

		// Security: Use LimitReader to enforce declared size
		content, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", safeName, err)
		}

		// Security: Verify actual size doesn't exceed declared
		if int64(len(content)) > header.Size {
			return nil, fmt.Errorf("file %s actual size exceeds declared size", safeName)
		}

		files[safeName] = content
	}

	return files, nil
}

func computeContentHash(files map[string][]byte) string {
	hashes := make([]string, 0, len(files))
	for name, content := range files {
		hash := fmt.Sprintf("%s:%x", name, len(content))
		hashes = append(hashes, hash)
	}
	return computeCombinedHash(hashes)
}
