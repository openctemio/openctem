package fetchers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// S3Config contains configuration for S3 fetcher.
type S3Config struct {
	Bucket     string
	Region     string
	Prefix     string // Object prefix (folder path)
	Endpoint   string // Custom endpoint for S3-compatible services
	AuthType   string // keys, sts_role
	AccessKey  string
	SecretKey  string
	RoleARN    string
	ExternalID string
}

// S3Fetcher fetches templates from S3/MinIO.
type S3Fetcher struct {
	config S3Config
	client *s3.Client
}

// NewS3Fetcher creates a new S3 fetcher.
func NewS3Fetcher(ctx context.Context, cfg S3Config) (*S3Fetcher, error) {
	f := &S3Fetcher{config: cfg}

	// Build AWS config
	var awsOpts []func(*config.LoadOptions) error

	awsOpts = append(awsOpts, config.WithRegion(cfg.Region))

	// Setup authentication
	switch cfg.AuthType {
	case "keys":
		awsOpts = append(awsOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	case "sts_role":
		// Load base config first
		baseCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

		stsClient := sts.NewFromConfig(baseCfg)
		assumeOpts := func(o *stscreds.AssumeRoleOptions) {
			if cfg.ExternalID != "" {
				o.ExternalID = aws.String(cfg.ExternalID)
			}
		}
		creds := stscreds.NewAssumeRoleProvider(stsClient, cfg.RoleARN, assumeOpts)
		awsOpts = append(awsOpts, config.WithCredentialsProvider(creds))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client
	s3Opts := []func(*s3.Options){}
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true // Required for MinIO
		})
	}

	f.client = s3.NewFromConfig(awsCfg, s3Opts...)

	return f, nil
}

// Fetch downloads files from S3.
func (f *S3Fetcher) Fetch(ctx context.Context, opts FetchOptions) (*FetchResult, error) {
	// List objects
	prefix := f.config.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var files = make(map[string][]byte)
	var totalSize int64
	var hashes []string

	paginator := s3.NewListObjectsV2Paginator(f.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.config.Bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)

			// Skip "directories"
			if strings.HasSuffix(key, "/") {
				continue
			}

			// Check extension filter
			if len(opts.Extensions) > 0 {
				ext := filepath.Ext((key))
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

			// Check file size
			size := aws.ToInt64(obj.Size)
			if opts.MaxFileSize > 0 && size > opts.MaxFileSize {
				continue
			}

			// Check total size
			if opts.MaxTotalSize > 0 && totalSize+size > opts.MaxTotalSize {
				return nil, fmt.Errorf("total size exceeds limit")
			}

			// Add ETag to hash list
			hashes = append(hashes, aws.ToString(obj.ETag))

			// Download file
			resp, err := f.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(f.config.Bucket),
				Key:    aws.String(key),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to download %s: %w", key, err)
			}

			content, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read %s: %w", key, err)
			}

			// Store with relative path (remove prefix)
			relPath := strings.TrimPrefix(key, prefix)
			files[relPath] = content
			totalSize += size
		}
	}

	// Compute combined hash
	combinedHash := computeCombinedHash(hashes)

	return &FetchResult{
		Files:      files,
		Hash:       combinedHash,
		FetchedAt:  time.Now(),
		TotalFiles: len(files),
		TotalSize:  totalSize,
	}, nil
}

// CheckForUpdates checks if S3 objects have changed.
func (f *S3Fetcher) CheckForUpdates(ctx context.Context, lastHash string) (string, bool, error) {
	prefix := f.config.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var hashes []string

	paginator := s3.NewListObjectsV2Paginator(f.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.config.Bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", false, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			if !strings.HasSuffix(aws.ToString(obj.Key), "/") {
				hashes = append(hashes, aws.ToString(obj.ETag))
			}
		}
	}

	currentHash := computeCombinedHash(hashes)
	hasChanges := lastHash == "" || lastHash != currentHash

	return currentHash, hasChanges, nil
}

// Close releases resources.
func (f *S3Fetcher) Close() error {
	// S3 client doesn't need explicit cleanup
	return nil
}

// ReadFile reads a single file from S3.
func (f *S3Fetcher) ReadFile(ctx context.Context, path string) (io.ReadCloser, error) {
	key := f.config.Prefix
	if key != "" && !strings.HasSuffix(key, "/") {
		key += "/"
	}
	key += path

	resp, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(f.config.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	return resp.Body, nil
}

// ListFiles returns all files matching the extensions.
func (f *S3Fetcher) ListFiles(ctx context.Context, extensions []string) ([]string, error) {
	prefix := f.config.Prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var files []string

	paginator := s3.NewListObjectsV2Paginator(f.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.config.Bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if strings.HasSuffix(key, "/") {
				continue
			}

			if len(extensions) > 0 {
				ext := filepath.Ext((key))
				for _, e := range extensions {
					if strings.EqualFold(ext, e) {
						files = append(files, strings.TrimPrefix(key, prefix))
						break
					}
				}
			} else {
				files = append(files, strings.TrimPrefix(key, prefix))
			}
		}
	}

	return files, nil
}

// computeCombinedHash creates a hash from multiple ETags.
// Uses SHA-256 for cryptographic strength and includes separators to prevent
// collision attacks where ["abc", "def"] would equal ["abcd", "ef"].
// Hashes are sorted to ensure consistent ordering regardless of S3 listing order.
func computeCombinedHash(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}

	// Sort hashes to ensure consistent ordering
	sorted := make([]string, len(hashes))
	copy(sorted, hashes)
	sort.Strings(sorted)

	var buf bytes.Buffer
	for i, h := range sorted {
		if i > 0 {
			buf.WriteByte('\n') // Separator to prevent collision attacks
		}
		buf.WriteString(h)
	}

	// Use SHA-256 instead of MD5 (cryptographically stronger)
	hash := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(hash[:])
}
