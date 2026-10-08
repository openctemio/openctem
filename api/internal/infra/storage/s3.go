package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// S3Storage stores files in S3-compatible object storage (AWS S3, MinIO, etc).
// Object key layout: {tenantID}/{storageKey}
type S3Storage struct {
	client *s3.Client
	bucket string
}

// NewS3Storage creates an S3 storage provider for a tenant-configured bucket.
// For MinIO: set endpoint to MinIO URL (e.g., "https://minio.corp:9000").
// For AWS S3: leave endpoint empty (uses default AWS endpoint).
//
// The tenant's keys are required and nothing is loaded from the server's
// environment (no default credential chain, profiles or AWS_ENDPOINT_URL);
// the endpoint is checked by the SSRF guard and every request is dialed
// through it.
func NewS3Storage(bucket, region, endpoint, accessKey, secretKey string) (*S3Storage, error) {
	if bucket == "" {
		return nil, fmt.Errorf("S3 bucket name is required")
	}
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("S3 storage requires the tenant's access key and secret key")
	}
	if endpoint != "" {
		if err := checkS3Endpoint(endpoint); err != nil {
			return nil, fmt.Errorf("S3 endpoint blocked: %w", err)
		}
	}
	return newS3Storage(bucket, region, endpoint, accessKey, secretKey, s3HTTPClient()), nil
}

// NewOperatorS3Storage creates the server-wide attachment storage the operator
// configured (STORAGE_PROVIDER=s3|minio, STORAGE_BUCKET, STORAGE_REGION,
// STORAGE_ENDPOINT, STORAGE_ACCESS_KEY, STORAGE_SECRET_KEY). Unlike a tenant
// bucket, the endpoint is the operator's own configuration, so it may be a
// private address (an in-cluster MinIO) and is not run through the SSRF guard.
// Static keys are required: nothing is taken from the ambient AWS environment.
func NewOperatorS3Storage(bucket, region, endpoint, accessKey, secretKey string) (*S3Storage, error) {
	if bucket == "" {
		return nil, fmt.Errorf("STORAGE_BUCKET is required for STORAGE_PROVIDER=s3/minio")
	}
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("STORAGE_ACCESS_KEY and STORAGE_SECRET_KEY are required for STORAGE_PROVIDER=s3/minio")
	}
	return newS3Storage(bucket, region, endpoint, accessKey, secretKey, nil), nil
}

// newS3Storage builds the client. httpClient nil = the SDK's default client.
func newS3Storage(bucket, region, endpoint, accessKey, secretKey string, httpClient aws.HTTPClient) *S3Storage {
	if region == "" {
		region = "us-east-1"
	}

	cfg := aws.Config{
		Region:      region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	}
	if httpClient != nil {
		cfg.HTTPClient = httpClient
	}

	clientOpts := []func(*s3.Options){}
	if endpoint != "" {
		// MinIO or custom S3-compatible endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true // MinIO requires path-style
		})
	}

	return &S3Storage{client: s3.NewFromConfig(cfg, clientOpts...), bucket: bucket}
}

func (s *S3Storage) Upload(ctx context.Context, tenantID, filename, contentType string, reader io.Reader) (string, error) {
	safe := sanitizeFilename(filename)
	key := fmt.Sprintf("%s_%s", shared.NewID().String(), safe)
	objectKey := path.Join(tenantID, key)

	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(objectKey),
		Body:        reader,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	return key, nil
}

func (s *S3Storage) Download(ctx context.Context, tenantID, storageKey string) (io.ReadCloser, string, error) {
	objectKey := path.Join(tenantID, storageKey)

	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, "", attachment.ErrNotFound
		}
		return nil, "", fmt.Errorf("S3 download failed: %w", err)
	}

	ct := ""
	if result.ContentType != nil {
		ct = *result.ContentType
	}

	return result.Body, ct, nil
}

func (s *S3Storage) Delete(ctx context.Context, tenantID, storageKey string) error {
	objectKey := path.Join(tenantID, storageKey)

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(objectKey),
	})
	// Idempotent — S3 DeleteObject doesn't error on missing keys
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}
	return nil
}

// EraseTenant deletes every object under "{tenantID}/" in the bucket, page by
// page. The prefix ends in a slash and tenant ids have a fixed length, so no
// other tenant's key can match it.
func (s *S3Storage) EraseTenant(ctx context.Context, tenantID string) (int, error) {
	if err := attachment.ValidateTenantNamespace(tenantID); err != nil {
		return 0, err
	}
	prefix := tenantID + "/"
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	n := 0
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return n, fmt.Errorf("list tenant objects: %w", err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if !strings.HasPrefix(key, prefix) {
				continue // the listing is not trusted to apply the prefix
			}
			if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(s.bucket),
				Key:    aws.String(key),
			}); err != nil {
				return n, fmt.Errorf("delete tenant object: %w", err)
			}
			n++
		}
	}
	return n, nil
}
