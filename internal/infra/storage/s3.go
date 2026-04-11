package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/domain/shared"
)

// S3Storage stores files in S3-compatible object storage (AWS S3, MinIO, etc).
// Object key layout: {tenantID}/{storageKey}
type S3Storage struct {
	client *s3.Client
	bucket string
}

// NewS3Storage creates an S3 storage provider.
// For MinIO: set endpoint to MinIO URL (e.g., "http://minio:9000").
// For AWS S3: leave endpoint empty (uses default AWS endpoint).
func NewS3Storage(bucket, region, endpoint, accessKey, secretKey string) (*S3Storage, error) {
	if bucket == "" {
		return nil, fmt.Errorf("S3 bucket name is required")
	}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load S3 config: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if endpoint != "" {
		// MinIO or custom S3-compatible endpoint
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true // MinIO requires path-style
		})
	}

	client := s3.NewFromConfig(cfg, clientOpts...)

	return &S3Storage{client: client, bucket: bucket}, nil
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
