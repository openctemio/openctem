-- Track which storage provider holds each file.
-- When tenant switches providers (local→S3), old files stay accessible
-- because Download reads the attachment's provider, not tenant's current config.
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS storage_provider VARCHAR(20) NOT NULL DEFAULT 'local';

COMMENT ON COLUMN attachments.storage_provider IS 'Storage backend that holds this file (local, s3, minio, gcs)';
