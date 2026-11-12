package unit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// switchableResolver answers the storage setting a test sets, and counts reads.
type switchableResolver struct {
	mu    sync.Mutex
	cfg   *attachment.StorageConfig
	err   error
	reads int
}

func (r *switchableResolver) GetTenantStorageConfig(context.Context, string) (*attachment.StorageConfig, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	return r.cfg, r.err
}

func (r *switchableResolver) set(cfg *attachment.StorageConfig, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg, r.err = cfg, err
}

func evidenceUpload(tenantID string, body []byte) integration.UploadInput {
	return integration.UploadInput{
		TenantID: tenantID, Filename: "notes.txt", ContentType: "text/plain",
		Size: int64(len(body)), Reader: bytes.NewReader(body), UploadedBy: shared.NewID().String(),
	}
}

// The size limit holds on the bytes read, whatever the client declared, and
// nothing is left in the storage.
func TestAttPolicy_SizeCountedOnBytesNotClaim(t *testing.T) {
	svc, repo, st := newAttSvc()
	in := evidenceUpload(attTID, make([]byte, attachment.MaxFileSize+1))
	in.Size = 10 // a lie
	_, err := svc.Upload(context.Background(), in)
	require.ErrorIs(t, err, attachment.ErrTooLarge)
	assert.Empty(t, repo.store)
	assert.Empty(t, st.files, "the oversized upload must not stay in the storage")
}

func TestAttPolicy_RecordsBytesRead(t *testing.T) {
	svc, _, _ := newAttSvc()
	in := evidenceUpload(attTID, []byte("twelve bytes"))
	in.Size = 99999
	att, err := svc.Upload(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, int64(12), att.Size())
}

// A duplicate in the same context returns the existing attachment and does
// not leave a second copy in the storage.
func TestAttPolicy_DedupDeletesTheSecondCopy(t *testing.T) {
	svc, _, st := newAttSvc()
	a1, err := svc.Upload(context.Background(), mkUpload())
	require.NoError(t, err)
	a2, err := svc.Upload(context.Background(), mkUpload())
	require.NoError(t, err)
	assert.Equal(t, a1.ID(), a2.ID())
	assert.Len(t, st.files, 1)
}

// The quota counts one organization's bytes only: tenant A at its quota is
// refused, tenant B still uploads.
func TestAttPolicy_QuotaPerTenant(t *testing.T) {
	svc, _, st := newAttSvc()
	svc.SetTenantQuota(20)
	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()

	_, err := svc.Upload(context.Background(), evidenceUpload(tenantA, []byte("0123456789abcdef"))) // 16 B
	require.NoError(t, err)

	// Declared size over the quota: refused before any byte is stored.
	_, err = svc.Upload(context.Background(), evidenceUpload(tenantA, []byte("0123456789")))
	require.ErrorIs(t, err, attachment.ErrQuotaExceeded)

	// Declared small, actually over: refused after the write, and removed.
	lie := evidenceUpload(tenantA, []byte("0123456789"))
	lie.Size = 1
	_, err = svc.Upload(context.Background(), lie)
	require.ErrorIs(t, err, attachment.ErrQuotaExceeded)
	assert.Len(t, st.files, 1, "the refused file must not stay in the storage")

	_, err = svc.Upload(context.Background(), evidenceUpload(tenantB, []byte("0123456789abcdef")))
	require.NoError(t, err, "another organization's usage must not count")
}

func TestAttPolicy_NoQuotaWhenZero(t *testing.T) {
	svc, _, _ := newAttSvc()
	svc.SetTenantQuota(0)
	_, err := svc.Upload(context.Background(), evidenceUpload(attTID, make([]byte, 1<<20)))
	require.NoError(t, err)
}

// A tenant that chose its own bucket never has its files written to the
// server-wide storage when that bucket cannot be used.
func TestAttPolicy_OwnBucketFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *attachment.StorageConfig
		readErr error
		factory error
	}{
		{name: "bucket cannot be built", cfg: &attachment.StorageConfig{Provider: attachment.ProviderS3, Bucket: "b"}, factory: errors.New("endpoint blocked")},
		{name: "setting unreadable", readErr: errors.New("decrypt storage secret key")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, operator := newAttSvc()
			svc.SetTenantStorageResolver(stubStorageResolver{cfg: tc.cfg, err: tc.readErr},
				func(attachment.StorageConfig) (attachment.FileStorage, error) { return nil, tc.factory })
			_, err := svc.Upload(context.Background(), mkUpload())
			require.ErrorIs(t, err, attachment.ErrStorageUnavailable)
			assert.Empty(t, operator.files, "nothing may fall back to the server-wide storage")
			assert.Empty(t, repo.store)

			_, _, err = svc.StoreBlob(context.Background(), attTID, "s.png", "image/png", []byte("x"))
			require.ErrorIs(t, err, attachment.ErrStorageUnavailable)
			assert.Empty(t, operator.files)
		})
	}
}

// A file in the tenant's own bucket is read from that bucket or not at all,
// never looked up in the server-wide storage once the setting is gone.
func TestAttPolicy_FileInRemovedBucketIsUnavailable(t *testing.T) {
	svc, _, operator := newAttSvc()
	own := newMockAttStorage()
	res := &switchableResolver{cfg: &attachment.StorageConfig{Provider: attachment.ProviderS3, Bucket: "b"}}
	svc.SetTenantStorageResolver(res, func(attachment.StorageConfig) (attachment.FileStorage, error) { return own, nil })

	att, err := svc.Upload(context.Background(), mkUpload())
	require.NoError(t, err)
	assert.Equal(t, attachment.ProviderS3, att.StorageProvider())
	assert.Len(t, own.files, 1)
	assert.Empty(t, operator.files)

	res.set(nil, nil) // the organization went back to the server storage
	svc.InvalidateTenantStorage(attTID)
	_, _, _, err = svc.Download(context.Background(), attTID, att.ID().String())
	require.ErrorIs(t, err, attachment.ErrStorageUnavailable)
	require.ErrorIs(t, svc.Delete(context.Background(), attTID, att.ID().String()), attachment.ErrStorageUnavailable)
}

// Changing the storage setting applies to the next upload once the cache of
// that tenant is invalidated (the settings handler does it on save).
func TestAttPolicy_InvalidateAppliesNewSetting(t *testing.T) {
	svc, _, operator := newAttSvc()
	own := newMockAttStorage()
	res := &switchableResolver{}
	svc.SetTenantStorageResolver(res, func(attachment.StorageConfig) (attachment.FileStorage, error) { return own, nil })

	res.set(&attachment.StorageConfig{Provider: attachment.ProviderS3, Bucket: "b"}, nil)
	_, err := svc.Upload(context.Background(), evidenceUpload(attTID, []byte("one")))
	require.NoError(t, err)
	assert.Len(t, own.files, 1)

	res.set(nil, nil)
	svc.InvalidateTenantStorage(attTID)
	_, err = svc.Upload(context.Background(), evidenceUpload(attTID, []byte("two")))
	require.NoError(t, err)
	assert.Len(t, operator.files, 1, "the new setting (server storage) must apply at once")
	assert.Len(t, own.files, 1)
}

// The service streams the upload: the storage receives a reader it can
// read once, never the whole file buffered by the service.
func TestAttPolicy_StreamsToStorage(t *testing.T) {
	svc, _, st := newAttSvc()
	body := strings.Repeat("x", 3<<20)
	in := evidenceUpload(attTID, nil)
	in.Reader = io.MultiReader(strings.NewReader(body))
	in.Size = int64(len(body))
	att, err := svc.Upload(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, int64(len(body)), att.Size())
	assert.Equal(t, body, st.files[att.StorageKey()])
}

func TestDetectContentType(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	html := []byte("<!DOCTYPE html><html><script>alert(1)</script></html>")
	cases := []struct {
		name, file string
		head       []byte
		want       string
	}{
		{"png bytes", "a.png", png, "image/png"},
		{"png bytes named pdf", "a.pdf", png, "image/png"},
		{"pdf", "letter.pdf", []byte("%PDF-1.7\n%\xe2\xe3\xcf\xd3"), "application/pdf"},
		{"html declared as an image", "a.png", html, "text/html"},
		{"html named markdown is still html", "a.md", html, "text/html"},
		{"markdown text", "notes.md", []byte("# Title\n\nbody"), "text/markdown"},
		{"har json", "trace.har", []byte(`{"log":{"version":"1.2"}}`), "application/har+json"},
		{"plain text", "a.txt", []byte("hello"), "text/plain"},
		// Served as text/plain with nosniff: never rendered as an image.
		{"svg is never an image", "a.png", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>`), "text/plain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := attachment.DetectContentType(tc.head, tc.file)
			assert.Equal(t, tc.want, got)
		})
	}
	assert.False(t, attachment.AllowedContentTypes[attachment.DetectContentType(html, "x.png")])
}
