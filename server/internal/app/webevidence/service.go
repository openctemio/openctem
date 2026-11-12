// Package webevidence stores and serves what sensors saw when they fetched
// web assets (status, title, masked snippet, optional screenshot).
// Design: docs/rfcs/RFC-081-web-evidence-screenshots.md.
package webevidence

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/webevidence"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Repository stores captures.
type Repository interface {
	Insert(ctx context.Context, rec webevidence.Record) error
	List(ctx context.Context, tenantID, assetID shared.ID) ([]webevidence.Record, error)
	Get(ctx context.Context, tenantID, assetID shared.ID, id string) (*webevidence.Record, error)
	ExpireScreenshots(ctx context.Context, now time.Time, limit int) ([]webevidence.BlobRef, error)
	TakeOrphans(ctx context.Context, limit int) ([]webevidence.BlobRef, error)
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
}

// BlobStore is the tenant file storage (the attachments' storage: the
// operator's storage or the organization's own bucket, namespaced by tenant).
type BlobStore interface {
	StoreBlob(ctx context.Context, tenantID, filename, contentType string, data []byte) (key, provider string, err error)
	OpenBlob(ctx context.Context, tenantID, provider, key string) (io.ReadCloser, error)
	DeleteBlob(ctx context.Context, tenantID, provider, key string) error
}

// Settings reads the organization's attack-surface settings.
type Settings interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
}

// maxScreenshotsPerReport bounds the images one report may store.
const maxScreenshotsPerReport = 20

// sweepBatch bounds one retention pass per kind.
const sweepBatch = 500

// Service records and serves web evidence.
type Service struct {
	repo     Repository
	blobs    BlobStore
	settings Settings
	log      *logger.Logger
	now      func() time.Time
}

// NewService creates the service. blobs may be nil (no screenshots kept).
func NewService(repo Repository, blobs BlobStore, settings Settings, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: repo, blobs: blobs, settings: settings, log: log, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// screenshotsOn reports whether the organization keeps screenshots. An
// unreadable setting keeps none (fail closed).
func (s *Service) screenshotsOn(ctx context.Context, tenantID shared.ID) bool {
	if s.blobs == nil || s.settings == nil {
		return false
	}
	es, err := s.settings.GetEASMSettings(ctx, tenantID.String())
	if err != nil {
		s.log.Warn("web evidence: settings unreadable; screenshots dropped", "tenant_id", tenantID.String(),
			"error", logger.SanitizeError(err))
		return false
	}
	return es.WebScreenshotsEnabled
}

// RecordReport stores the captures of one report. Best effort: a capture
// that does not validate or store is skipped and counted.
func (s *Service) RecordReport(ctx context.Context, tenantID shared.ID, tool string, items []webevidence.Item) (stored, skipped int) {
	if len(items) == 0 {
		return 0, 0
	}
	now := s.now()
	keep := s.screenshotsOn(ctx, tenantID)
	shots := 0
	for _, it := range items {
		captures, bad := webevidence.FromProperty(it.Raw, tool, now, keep)
		skipped += bad
		for _, c := range captures {
			if stored >= webevidence.MaxCapturesPerReport {
				skipped++
				continue
			}
			rec := webevidence.Record{TenantID: tenantID.String(), AssetID: it.AssetID.String(), Capture: c}
			if c.Screenshot != nil && shots < maxScreenshotsPerReport {
				if err := s.storeScreenshot(ctx, &rec, now); err != nil {
					s.log.Warn("web evidence: screenshot not stored", "tenant_id", tenantID.String(),
						"error", logger.SanitizeError(err))
				} else {
					shots++
				}
			}
			if err := s.repo.Insert(ctx, rec); err != nil {
				s.log.Warn("web evidence: capture not stored", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
				if rec.ScreenshotKey != "" {
					_ = s.blobs.DeleteBlob(ctx, rec.TenantID, rec.ScreenshotProvider, rec.ScreenshotKey)
				}
				skipped++
				continue
			}
			stored++
		}
	}
	return stored, skipped
}

func (s *Service) storeScreenshot(ctx context.Context, rec *webevidence.Record, now time.Time) error {
	shot := rec.Screenshot
	key, provider, err := s.blobs.StoreBlob(ctx, rec.TenantID, "web-evidence-"+shot.SHA256[:16]+".png",
		webevidence.ScreenshotMediaType, shot.Data)
	if err != nil {
		return err
	}
	exp := now.Add(webevidence.ScreenshotRetention)
	rec.ScreenshotKey, rec.ScreenshotProvider, rec.ScreenshotSHA256 = key, provider, shot.SHA256
	rec.ScreenshotSize, rec.ScreenshotWidth, rec.ScreenshotHeight = len(shot.Data), shot.Width, shot.Height
	rec.ScreenshotExpiresAt = &exp
	return nil
}

// List returns the asset's captures. The caller has checked the asset is in
// the caller's data scope.
func (s *Service) List(ctx context.Context, tenantID, assetID shared.ID) ([]webevidence.Record, error) {
	return s.repo.List(ctx, tenantID, assetID)
}

// Screenshot opens the screenshot of one capture of the asset.
// shared.ErrNotFound when there is none.
func (s *Service) Screenshot(ctx context.Context, tenantID, assetID shared.ID, id string) (io.ReadCloser, *webevidence.Record, error) {
	rec, err := s.repo.Get(ctx, tenantID, assetID, id)
	if err != nil {
		return nil, nil, err
	}
	if !rec.HasScreenshot() || s.blobs == nil {
		return nil, nil, shared.ErrNotFound
	}
	rc, err := s.blobs.OpenBlob(ctx, tenantID.String(), rec.ScreenshotProvider, rec.ScreenshotKey)
	if err != nil {
		return nil, nil, fmt.Errorf("open screenshot: %w", err)
	}
	// Serve only bytes that still match what was stored.
	data, err := io.ReadAll(io.LimitReader(rc, int64(rec.ScreenshotSize)+1))
	_ = rc.Close()
	if err != nil || len(data) != rec.ScreenshotSize {
		return nil, nil, fmt.Errorf("screenshot size mismatch")
	}
	return io.NopCloser(bytes.NewReader(data)), rec, nil
}

// Sweep deletes expired screenshots (decision O7: 30 days), files of rows
// that went away, and capture text past a year. Returns files deleted.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	deleted := 0
	expired, err := s.repo.ExpireScreenshots(ctx, now, sweepBatch)
	if err != nil {
		return 0, err
	}
	orphans, err := s.repo.TakeOrphans(ctx, sweepBatch)
	if err != nil {
		return 0, err
	}
	if s.blobs != nil {
		for _, b := range append(expired, orphans...) {
			if err := s.blobs.DeleteBlob(ctx, b.TenantID, b.Provider, b.Key); err != nil {
				s.log.Warn("web evidence: screenshot file not deleted", "tenant_id", b.TenantID, "error", logger.SanitizeError(err))
				continue
			}
			deleted++
		}
	}
	if _, err := s.repo.DeleteOlderThan(ctx, now.Add(-webevidence.Retention)); err != nil {
		return deleted, err
	}
	return deleted, nil
}
