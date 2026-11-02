package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// APIKeyExpiryNotifier tells the holders of API keys that expire soon
// (apikey.Service.NotifyExpiring).
type APIKeyExpiryNotifier interface {
	NotifyExpiring(ctx context.Context, now time.Time, batch int) (int, error)
}

// APIKeyExpiryNoticeController sends the "your API key expires soon" notice
// once per key, a week before it expires.
type APIKeyExpiryNoticeController struct {
	service  APIKeyExpiryNotifier
	interval time.Duration
	batch    int
	logger   *logger.Logger
}

// NewAPIKeyExpiryNoticeController creates the controller.
func NewAPIKeyExpiryNoticeController(service APIKeyExpiryNotifier, interval time.Duration, batch int, log *logger.Logger) *APIKeyExpiryNoticeController {
	if interval <= 0 {
		interval = time.Hour
	}
	if batch <= 0 {
		batch = 200
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &APIKeyExpiryNoticeController{service: service, interval: interval, batch: batch, logger: log}
}

// Name returns the controller name.
func (c *APIKeyExpiryNoticeController) Name() string { return "api-key-expiry-notice" }

// Interval returns the reconciliation interval.
func (c *APIKeyExpiryNoticeController) Interval() time.Duration { return c.interval }

// Reconcile sends the notices that are due.
func (c *APIKeyExpiryNoticeController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.NotifyExpiring(ctx, time.Now().UTC(), c.batch)
	if err != nil {
		c.logger.Error("api key expiry notice sweep failed", "error", err)
		return n, err
	}
	if n > 0 {
		c.logger.Info("told holders of API keys that expire soon", "count", n)
	}
	return n, nil
}
