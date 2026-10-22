package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// SAMLCertExpirySweeper alerts owners about expiring SAML IdP certificates.
type SAMLCertExpirySweeper interface {
	SweepCertificateExpiry(ctx context.Context, now time.Time) (int, error)
}

// SAMLCertExpiryController runs the SAML IdP certificate expiry sweep.
type SAMLCertExpiryController struct {
	sweeper  SAMLCertExpirySweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewSAMLCertExpiryController creates the controller (default interval 6h).
func NewSAMLCertExpiryController(s SAMLCertExpirySweeper, interval time.Duration, log *logger.Logger) *SAMLCertExpiryController {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &SAMLCertExpiryController{sweeper: s, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *SAMLCertExpiryController) Name() string { return "saml-cert-expiry" }

// Interval returns the reconciliation interval.
func (c *SAMLCertExpiryController) Interval() time.Duration { return c.interval }

// Reconcile alerts owners whose IdP certificate reached a new notice level.
func (c *SAMLCertExpiryController) Reconcile(ctx context.Context) (int, error) {
	if c.sweeper == nil {
		return 0, nil
	}
	n, err := c.sweeper.SweepCertificateExpiry(ctx, time.Now().UTC())
	if err != nil {
		c.logger.Error("saml certificate expiry sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("saml certificate expiry alerts sent", "organizations", n)
	}
	return n, nil
}
