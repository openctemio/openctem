package controller

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// ReportBytesMover moves files still held in database rows to the file
// storage (pentest report templates, stored reports).
type ReportBytesMover interface {
	MoveContentToStore(ctx context.Context, limit int) (int, error)
}

// reportMoveBatch is how many rows one mover handles per tick (a stored
// report may be 50 MiB, held in memory while it is copied).
const reportMoveBatch = 10

// ReportFileMigrationController copies report templates and stored reports
// from Postgres to the organization's file storage
// (api/docs/architecture/file-storage.md). Once every row is moved each run
// is two empty queries.
type ReportFileMigrationController struct {
	movers   []ReportBytesMover
	interval time.Duration
	logger   *logger.Logger
}

// NewReportFileMigrationController builds the controller (interval 0 = 1 min).
func NewReportFileMigrationController(movers []ReportBytesMover, interval time.Duration, log *logger.Logger) *ReportFileMigrationController {
	if interval <= 0 {
		interval = time.Minute
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &ReportFileMigrationController{movers: movers, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *ReportFileMigrationController) Name() string { return "report-file-migration" }

// Interval returns the reconciliation interval.
func (c *ReportFileMigrationController) Interval() time.Duration { return c.interval }

// Exclusive: one replica copies at a time.
func (c *ReportFileMigrationController) Exclusive() bool { return true }

// ReconcileTimeout covers one batch of copies.
func (c *ReportFileMigrationController) ReconcileTimeout() time.Duration { return 10 * time.Minute }

// Reconcile moves one batch per kind.
func (c *ReportFileMigrationController) Reconcile(ctx context.Context) (int, error) {
	total := 0
	var errs []error
	for _, m := range c.movers {
		n, err := m.MoveContentToStore(ctx, reportMoveBatch)
		total += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	if total > 0 {
		c.logger.Info("report files moved to the file storage", "count", total)
	}
	if err := errors.Join(errs...); err != nil {
		c.logger.Error("report file migration: some files were not moved", "error", logger.SanitizeError(err))
		return total, err
	}
	return total, nil
}
