package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/easmalert"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMExposureWriter is the exposure writer of the EASM producers (the CT
// monitor, the DNS checks, takeover confirmation). It upserts like
// ExposureRepository.BulkUpsert and, in the same transaction, announces the
// rows it inserted through the notification outbox (research/22 P0-7). A
// re-sighting announces nothing; a rollback leaves neither the exposure nor
// the alert.
type EASMExposureWriter struct {
	db        *DB
	exposures *ExposureRepository
	alerts    *EASMAlerter
}

// NewEASMExposureWriter builds the writer.
func NewEASMExposureWriter(db *DB, alerts *EASMAlerter) *EASMExposureWriter {
	return &EASMExposureWriter{db: db, exposures: NewExposureRepository(db), alerts: alerts}
}

// BulkUpsert writes the events and announces the new ones.
func (w *EASMExposureWriter) BulkUpsert(ctx context.Context, events []*exposure.ExposureEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin exposure upsert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	written, err := w.exposures.BulkUpsertInTx(ctx, tx, events)
	if err != nil {
		return err
	}
	inserted := map[string][]string{}
	var tenants []string
	for _, u := range written {
		if !u.Inserted {
			continue
		}
		if _, ok := inserted[u.TenantID]; !ok {
			tenants = append(tenants, u.TenantID)
		}
		inserted[u.TenantID] = append(inserted[u.TenantID], u.ID)
	}
	for _, t := range tenants {
		tenantID, err := shared.IDFromString(t)
		if err != nil {
			return fmt.Errorf("tenant id: %w", err)
		}
		if err := w.alerts.EnqueueInTx(ctx, tx, tenantID, inserted[t], easmalert.ReasonNew); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit exposure upsert: %w", err)
	}
	return nil
}

// AnnouncingExposureRepository is the exposure repository of the recon asset
// bridge (port_open, service_detected, certificate and TLS exposures from
// scans): a Create also announces the new exposure through the notification
// outbox, in the same transaction (research/22 P0-6 with P0-7). Every other
// method is the plain repository's.
type AnnouncingExposureRepository struct {
	*ExposureRepository
	db     *DB
	alerts *EASMAlerter
}

// NewAnnouncingExposureRepository builds the repository.
func NewAnnouncingExposureRepository(db *DB, alerts *EASMAlerter) *AnnouncingExposureRepository {
	return &AnnouncingExposureRepository{ExposureRepository: NewExposureRepository(db), db: db, alerts: alerts}
}

// Create inserts the event and announces it in one transaction.
func (r *AnnouncingExposureRepository) Create(ctx context.Context, event *exposure.ExposureEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin exposure create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.CreateInTx(ctx, tx, event); err != nil {
		return err
	}
	if err := r.alerts.EnqueueInTx(ctx, tx, event.TenantID(), []string{event.ID().String()}, easmalert.ReasonNew); err != nil {
		return err
	}
	return tx.Commit()
}
