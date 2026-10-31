package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/easmalert"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASMExposureWriter is the exposure writer of the EASM producers (the CT
// monitor, the DNS checks, takeover confirmation). It upserts like
// ExposureRepository.BulkUpsert and, in the same transaction, announces the
// rows it inserted through the notification outbox (research/22 P0-7). A
// re-sighting announces nothing, unless the exposure was active and unseen
// for longer than the tenant's alert fingerprint lifetime
// (tenant.EASMSettings.ReappearAfterDays): that one goes out as "reappeared".
// A rollback leaves neither the exposure nor
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

	// The prior sighting is read before the upsert moves last_seen_at, and
	// the rows stay locked until commit.
	prior, err := priorSightings(ctx, tx, events)
	if err != nil {
		return err
	}
	written, err := w.exposures.BulkUpsertInTx(ctx, tx, events)
	if err != nil {
		return err
	}
	inserted := map[string][]string{}
	reappeared := map[string][]string{}
	var tenants []string
	now := w.alerts.now()
	windows := map[string]time.Duration{}
	for _, u := range written {
		if !u.Inserted {
			p, ok := prior[sightingKey{u.TenantID, u.Fingerprint}]
			if !ok || !exposure.State(p.state).IsOpen() {
				continue
			}
			win, ok := windows[u.TenantID]
			if !ok {
				tid, err := shared.IDFromString(u.TenantID)
				if err != nil {
					return fmt.Errorf("tenant id: %w", err)
				}
				if win, err = w.alerts.reappearAfter(ctx, tx, tid); err != nil {
					return err
				}
				windows[u.TenantID] = win
			}
			if now.Sub(p.lastSeen) > win {
				if _, seen := inserted[u.TenantID]; !seen && len(reappeared[u.TenantID]) == 0 {
					tenants = append(tenants, u.TenantID)
				}
				reappeared[u.TenantID] = append(reappeared[u.TenantID], u.ID)
			}
			continue
		}
		if _, ok := inserted[u.TenantID]; !ok && len(reappeared[u.TenantID]) == 0 {
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
		if err := w.alerts.EnqueueInTx(ctx, tx, tenantID, reappeared[t], easmalert.ReasonReappeared); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit exposure upsert: %w", err)
	}
	return nil
}

type sightingKey struct{ tenantID, fingerprint string }

type sighting struct {
	lastSeen time.Time
	state    string
}

// priorSightings reads, per tenant, the stored last sighting and state of
// the fingerprints the batch is about to upsert, and locks those rows. Each
// query is scoped to one tenant: a fingerprint is never looked up across
// tenants.
func priorSightings(ctx context.Context, tx *sql.Tx, events []*exposure.ExposureEvent) (map[sightingKey]sighting, error) {
	byTenant := map[string][]string{}
	for _, e := range events {
		t := e.TenantID().String()
		byTenant[t] = append(byTenant[t], e.Fingerprint())
	}
	out := map[sightingKey]sighting{}
	for t, fps := range byTenant {
		if err := readPriorSightings(ctx, tx, t, fps, out); err != nil {
			return nil, err
		}
	}
	return out, nil
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

func readPriorSightings(ctx context.Context, tx *sql.Tx, tenantID string, fingerprints []string, out map[sightingKey]sighting) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT fingerprint, last_seen_at, state FROM exposure_events
		WHERE tenant_id = $1 AND fingerprint = ANY($2) ORDER BY fingerprint FOR UPDATE`, tenantID, pq.Array(fingerprints))
	if err != nil {
		return fmt.Errorf("read prior exposure sightings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fp, state string
		var seen time.Time
		if err := rows.Scan(&fp, &seen, &state); err != nil {
			return fmt.Errorf("scan prior exposure sighting: %w", err)
		}
		out[sightingKey{tenantID, fp}] = sighting{lastSeen: seen, state: state}
	}
	return rows.Err()
}
