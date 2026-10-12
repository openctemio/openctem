package unit

// Sensor-surface hardening tests for the sensor service:
//   - a heartbeat racing an admin revoke / key regeneration cannot undo it
//   - admin key regeneration also revokes self-renewed key rows
//   - sensor self-renewal is audited

import (
	"context"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// copyingSensorRepo wraps the in-memory mock so GetByID returns a private copy
// (as the real postgres repo does) and lets a test inject an "admin action"
// between the service's read and its write.
type copyingSensorRepo struct {
	*sensorSvcMockRepo
	beforeWrite func()
}

func (r *copyingSensorRepo) GetByID(ctx context.Context, id shared.ID) (*sensor.Sensor, error) {
	a, err := r.sensorSvcMockRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	cp := *a
	return &cp, nil
}

func (r *copyingSensorRepo) UpdateHeartbeat(ctx context.Context, id shared.ID, hb sensor.HeartbeatUpdate) (bool, error) {
	if r.beforeWrite != nil {
		r.beforeWrite()
	}
	return r.sensorSvcMockRepo.UpdateHeartbeat(ctx, id, hb)
}

// A full-row Update would (and, before the fix, did) write back the status and
// key read at the start of the heartbeat. Also wire Update to the hook so the
// test would catch a regression back to the full-row write.
func (r *copyingSensorRepo) Update(ctx context.Context, a *sensor.Sensor) error {
	if r.beforeWrite != nil {
		r.beforeWrite()
	}
	cp := *a
	return r.sensorSvcMockRepo.Update(ctx, &cp)
}

func TestUpdateHeartbeat_ConcurrentRevokeStaysRevoked(t *testing.T) {
	base := newSensorSvcMockRepo()
	tenantID := shared.NewID()
	a := base.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.SetAPIKey("old-hash", "rda_old0")

	repo := &copyingSensorRepo{sensorSvcMockRepo: base}
	// Admin revokes the sensor and rotates its key AFTER the heartbeat read.
	repo.beforeWrite = func() {
		base.mu.Lock()
		defer base.mu.Unlock()
		stored := base.sensors[a.ID.String()]
		stored.Revoke("compromised")
		stored.SetAPIKey("admin-new-hash", "rda_new0")
	}
	svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Version: "9.9.9", CPUPercent: 10,
	}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	stored := base.sensors[a.ID.String()]
	if stored.Status != sensor.SensorStatusRevoked {
		t.Fatalf("heartbeat undid the admin revoke: status=%q", stored.Status)
	}
	if stored.APIKeyHash != "admin-new-hash" {
		t.Fatalf("heartbeat overwrote the admin-rotated key hash: %q", stored.APIKeyHash)
	}
	if stored.Version == "9.9.9" {
		t.Error("heartbeat metrics must not be written to a revoked sensor")
	}
	if base.updateCalls != 0 {
		t.Errorf("heartbeat must not use the full-row Update, got %d calls", base.updateCalls)
	}
}

func TestUpdateHeartbeat_ActiveSensorUpdatesOnlyLivenessColumns(t *testing.T) {
	base := newSensorSvcMockRepo()
	tenantID := shared.NewID()
	a := base.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.SetAPIKey("keep-hash", "rda_keep")
	a.Health = sensor.SensorHealthOffline

	repo := &copyingSensorRepo{sensorSvcMockRepo: base}
	svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Version: "1.2.3", Hostname: "h1", CPUPercent: 50, MemoryPercent: 20,
	}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	stored := base.sensors[a.ID.String()]
	if stored.Version != "1.2.3" || stored.Hostname != "h1" || stored.CPUPercent != 50 {
		t.Errorf("heartbeat fields not persisted: %+v", stored)
	}
	if stored.Health != sensor.SensorHealthOnline || stored.LastSeenAt == nil {
		t.Error("expected sensor online with last_seen set")
	}
	if stored.LoadScore == 0 {
		t.Error("expected load score recomputed from metrics")
	}
	if stored.APIKeyHash != "keep-hash" || stored.Status != sensor.SensorStatusActive {
		t.Error("heartbeat must not touch key/status")
	}
	if base.updateHeartbeatCalls != 1 || base.updateCalls != 0 {
		t.Errorf("expected exactly one targeted heartbeat write, got heartbeat=%d full=%d",
			base.updateHeartbeatCalls, base.updateCalls)
	}
}

// A revoked sensor's heartbeat (e.g. the request authenticated just before the
// revoke) records no connect event.
func TestUpdateHeartbeat_RevokedSensorNoConnectAudit(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())
	a := repo.seedSensor(shared.NewID(), "sensor-1", sensor.SensorTypeWorker)
	a.Health = sensor.SensorHealthOffline
	a.Revoke("gone")

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	if auditRepo.createCalls != 0 {
		t.Errorf("expected no connect audit for a revoked sensor, got %d", auditRepo.createCalls)
	}
}

// Renewal must not revive a sensor revoked between its status re-read and the
// key write (the targeted UPDATE is status-guarded).
func TestRenewAPIKey_RevokedDuringRenewIsRejected(t *testing.T) {
	base := newSensorSvcMockRepo()
	a := base.seedSensor(shared.NewID(), "sensor-1", sensor.SensorTypeWorker)
	a.SetAPIKey("old-hash", "rda_old0")

	repo := &revokeOnKeyWriteRepo{sensorSvcMockRepo: base}
	svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())

	if _, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a}); err == nil {
		t.Fatal("expected renewal to fail for a sensor revoked mid-renewal")
	}
	stored := base.sensors[a.ID.String()]
	if stored.Status != sensor.SensorStatusRevoked {
		t.Fatalf("renewal revived a revoked sensor: %q", stored.Status)
	}
	if stored.APIKeyHash != "old-hash" {
		t.Fatal("renewal installed a fresh key on a revoked sensor")
	}
}

type revokeOnKeyWriteRepo struct{ *sensorSvcMockRepo }

func (r *revokeOnKeyWriteRepo) GetByID(ctx context.Context, id shared.ID) (*sensor.Sensor, error) {
	a, err := r.sensorSvcMockRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	cp := *a
	return &cp, nil
}

func (r *revokeOnKeyWriteRepo) UpdateAPIKey(ctx context.Context, id shared.ID, hash, prefix string, exp *time.Time, requireActive bool) (bool, error) {
	r.mu.Lock()
	r.sensors[id.String()].Revoke("admin")
	r.mu.Unlock()
	return r.sensorSvcMockRepo.UpdateAPIKey(ctx, id, hash, prefix, exp, requireActive)
}

// Admin regeneration revokes every self-renewed key row, so a renewed copy of a
// leaked credential stops working.
func TestRegenerateAPIKey_RevokesRenewedKeyRows(t *testing.T) {
	repo := newSensorSvcMockRepo()
	keyRepo := newMockSensorAPIKeyRepo(repo)
	svc := newSensorSvcTestService(repo)
	svc.SetKeyTTL(time.Hour)
	svc.SetAPIKeyRepository(keyRepo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(), Name: "regen-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	renewed, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: out.Sensor})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if _, err := svc.AuthenticateByAPIKey(context.Background(), renewed); err != nil {
		t.Fatalf("renewed key should authenticate before regeneration: %v", err)
	}

	regenerated, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), out.Sensor.ID.String(), nil)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	if _, err := svc.AuthenticateByAPIKey(context.Background(), renewed); err == nil {
		t.Fatal("renewed key row survived admin regeneration")
	}
	if n, _ := keyRepo.CountActiveBySensorID(context.Background(), out.Sensor.ID); n != 0 {
		t.Errorf("expected 0 active key rows after regeneration, got %d", n)
	}
	if _, err := svc.AuthenticateByAPIKey(context.Background(), regenerated); err != nil {
		t.Errorf("regenerated key must authenticate: %v", err)
	}
	if repo.updateCalls != 0 {
		t.Errorf("regeneration must use the targeted key write, got %d full-row updates", repo.updateCalls)
	}
}

func TestRenewAPIKey_WritesAuditEvent(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())
	a := repo.seedSensor(shared.NewID(), "sensor-1", sensor.SensorTypeWorker)

	if _, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a}); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if auditRepo.createCalls != 1 {
		t.Fatalf("expected 1 audit event for renewal, got %d", auditRepo.createCalls)
	}
	if got := auditRepo.lastCreated.Action(); got != auditdom.ActionSensorKeyRenewed {
		t.Errorf("action = %q, want %q", got, auditdom.ActionSensorKeyRenewed)
	}
}
