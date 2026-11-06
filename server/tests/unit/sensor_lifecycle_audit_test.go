package unit

// Tests for the sensor connect/disconnect lifecycle audit trail. These prove the
// events that activate the SensorAuditLog UI (which reads resource_type="sensor")
// are actually written to the shared audit_logs, and only on real transitions.

import (
	"context"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- CONNECT (heartbeat transition) --------------------------------------

func TestUpdateHeartbeat_LogsConnectOnOfflineToOnlineTransition(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())

	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.Health = sensor.SensorHealthOffline // previously offline

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{Version: "1.0.0"}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	if auditRepo.createCalls != 1 {
		t.Fatalf("expected exactly 1 connect audit event, got %d", auditRepo.createCalls)
	}
	got := auditRepo.lastCreated
	if got.Action() != auditdom.ActionSensorConnected {
		t.Errorf("action = %q, want %q", got.Action(), auditdom.ActionSensorConnected)
	}
	if got.ResourceType() != auditdom.ResourceTypeSensor {
		t.Errorf("resource_type = %q, want %q (UI reads 'sensor')", got.ResourceType(), auditdom.ResourceTypeSensor)
	}
	if got.ResourceID() != a.ID.String() {
		t.Errorf("resource_id = %q, want sensor id %q", got.ResourceID(), a.ID.String())
	}
	if got.TenantID() == nil || *got.TenantID() != tenantID {
		t.Errorf("tenant_id = %v, want %s (must use the sensor's own tenant)", got.TenantID(), tenantID)
	}
}

func TestUpdateHeartbeat_NoConnectLogOnSteadyStateHeartbeat(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())

	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.Health = sensor.SensorHealthOnline // already online — a normal recurring heartbeat

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{Version: "1.0.0"}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	if auditRepo.createCalls != 0 {
		t.Fatalf("steady-state heartbeat must not log a connect event; got %d audit writes", auditRepo.createCalls)
	}
}

func TestUpdateHeartbeat_ConnectLogsOnceThenGoesQuiet(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())

	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.Health = sensor.SensorHealthOffline

	// First heartbeat is the transition -> one connect event.
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat #1: %v", err)
	}
	// Second and third heartbeats are steady-state -> no further events.
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat #2: %v", err)
	}
	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat #3: %v", err)
	}

	if auditRepo.createCalls != 1 {
		t.Fatalf("expected exactly 1 connect event across 3 heartbeats, got %d", auditRepo.createCalls)
	}
}

func TestUpdateHeartbeat_NoConnectLogForPlatformSensor(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())

	a := repo.seedSensor(shared.NewID(), "platform-sensor", sensor.SensorTypeWorker)
	a.TenantID = nil // platform sensor — shared infra, no owning tenant
	a.Health = sensor.SensorHealthOffline

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}

	if auditRepo.createCalls != 0 {
		t.Fatalf("platform sensor (no tenant) must not produce a tenant-scoped connect event; got %d", auditRepo.createCalls)
	}
}

// --- DISCONNECT (health controller mark-offline) --------------------------

func TestSensorHealthReconcile_LogsDisconnectForNewlyOfflineSensor(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()

	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	// Silent for ten minutes: the ladder puts it past offline; GetByID then
	// resolves tenant + name.
	repo.silence(a, 10*time.Minute)

	ctrl := controller.NewSensorHealthController(repo, auditSvc, &controller.SensorHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	n, err := ctrl.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("Reconcile reported %d offline sensors, want 1", n)
	}
	if auditRepo.createCalls != 1 {
		t.Fatalf("expected exactly 1 disconnect audit event, got %d", auditRepo.createCalls)
	}
	got := auditRepo.lastCreated
	if got.Action() != auditdom.ActionSensorDisconnected {
		t.Errorf("action = %q, want %q", got.Action(), auditdom.ActionSensorDisconnected)
	}
	if got.ResourceType() != auditdom.ResourceTypeSensor {
		t.Errorf("resource_type = %q, want %q", got.ResourceType(), auditdom.ResourceTypeSensor)
	}
	if got.ResourceID() != a.ID.String() {
		t.Errorf("resource_id = %q, want %q", got.ResourceID(), a.ID.String())
	}
	if got.TenantID() == nil || *got.TenantID() != tenantID {
		t.Errorf("tenant_id = %v, want %s", got.TenantID(), tenantID)
	}
}

func TestSensorHealthReconcile_NoDisconnectWhenNothingWentOffline(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()

	ctrl := controller.NewSensorHealthController(repo, auditSvc, &controller.SensorHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if auditRepo.createCalls != 0 {
		t.Fatalf("no sensors went offline; expected 0 audit writes, got %d", auditRepo.createCalls)
	}
}

func TestSensorHealthReconcile_NoDisconnectForPlatformSensor(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()

	a := repo.seedSensor(shared.NewID(), "platform-sensor", sensor.SensorTypeWorker)
	a.TenantID = nil // platform sensor
	repo.silence(a, 10*time.Minute)

	ctrl := controller.NewSensorHealthController(repo, auditSvc, &controller.SensorHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if auditRepo.createCalls != 0 {
		t.Fatalf("platform sensor (no tenant) must not produce a tenant-scoped disconnect event; got %d", auditRepo.createCalls)
	}
}

func TestSensorHealthReconcile_NilAuditServiceIsSafe(t *testing.T) {
	repo := newSensorSvcMockRepo()
	a := repo.seedSensor(shared.NewID(), "sensor-1", sensor.SensorTypeWorker)
	repo.silence(a, 10*time.Minute)

	// nil audit service — the controller must still reconcile without panicking.
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{
		Logger: logger.NewNop(),
	})

	n, err := ctrl.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile with nil audit service: %v", err)
	}
	if n != 1 {
		t.Fatalf("Reconcile reported %d, want 1", n)
	}
}
