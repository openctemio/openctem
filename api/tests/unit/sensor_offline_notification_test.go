package unit

// Tests for the sensor.offline notification and the heartbeat client IP.
//
// sensor.offline was a subscribable event type (event_types catalog, migrated
// subscriptions in 000230) that nothing ever emitted: the health controller
// only wrote the sensor.disconnected audit row. And the sensor.connected audit
// message read "connected from " because heartbeats never stored the caller's
// address.

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingEnqueuer struct {
	mu    sync.Mutex
	calls []outbox.EnqueueParams
}

func (r *recordingEnqueuer) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, p)
	return nil
}

func TestSensorHealthReconcile_EnqueuesSensorOfflineNotification(t *testing.T) {
	repo := newSensorSvcMockRepo()
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "edge-scanner", sensor.SensorTypeWorker)
	repo.silence(a, 10*time.Minute)

	notifier := &recordingEnqueuer{}
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	ctrl.SetNotifier(notifier)

	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(notifier.calls) != 1 {
		t.Fatalf("expected 1 sensor.offline notification, got %d", len(notifier.calls))
	}
	got := notifier.calls[0]
	if got.EventType != "sensor.offline" {
		t.Errorf("event_type = %q, want sensor.offline (the id subscriptions store)", got.EventType)
	}
	if got.TenantID != tenantID {
		t.Errorf("tenant = %s, want the sensor's tenant %s", got.TenantID, tenantID)
	}
	if got.AggregateType != "sensor" || got.AggregateID == nil || got.AggregateID.String() != a.ID.String() {
		t.Errorf("aggregate = %s/%v, want sensor/%s", got.AggregateType, got.AggregateID, a.ID)
	}
	if !strings.Contains(got.Title, "edge-scanner") {
		t.Errorf("title %q should name the sensor", got.Title)
	}
	if got.Severity != "high" {
		t.Errorf("severity = %q, want high (clears the default critical+high filter)", got.Severity)
	}
}

// The controller only gets ids for sensors whose health WAS online, so a sensor
// that stays offline produces nothing on later ticks.
func TestSensorHealthReconcile_NoRepeatNotificationWhileStillOffline(t *testing.T) {
	repo := newSensorSvcMockRepo()
	a := repo.seedSensor(shared.NewID(), "edge-scanner", sensor.SensorTypeWorker)
	repo.silence(a, 10*time.Minute)

	notifier := &recordingEnqueuer{}
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	ctrl.SetNotifier(notifier)

	_, _ = ctrl.Reconcile(context.Background())
	_, _ = ctrl.Reconcile(context.Background())
	_, _ = ctrl.Reconcile(context.Background())

	if len(notifier.calls) != 1 {
		t.Fatalf("expected exactly 1 notification across 3 ticks, got %d", len(notifier.calls))
	}
}

func TestSensorHealthReconcile_NoNotificationForPlatformSensor(t *testing.T) {
	repo := newSensorSvcMockRepo()
	a := repo.seedSensor(shared.NewID(), "platform", sensor.SensorTypeWorker)
	a.TenantID = nil
	repo.silence(a, 10*time.Minute)

	notifier := &recordingEnqueuer{}
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	ctrl.SetNotifier(notifier)

	_, _ = ctrl.Reconcile(context.Background())
	if len(notifier.calls) != 0 {
		t.Fatalf("platform sensor has no tenant to notify; got %d notifications", len(notifier.calls))
	}
}

// The catalog clients render (GET /me/event-types) is AllEventTypes(); a type
// missing there cannot be switched on in the UI.
func TestSensorOfflineIsInTheEventTypeCatalog(t *testing.T) {
	for _, info := range integrationdom.AllEventTypes() {
		if info.Type == integrationdom.EventTypeSensorOffline {
			if info.RequiredModule != integrationdom.ModuleSensors {
				t.Errorf("sensor.offline requires module %q, want %q", info.RequiredModule, integrationdom.ModuleSensors)
			}
			return
		}
	}
	t.Fatal("sensor.offline is not registered in AllEventTypes()")
}

func TestUpdateHeartbeat_StoresClientIPAndUsesItInConnectAudit(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())

	a := repo.seedSensor(shared.NewID(), "sensor-1", sensor.SensorTypeWorker)
	a.Health = sensor.SensorHealthOffline

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{IPAddress: "203.0.113.7"}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	if !a.IPAddress.Equal(net.ParseIP("203.0.113.7")) {
		t.Errorf("stored ip = %v, want 203.0.113.7", a.IPAddress)
	}
	if auditRepo.createCalls != 1 {
		t.Fatalf("expected 1 connect audit event, got %d", auditRepo.createCalls)
	}
	if msg := auditRepo.lastCreated.Message(); !strings.HasSuffix(msg, "connected from 203.0.113.7") {
		t.Errorf("connect message = %q, want it to end with the client IP", msg)
	}
}

// An unparseable address (e.g. a garbage forwarded header) must not wipe the
// stored IP, and the audit message must not end with an empty "from ".
func TestUpdateHeartbeat_InvalidIPKeepsStoredAddress(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())

	a := repo.seedSensor(shared.NewID(), "sensor-1", sensor.SensorTypeWorker)
	a.Health = sensor.SensorHealthOffline
	a.IPAddress = net.ParseIP("198.51.100.4")

	if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{IPAddress: "not-an-ip"}); err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	if !a.IPAddress.Equal(net.ParseIP("198.51.100.4")) {
		t.Errorf("stored ip = %v, want the previous 198.51.100.4", a.IPAddress)
	}
	if msg := auditRepo.lastCreated.Message(); strings.HasSuffix(msg, "from ") {
		t.Errorf("connect message %q ends with an empty address", msg)
	}
}
