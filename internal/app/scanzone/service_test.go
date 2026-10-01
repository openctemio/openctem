package scanzone

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/api/internal/app/audit"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	zonedom "github.com/openctemio/api/pkg/domain/scanzone"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type memRepo struct {
	zonedom.Repository
	zones    map[shared.ID]*zonedom.Zone
	count    int
	coverage *zonedom.Coverage
}

func (m *memRepo) Create(_ context.Context, z *zonedom.Zone) error { m.zones[z.ID] = z; return nil }
func (m *memRepo) Update(_ context.Context, z *zonedom.Zone) error { m.zones[z.ID] = z; return nil }
func (m *memRepo) Count(context.Context, shared.ID) (int, error)   { return m.count, nil }
func (m *memRepo) Delete(_ context.Context, _, id shared.ID) error {
	delete(m.zones, id)
	return nil
}
func (m *memRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*zonedom.Zone, error) {
	z, ok := m.zones[id]
	if !ok || z.TenantID != tenantID {
		return nil, zonedom.ErrZoneNotFound
	}
	cp := *z
	return &cp, nil
}
func (m *memRepo) AssignSensor(_ context.Context, _, zoneID, sensorID shared.ID, _ *shared.ID) error {
	if !m.zones[zoneID].HasSensor(sensorID) {
		m.zones[zoneID].SensorIDs = append(m.zones[zoneID].SensorIDs, sensorID)
	}
	return nil
}
func (m *memRepo) UnassignSensor(_ context.Context, _, zoneID, sensorID shared.ID) (bool, error) {
	z := m.zones[zoneID]
	for i, s := range z.SensorIDs {
		if s == sensorID {
			z.SensorIDs = append(z.SensorIDs[:i], z.SensorIDs[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}
func (m *memRepo) Coverage(context.Context, shared.ID) (*zonedom.Coverage, error) {
	return m.coverage, nil
}

type recAudit struct{ actions []auditdom.Action }

func (r *recAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	r.actions = append(r.actions, e.Action)
	return nil
}

func TestService_EveryChangeIsAudited(t *testing.T) {
	repo := &memRepo{zones: map[shared.ID]*zonedom.Zone{}}
	audit := &recAudit{}
	svc := NewService(repo, audit, logger.NewNop())
	ctx := context.Background()
	tenant := shared.NewID()
	actx := auditapp.AuditContext{TenantID: tenant.String(), ActorID: shared.NewID().String()}

	z, err := svc.CreateZone(ctx, CreateInput{TenantID: tenant.String(), Name: "dc", Ranges: []string{"10.1.0.0/16"}}, actx)
	if err != nil {
		t.Fatal(err)
	}
	name := "dc-1"
	if _, err := svc.UpdateZone(ctx, UpdateInput{TenantID: tenant.String(), ZoneID: z.ID.String(), Name: &name}, actx); err != nil {
		t.Fatal(err)
	}
	sensor := shared.NewID()
	if _, err := svc.AssignSensor(ctx, tenant.String(), z.ID.String(), sensor.String(), actx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AssignSensor(ctx, tenant.String(), z.ID.String(), sensor.String(), actx); err != nil {
		t.Fatal(err) // idempotent, and not audited twice
	}
	if err := svc.UnassignSensor(ctx, tenant.String(), z.ID.String(), sensor.String(), actx); err != nil {
		t.Fatal(err)
	}
	if err := svc.UnassignSensor(ctx, tenant.String(), z.ID.String(), sensor.String(), actx); !errors.Is(err, zonedom.ErrSensorNotFound) {
		t.Errorf("unassigning an unassigned sensor: %v", err)
	}
	if err := svc.DeleteZone(ctx, tenant.String(), z.ID.String(), actx); err != nil {
		t.Fatal(err)
	}
	want := []auditdom.Action{
		auditdom.ActionScanZoneCreated, auditdom.ActionScanZoneUpdated,
		auditdom.ActionScanZoneSensorAssigned, auditdom.ActionScanZoneSensorUnassigned,
		auditdom.ActionScanZoneDeleted,
	}
	if len(audit.actions) != len(want) {
		t.Fatalf("audit = %v, want %v", audit.actions, want)
	}
	for i := range want {
		if audit.actions[i] != want[i] {
			t.Errorf("audit[%d] = %s, want %s", i, audit.actions[i], want[i])
		}
		if !audit.actions[i].IsValid() {
			t.Errorf("audit action %s is not a registered action", audit.actions[i])
		}
	}
}

func TestService_RejectsBadInput(t *testing.T) {
	repo := &memRepo{zones: map[shared.ID]*zonedom.Zone{}}
	svc := NewService(repo, nil, logger.NewNop())
	ctx := context.Background()
	tenant := shared.NewID().String()

	if _, err := svc.CreateZone(ctx, CreateInput{TenantID: tenant, Name: "x", Ranges: []string{"0.0.0.0/0"}}, auditapp.AuditContext{}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("0.0.0.0/0: %v", err)
	}
	repo.count = zonedom.MaxZonesPerTenant
	if _, err := svc.CreateZone(ctx, CreateInput{TenantID: tenant, Name: "x", Ranges: []string{"10.0.0.0/8"}}, auditapp.AuditContext{}); !errors.Is(err, zonedom.ErrTooManyZones) {
		t.Errorf("zone limit: %v", err)
	}
	if _, err := svc.GetZone(ctx, tenant, "not-a-uuid"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("malformed id: %v", err)
	}
	if _, err := svc.GetZone(ctx, "bad", shared.NewID().String()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad tenant: %v", err)
	}
}

func TestCoverageWarnings(t *testing.T) {
	noSensors, privNoHealthy, defNoHealthy, fine := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	cov := &zonedom.Coverage{
		OutsidePrivate: 4, OutsidePublic: 2,
		Zones: []zonedom.ZoneCoverage{
			{ZoneID: noSensors, Name: "a", HasPrivateRange: true},
			{ZoneID: privNoHealthy, Name: "b", HasPrivateRange: true, AssignedSensors: 2},
			{ZoneID: defNoHealthy, Name: "c", IsDefault: true, AssignedSensors: 1},
			{ZoneID: fine, Name: "d", HasPrivateRange: true, AssignedSensors: 1, HealthySensors: 1},
		},
	}
	got := map[string]string{}
	for _, w := range coverageWarnings(cov) {
		got[w.Code] = w.ZoneID
	}
	want := map[string]string{
		WarnNoSensors:             noSensors.String(),
		WarnPrivateWithoutHealthy: privNoHealthy.String(),
		WarnDefaultWithoutHealthy: defNoHealthy.String(),
		WarnUnzonedPrivate:        "",
		WarnPublicWithoutDefault:  "",
	}
	if len(got) != len(want) {
		t.Fatalf("warnings = %v", got)
	}
	for code, zone := range want {
		if got[code] != zone {
			t.Errorf("%s -> %q, want %q", code, got[code], zone)
		}
	}
	// A tenant without zones gets no warnings: nothing changed for it.
	if w := coverageWarnings(&zonedom.Coverage{OutsidePrivate: 9, OutsidePublic: 9}); len(w) != 0 {
		t.Errorf("tenant without zones: %v", w)
	}
}
