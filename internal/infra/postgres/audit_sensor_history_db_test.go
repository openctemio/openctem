package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/pagination"
)

// Audit rows written before the agent → sensor rename keep action "agent.*"
// and resource type "agent" (the log is hash-chained). A query for the sensor
// family must still return them next to the new "sensor.*" rows.
func TestAuditRepository_SensorFamilyIncludesHistoricalRows(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)
	resourceID := tenantID.String() // any stable id unique to this test

	for _, row := range []struct{ action, resourceType string }{
		{"agent.created", "agent"},   // written before the upgrade
		{"sensor.created", "sensor"}, // written after
		{"finding.created", "finding"},
	} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, message)
			 VALUES ($1, $2, $3, $4, 'test')`,
			tenantID.String(), row.action, row.resourceType, resourceID); err != nil {
			t.Fatalf("seed audit row: %v", err)
		}
	}

	repo := NewAuditRepository(&DB{DB: db})
	page := pagination.New(1, 50)

	byAction, err := repo.List(ctx, audit.NewFilter().WithTenantID(tenantID).WithActions(audit.ActionSensorCreated), page)
	if err != nil {
		t.Fatal(err)
	}
	if byAction.Total != 2 {
		t.Errorf("action filter sensor.created matched %d rows, want 2 (historical agent.created + sensor.created)", byAction.Total)
	}

	byType, err := repo.List(ctx, audit.NewFilter().WithTenantID(tenantID).WithResourceTypes(audit.ResourceTypeSensor), page)
	if err != nil {
		t.Fatal(err)
	}
	if byType.Total != 2 {
		t.Errorf("resource type filter sensor matched %d rows, want 2", byType.Total)
	}

	n, err := repo.CountByAction(ctx, &tenantID, audit.ActionSensorCreated, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("CountByAction(sensor.created) = %d, want 2", n)
	}

	latest, err := repo.GetLatestByResource(ctx, tenantID, audit.ResourceTypeSensor, resourceID)
	if err != nil || latest == nil {
		t.Fatalf("GetLatestByResource: %v, %v", latest, err)
	}
}
