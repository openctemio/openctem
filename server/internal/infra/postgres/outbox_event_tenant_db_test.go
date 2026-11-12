package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/outbox"
)

// A delivery is read only inside its tenant: another tenant asking for the
// same id gets not found, the answer a missing id gets.
func TestOutboxEventRepository_GetByTenantAndID(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewOutboxEventRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)

	entry := outbox.NewOutbox(outbox.OutboxParams{TenantID: tenantA, EventType: "new_finding", Title: "t", Severity: outbox.SeverityHigh})
	entry.MarkCompleted()
	ev := outbox.NewEventFromOutbox(entry, outbox.ProcessingResults{SendResults: []outbox.SendResult{{IntegrationID: "i", Status: "success", SentAt: time.Now(), Attempts: 2}}})
	if err := repo.Create(ctx, ev); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM notification_events WHERE id = $1`, ev.ID().String()) })

	got, err := repo.GetByTenantAndID(ctx, tenantA, ev.ID())
	if err != nil {
		t.Fatalf("own tenant: %v", err)
	}
	if rs := got.SendResults(); len(rs) != 1 || rs[0].Attempts != 2 {
		t.Fatalf("send results %+v", rs)
	}
	if _, err := repo.GetByTenantAndID(ctx, tenantB, ev.ID()); !errors.Is(err, outbox.ErrEventNotFound) {
		t.Fatalf("other tenant: want ErrEventNotFound, got %v", err)
	}
}
