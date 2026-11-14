package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A notification dated ahead of the database clock must not stay unread after
// "mark all read": the watermark covers it, and a writer's future time is
// clamped to the database clock on insert and on a coalescing update.
// Requires DATABASE_URL.
func TestNotification_FutureDatedClearedByReadAll(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	repo := NewNotificationRepository(db)

	tenant := seedTestTenant(ctx, t, sqlDB)
	user := seedUser(ctx, t, db)

	// A row already stored 3.5 hours ahead (written before the clamp existed).
	rowID := shared.NewID()
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO notifications (id, tenant_id, audience, audience_id, notification_type, title, severity, created_at)
		VALUES ($1, $2, 'user', $3, 'coverage_gap', 'future', 'medium', NOW() + INTERVAL '3 hours 30 minutes')`,
		rowID.String(), tenant.String(), user.String()); err != nil {
		t.Fatal(err)
	}
	n, err := repo.UnreadCount(ctx, tenant, user, nil)
	if err != nil || n != 1 {
		t.Fatalf("unread before = %d, %v; want 1", n, err)
	}
	if err := repo.MarkAllAsRead(ctx, tenant, user); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.UnreadCount(ctx, tenant, user, nil); err != nil || n != 0 {
		t.Fatalf("unread after read-all = %d, %v; want 0", n, err)
	}

	// A caller-supplied future time is stored as the database's now.
	uid := user
	future := notification.Reconstitute(shared.NewID(), tenant, notification.AudienceUser, &uid,
		notification.TypeCoverageGap, "later", "", "medium", "", nil, "", nil, time.Now().Add(4*time.Hour), false)
	if err := repo.Create(ctx, future); err != nil {
		t.Fatal(err)
	}
	var ahead bool
	if err := sqlDB.QueryRowContext(ctx, `SELECT created_at > NOW() + INTERVAL '1 minute' FROM notifications WHERE id = $1`, future.ID().String()).Scan(&ahead); err != nil || ahead {
		t.Fatalf("a future created_at was stored: ahead=%v err=%v", ahead, err)
	}
}
