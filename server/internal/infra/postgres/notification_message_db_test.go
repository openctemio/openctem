package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// A notice's message code and values are stored and read back with it; a
// coalesced notice takes the newer message; a notice without one reads back
// with none; and another organization's user never reads the row.
// Requires DATABASE_URL.
func TestNotification_MessageRoundTrip(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	repo := NewNotificationRepository(db)

	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	user := seedUser(ctx, t, db)
	uid := user
	asset := shared.NewID()

	msg := notification.Msg("coverage.readiness", "capability", "capture.screenshot", "count", 3,
		"readiness", notification.Msg("coverage.readiness.feature_off"))
	first := notification.NewNotification(notification.NotificationParams{
		TenantID: tenant, Audience: notification.AudienceUser, AudienceID: &uid,
		NotificationType: notification.TypeCoverageGap, Title: "Coverage paused: capture.screenshot",
		Body: "English body", Message: msg, ResourceType: "asset", ResourceID: &asset, Coalesce: true,
	})
	if err := repo.Create(ctx, first); err != nil {
		t.Fatal(err)
	}
	plain := notification.NewNotification(notification.NotificationParams{
		TenantID: tenant, Audience: notification.AudienceUser, AudienceID: &uid,
		NotificationType: notification.TypeSystemAlert, Title: "No code",
	})
	if err := repo.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}

	// A second event on the same item folds in and replaces the message.
	newer := notification.NewNotification(notification.NotificationParams{
		TenantID: tenant, Audience: notification.AudienceUser, AudienceID: &uid,
		NotificationType: notification.TypeCoverageGap, Title: "Coverage paused: capture.screenshot",
		Body: "English body 2", Message: notification.Msg("coverage.readiness", "capability", "capture.screenshot", "count", 5),
		ResourceType: "asset", ResourceID: &asset, Coalesce: true,
	})
	merged, err := repo.CreateCoalesced(ctx, newer)
	if err != nil || !merged {
		t.Fatalf("coalesce merged=%v err=%v", merged, err)
	}

	res, err := repo.List(ctx, tenant, user, notification.ListFilter{}, pagination.New(1, 20))
	if err != nil {
		t.Fatal(err)
	}
	var coded, none bool
	for _, n := range res.Data {
		switch n.ID() {
		case first.ID():
			m := n.Message()
			if m == nil || m.Code != "coverage.readiness" || m.Params["count"] != float64(5) || n.Body() != "English body 2" {
				t.Fatalf("coalesced message %+v body %q", m, n.Body())
			}
			coded = true
		case plain.ID():
			if n.Message() != nil {
				t.Fatalf("plain notice got a message %+v", n.Message())
			}
			none = true
		}
	}
	if !coded || !none {
		t.Fatalf("rows missing: coded=%v none=%v", coded, none)
	}

	// The same user in another organization sees none of these rows.
	if res, err := repo.List(ctx, other, user, notification.ListFilter{}, pagination.New(1, 20)); err != nil || len(res.Data) != 0 {
		t.Fatalf("other organization read %d rows, err %v", len(res.Data), err)
	}

	// The table refuses a malformed code even if a caller skipped Validate.
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO notifications (tenant_id, audience, notification_type, title, message_code)
		VALUES ($1, 'all', 'system_alert', 'x', 'Bad Code')`, tenant.String()); err == nil {
		t.Fatal("a malformed message code was stored")
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO notifications (tenant_id, audience, notification_type, title, message_code, message_params)
		VALUES ($1, 'all', 'system_alert', 'x', 'a.b', '[1]'::jsonb)`, tenant.String()); err == nil {
		t.Fatal("non-object message values were stored")
	}
}
