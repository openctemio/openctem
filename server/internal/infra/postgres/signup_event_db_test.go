package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/signupevent"
)

// Sign-up events (migration signup_events) as the application role: round
// trip, filters, daily counts, retention, the prefix check, the foreign keys
// that drop the link when the organization or the account goes, and the
// versioned thresholds setting. Requires DATABASE_URL.
func TestSignupEventRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	r := NewSignupEventRepository(db)
	domain := "se-" + shared.NewID().String()[28:] + ".example"
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM signup_events WHERE email_domain = $1`, domain)
	})

	tenantID := seedTenant(ctx, t, db)
	userID := seedUser(ctx, t, db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	events := []signupevent.Record{
		{Kind: signupevent.KindAccountCreated, Source: signupevent.SourcePassword, EmailDomain: domain,
			IPPrefix: "198.51.100.0/24", UserID: &userID, OccurredAt: now.Add(-2 * time.Minute)},
		{Kind: signupevent.KindOrganizationCreated, Source: signupevent.SourceSelfService, EmailDomain: domain,
			IPPrefix: "2001:db8:abcd::/48", TenantID: &tenantID, UserID: &userID, OccurredAt: now.Add(-time.Minute)},
		{Kind: signupevent.KindAccessRequested, Source: signupevent.SourcePublic, EmailDomain: domain, OccurredAt: now},
	}
	for _, e := range events {
		if err := r.Insert(ctx, e); err != nil {
			t.Fatalf("insert %s: %v", e.Kind, err)
		}
	}

	// A full address is refused by the check: only a /24 or a /48 is stored.
	if err := r.Insert(ctx, signupevent.Record{Kind: signupevent.KindAccountCreated, Source: signupevent.SourcePassword,
		EmailDomain: domain, IPPrefix: "198.51.100.7/32", OccurredAt: now}); err == nil {
		t.Fatal("a host address must be refused")
	}
	if err := r.Insert(ctx, signupevent.Record{Kind: "other", Source: signupevent.SourcePassword, EmailDomain: domain, OccurredAt: now}); err == nil {
		t.Fatal("an unknown kind must be refused")
	}

	list, total, err := r.List(ctx, signupevent.Filter{Kind: signupevent.KindOrganizationCreated, Since: now.Add(-time.Hour), Limit: 100})
	if err != nil || total < 1 {
		t.Fatalf("list: %v %d", err, total)
	}
	var found bool
	for _, e := range list {
		if e.Kind != signupevent.KindOrganizationCreated {
			t.Fatalf("filter leaked kind %s", e.Kind)
		}
		if e.EmailDomain == domain {
			found = true
			if e.IPPrefix != "2001:db8:abcd::/48" || e.TenantID == nil || *e.TenantID != tenantID {
				t.Fatalf("round trip: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("inserted event not listed")
	}

	daily, err := r.Daily(ctx, now.Add(-24*time.Hour))
	if err != nil || len(daily) == 0 {
		t.Fatalf("daily: %v %v", err, daily)
	}
	for _, d := range daily {
		if d.Day.Hour() != 0 || d.Day.Location() != time.UTC {
			t.Fatalf("day not truncated to UTC midnight: %v", d.Day)
		}
	}

	// Deleting the organization or the account keeps the event, unlinked.
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID.String()); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var linked int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM signup_events WHERE email_domain = $1
		AND (tenant_id IS NOT NULL OR user_id IS NOT NULL)`, domain).Scan(&linked); err != nil || linked != 0 {
		t.Fatalf("links kept after delete: %d %v", linked, err)
	}

	// Retention deletes only what is older than the cut-off.
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := r.Insert(ctx, signupevent.Record{Kind: signupevent.KindAccountCreated, Source: signupevent.SourcePassword,
		EmailDomain: domain, OccurredAt: old}); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if n, err := r.Purge(ctx, old.Add(time.Hour)); err != nil || n < 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	var left int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM signup_events WHERE email_domain = $1`, domain).Scan(&left)
	if left != 3 {
		t.Fatalf("purge removed recent events: %d left", left)
	}
}

func TestSignupBurstThresholdsSetting(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewSignupEventRepository(&DB{DB: sqlDB})
	var (
		prev    []byte
		prevVer int
	)
	hadPrev := sqlDB.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		signupevent.ThresholdsSettingKey).Scan(&prev, &prevVer) == nil
	_, _ = sqlDB.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, signupevent.ThresholdsSettingKey)
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM platform_settings WHERE key = $1`, signupevent.ThresholdsSettingKey)
		if hadPrev {
			_, _ = sqlDB.ExecContext(context.Background(), `INSERT INTO platform_settings (key, value, version) VALUES ($1, $2, $3)`,
				signupevent.ThresholdsSettingKey, prev, prevVer)
		}
	})

	if _, _, err := r.GetBurstThresholds(ctx); !errors.Is(err, signupevent.ErrThresholdsNotFound) {
		t.Fatalf("nothing stored: %v", err)
	}
	by := shared.NewID().String()
	want := signupevent.BurstThresholds{PerIPPrefix: 4, PerEmailDomain: 9, WindowMinutes: 30, IgnoredDomains: []string{"gmail.com"}}
	v, err := r.SetBurstThresholds(ctx, want, 0, by, time.Now())
	if err != nil || v != 1 {
		t.Fatalf("first set: %d %v", v, err)
	}
	if _, err := r.SetBurstThresholds(ctx, want, 0, by, time.Now()); !errors.Is(err, signupevent.ErrVersionConflict) {
		t.Fatalf("a second first write must conflict: %v", err)
	}
	got, ver, err := r.GetBurstThresholds(ctx)
	if err != nil || ver != 1 || got.PerIPPrefix != 4 || got.WindowMinutes != 30 || len(got.IgnoredDomains) != 1 {
		t.Fatalf("get: %+v %d %v", got, ver, err)
	}
	want.PerIPPrefix = 6
	if v, err := r.SetBurstThresholds(ctx, want, 1, by, time.Now()); err != nil || v != 2 {
		t.Fatalf("update: %d %v", v, err)
	}
	if _, err := r.SetBurstThresholds(ctx, want, 1, by, time.Now()); !errors.Is(err, signupevent.ErrVersionConflict) {
		t.Fatalf("stale version must conflict: %v", err)
	}
	// A stored value that does not validate is refused, never used.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE platform_settings SET value = '{"window_minutes": 1}' WHERE key = $1`,
		signupevent.ThresholdsSettingKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.GetBurstThresholds(ctx); err == nil {
		t.Fatal("an invalid stored value must be refused")
	}
}

// Account erasure unlinks the person's sign-up events (the domain and prefix
// stay as aggregate data).
func TestAccountErasureUnlinksSignupEvents(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	userID := seedUser(ctx, t, db)
	domain := "se-erase-" + shared.NewID().String()[28:] + ".example"
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM signup_events WHERE email_domain = $1`, domain)
	})
	if err := NewSignupEventRepository(db).Insert(ctx, signupevent.Record{Kind: signupevent.KindAccountCreated,
		Source: signupevent.SourcePassword, EmailDomain: domain, UserID: &userID, OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO account_deletions (user_id, erase_after, claimed_at)
		VALUES ($1, now(), now())`, userID.String()); err != nil {
		t.Fatal(err)
	}
	if err := NewAccountDeletionRepository(db).EraseAccount(ctx, userID, "Erased user"); err != nil {
		t.Fatalf("erase: %v", err)
	}
	var linked int
	if err := sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM signup_events WHERE email_domain = $1 AND user_id IS NOT NULL`,
		domain).Scan(&linked); err != nil || linked != 0 {
		t.Fatalf("erasure must unlink sign-up events: %d %v", linked, err)
	}
}
