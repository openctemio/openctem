package postgres

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Per-sensor answers: the newest answer of each sensor is kept, old answers
// are not read, a sensor of another tenant writes nothing, and another
// tenant never reads them.
func TestNameResolution_RecordReadIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewNameResolutionRepository(&DB{DB: sqlDB})
	a, b := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	sensor := func(tenant shared.ID) shared.ID {
		id := shared.NewID()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
			VALUES ($1, $2, $3, $4, 'p', 'active')`, id.String(), tenant.String(), "s-"+id.String()[:8], "h-"+id.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	laptop, bSensor := sensor(a), sensor(b)
	zone := shared.NewID()
	now := time.Now().UTC().Truncate(time.Second)
	ip := netip.MustParseAddr

	if err := repo.RecordAnswers(ctx, a, laptop, &zone, map[string][]netip.Addr{
		"Intranet.Example.com.": {ip("10.20.0.5"), ip("10.20.0.5"), ip("::ffff:10.20.0.6")},
		"":                      {ip("10.0.0.1")},
	}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A newer answer replaces it; an older one does not.
	_ = repo.RecordAnswers(ctx, a, laptop, &zone, map[string][]netip.Addr{"intranet.example.com": {ip("10.20.0.7")}}, now)
	_ = repo.RecordAnswers(ctx, a, laptop, nil, map[string][]netip.Addr{"intranet.example.com": {ip("10.99.0.1")}}, now.Add(-2*time.Hour))

	got, err := repo.VantageAnswers(ctx, a, []string{"intranet.example.com"}, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ans := got["intranet.example.com"]
	if len(ans) != 1 || ans[0].Observer != laptop || ans[0].ZoneID == nil || *ans[0].ZoneID != zone ||
		len(ans[0].Addrs) != 1 || ans[0].Addrs[0] != ip("10.20.0.7") {
		t.Fatalf("answers = %+v", ans)
	}
	// Outside the freshness window: not read.
	if got, _ := repo.VantageAnswers(ctx, a, []string{"intranet.example.com"}, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("stale answer read: %+v", got)
	}
	// Tenant b reads nothing of tenant a.
	if got, _ := repo.VantageAnswers(ctx, b, []string{"intranet.example.com"}, now.Add(-24*time.Hour)); len(got) != 0 {
		t.Fatalf("tenant b read tenant a's answers: %+v", got)
	}
	// Tenant b's sensor cannot write under tenant a.
	if err := repo.RecordAnswers(ctx, a, bSensor, nil, map[string][]netip.Addr{"intranet.example.com": {ip("10.66.0.1")}}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.VantageAnswers(ctx, a, []string{"intranet.example.com"}, now.Add(-24*time.Hour)); len(got["intranet.example.com"]) != 1 {
		t.Fatalf("another tenant's sensor wrote an answer: %+v", got)
	}
}
