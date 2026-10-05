package routes

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Scheduled reports mail organization posture out, so recipients are members
// of the organization or addresses in its allowed email domains (owner
// decision D12, research doc 15 L-19). Before, any address was accepted.
func TestReportRecipients_MembersOrAllowedDomains_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping report recipient DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer sqldb.Close()
	ctx := context.Background()
	if err := sqldb.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	tenant, other := shared.NewID().String(), shared.NewID().String()
	member, outsider := shared.NewID().String(), shared.NewID().String()
	memberEmail := "Analyst-" + member[24:] + "@Corp.Example"
	for _, tn := range []string{tenant, other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'rr', $2)`, tn, "rr-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenant, other} {
			_, _ = sqldb.ExecContext(bg, `DELETE FROM report_schedules WHERE tenant_id = $1`, tn)
			_, _ = sqldb.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{member, outsider} {
			_, _ = sqldb.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rr')`, member, memberEmail)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rr')`, outsider, "outsider-"+outsider[24:]+"@other.example")
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, member, tenant)
	// A member of another organization is not a member here.
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, outsider, other)

	db := &postgres.DB{DB: sqldb}
	repo := postgres.NewReportScheduleRepository(db)
	svc := module.NewReportScheduleService(repo, logger.NewNop())
	svc.SetRecipientPolicy(postgres.NewTenantRepository(db))
	create := func(emails ...string) error {
		rs := make([]reportschedule.Recipient, 0, len(emails))
		for _, e := range emails {
			rs = append(rs, reportschedule.Recipient{Email: e})
		}
		_, err := svc.CreateSchedule(ctx, module.CreateReportScheduleInput{
			TenantID: tenant, Name: "rr weekly", ReportType: "executive_summary", Format: "html",
			CronExpression: "0 9 * * 1", Recipients: rs,
		})
		return err
	}

	// No allowed domains: members only (case-insensitive).
	if err := create("analyst-" + member[24:] + "@corp.example"); err != nil {
		t.Errorf("a member as recipient: %v", err)
	}
	for _, e := range []string{"someone@gmail.com", "outsider-" + outsider[24:] + "@other.example"} {
		if err := create(e); !errors.Is(err, reportschedule.ErrRecipientNotAllowed) {
			t.Errorf("recipient %s: err = %v, want ErrRecipientNotAllowed", e, err)
		}
	}
	// With allowed domains, an address in one is accepted; others are not.
	exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{security}', '{"allowed_domains": ["corp.example"]}'::jsonb) WHERE id = $1`, tenant)
	if err := create("ciso@corp.example"); err != nil {
		t.Errorf("an allowed-domain recipient: %v", err)
	}
	if err := create("ciso@eu.corp.example"); !errors.Is(err, reportschedule.ErrRecipientNotAllowed) {
		t.Errorf("a subdomain of an allowed domain: err = %v, want refused", err)
	}

	// A schedule written before the policy cannot be switched back on with an
	// outside recipient.
	legacy, err := reportschedule.NewReportSchedule(shared.MustIDFromString(tenant), "rr legacy", "executive_summary", "html", "0 9 * * 1")
	if err != nil {
		t.Fatal(err)
	}
	legacy.SetRecipients([]reportschedule.Recipient{{Email: "someone@gmail.com"}})
	legacy.Deactivate()
	if err := repo.Create(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if err := svc.ToggleSchedule(ctx, tenant, legacy.ID().String(), true); !errors.Is(err, reportschedule.ErrRecipientNotAllowed) {
		t.Errorf("activating a legacy external schedule: err = %v, want refused", err)
	}
}
