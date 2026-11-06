package refingerprintcmd

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An applied run that masked something writes one findings.emails_masked
// entry in that tenant, with counts and no value; a dry run or a run that
// changed nothing writes none.
func TestAuditEmailScrub(t *testing.T) {
	tenant := shared.NewID()
	rec := &recorder{}
	ctx := context.Background()
	for _, rep := range []*postgres.EmailScrubReport{
		nil,
		{TenantID: tenant.String(), Applied: false, FindingsMasked: 3, EvidenceMasked: 2},
		{TenantID: tenant.String(), Applied: true, HumanFindingsLeft: 1},
	} {
		if err := AuditEmailScrub(ctx, rec, "run", rep); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.logs) != 0 {
		t.Fatalf("%d entries for runs that changed nothing", len(rec.logs))
	}
	rep := &postgres.EmailScrubReport{TenantID: tenant.String(), Applied: true, FindingsMasked: 3, EvidenceMasked: 2,
		HumanFindingsLeft: 1, Columns: map[string]int{"title": 3}}
	if err := AuditEmailScrub(ctx, rec, "run-1", rep); err != nil {
		t.Fatal(err)
	}
	if len(rec.logs) != 1 {
		t.Fatalf("%d entries, want 1", len(rec.logs))
	}
	l := rec.logs[0]
	if l.Action() != audit.ActionFindingsEmailsMasked || l.ActorUserAgent() != "refingerprint" || l.ResourceType() != audit.ResourceTypeFinding || l.TenantID() == nil || *l.TenantID() != tenant {
		t.Errorf("entry = %s %s %v", l.Action(), l.ResourceType(), l.TenantID())
	}
	md := l.Metadata()
	if md["findings_masked"] != 3 || md["evidence_masked"] != 2 || md["human_findings_left"] != 1 || md["run_id"] != "run-1" {
		t.Errorf("metadata = %v", md)
	}
	if strings.Contains(l.Message(), "@") {
		t.Errorf("message holds an address: %s", l.Message())
	}
}

// -mask-emails runs on the tenants named, or on every tenant only when asked
// to; never both, never neither.
func TestEmailScrubTenants(t *testing.T) {
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	got, err := emailScrubTenants(ctx, nil, a.String()+", "+b.String()+","+a.String(), false)
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("list = %v, %v", got, err)
	}
	for name, c := range map[string]struct {
		flag string
		all  bool
	}{"neither": {"", false}, "both": {a.String(), true}, "bad id": {"x", false}, "empty item": {a.String() + ",,", false}} {
		if _, err := emailScrubTenants(ctx, nil, c.flag, c.all); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
