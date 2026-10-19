package refingerprintcmd

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/refingerprint"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestReadOnlyURL(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h:5432/db?sslmode=disable": "postgres://u:p@h:5432/db?default_transaction_read_only=on&sslmode=disable",
		"host=h dbname=db":                         "host=h dbname=db default_transaction_read_only=on",
	}
	for in, want := range cases {
		if got := readOnlyURL(in); got != want {
			t.Errorf("readOnlyURL(%q) = %q, want %q", in, got, want)
		}
	}
}

type recorder struct{ logs []*audit.AuditLog }

func (r *recorder) Create(_ context.Context, l *audit.AuditLog) error {
	r.logs = append(r.logs, l)
	return nil
}

// An applied run that changed findings writes one findings.refingerprinted
// entry in that tenant; a dry run or a run that changed nothing writes none.
func TestAuditRun(t *testing.T) {
	tenant := shared.NewID()
	rec := &recorder{}
	ctx := context.Background()
	for _, rep := range []*refingerprint.Report{
		{TenantID: tenant.String(), Applied: false, Rekeyed: 3},
		{TenantID: tenant.String(), Applied: true},
	} {
		if err := auditRun(ctx, rec, "run-1", rep); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.logs) != 0 {
		t.Fatalf("%d entries for a dry run / empty run", len(rec.logs))
	}
	if err := auditRun(ctx, rec, "run-1", &refingerprint.Report{TenantID: tenant.String(), Applied: true, Scanned: 9, Rekeyed: 3, Merged: 1}); err != nil {
		t.Fatal(err)
	}
	if len(rec.logs) != 1 {
		t.Fatalf("%d entries, want 1", len(rec.logs))
	}
	l := rec.logs[0]
	if l.Action() != audit.ActionFindingsRefingerprinted || l.ActorUserAgent() != "refingerprint" ||
		l.TenantID() == nil || *l.TenantID() != tenant || l.Metadata()["run_id"] != "run-1" || l.Metadata()["rekeyed"] != 3 {
		t.Errorf("entry = %s %q %v %v", l.Action(), l.ActorUserAgent(), l.TenantID(), l.Metadata())
	}
}
