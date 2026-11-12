package integration

// Retired import sources at ingest (docs/architecture/source-retirement.md):
// a report of a retired source applies nothing and its receipt counts every
// finding it sent (never a silent drop); another tenant's source of the
// same name is not blocked; the source works again once restored.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/sourceretire"
)

func TestSourceRetire_IngestRefusesRetiredSource(t *testing.T) {
	r := newReconRig(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: r.db}
	retirements := postgres.NewSourceRetirementRepository(pg)
	r.ing.SetPolicyVersions(postgres.NewIngestPolicyVersions(pg))
	r.ing.SetRetiredSources(retirements)

	tenant := r.tenant()
	other := r.tenant()
	sync := func(tid shared.ID, name, run string, rules ...string) *ingest.Output {
		t.Helper()
		out, err := r.ing.Ingest(ctx, &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}, ingest.Input{
			Report: reconReport(rules...), CoverageType: ingest.CoverageTypePartial,
			Options: ingest.Options{Binding: ingest.TrustedBinding(), SourceKind: "integration", SourceName: name, SourceRun: run},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	countFindings := func(tid shared.ID, where string) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND `+where, tid.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	sync(tenant, "junk-feed", "s1", "a", "b")
	sync(other, "junk-feed", "o1", "a")
	if n := countFindings(tenant, "true"); n != 2 {
		t.Fatalf("findings before = %d", n)
	}

	ret, err := retirements.Create(ctx, &sourceretire.Retirement{TenantID: tenant,
		Selector: sourceretire.Selector{Kind: sourceretire.KindConnector, Sender: "junk-feed"},
		Options:  sourceretire.Options{Mode: sourceretire.ModeArchive}, Reason: "wrong results all along"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := retirements.ArchiveBatch(ctx, tenant, ret.ID, time.Now().UTC())
	if err != nil || res.Moved != 2 {
		t.Fatalf("archive: %+v %v", res, err)
	}

	// The retired source reports again, with a new finding: nothing is
	// applied, and the receipt reconciles with every finding refused.
	out := sync(tenant, "junk-feed", "s2", "a", "b", "c")
	if !out.SourceRetired || out.FindingsCreated != 0 {
		t.Fatalf("output = %+v", out)
	}
	received, c, outcomes := r.reconciled(tenant, out.ReceiptID)
	if received != 3 || outcomes[ingestreceipt.OutcomeSourceRetired] != 3 || c.Created+c.StillDetected+c.Reopened != 0 {
		t.Fatalf("receipt: received %d, counts %+v, outcomes %v", received, c, outcomes)
	}
	if n := countFindings(tenant, "status = 'resolved' AND closure_reason = 'obsolete_source'"); n != 2 {
		t.Fatalf("archived findings = %d, want 2 (a refused report never reopens them)", n)
	}
	if n := countFindings(tenant, "true"); n != 2 {
		t.Fatalf("a refused report created findings: %d", n)
	}

	// Another tenant's source of the same name is not blocked.
	if o := sync(other, "junk-feed", "o2", "a", "z"); o.SourceRetired || o.FindingsCreated != 1 {
		t.Fatalf("other tenant output = %+v", o)
	}
	if n := countFindings(other, "status = 'resolved'"); n != 0 {
		t.Fatalf("another tenant's findings archived: %d", n)
	}

	// Another source of the tenant is not blocked.
	if o := sync(tenant, "good-feed", "g1", "c"); o.SourceRetired || o.FindingsCreated != 1 {
		t.Fatalf("good feed output = %+v", o)
	}

	// Used again: restored and accepted.
	if _, err := retirements.StartRestore(ctx, tenant, ret.ID, nil, "fixed upstream"); err != nil {
		t.Fatal(err)
	}
	if _, err := retirements.RestoreBatch(ctx, tenant, ret.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if n := countFindings(tenant, "status = 'new'"); n != 3 {
		t.Fatalf("open findings after restore = %d, want 3", n)
	}
	if o := sync(tenant, "junk-feed", "s3", "a"); o.SourceRetired {
		t.Fatal("a restored source is still refused")
	}
}
