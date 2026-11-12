package postgres

// StoreSightingData: a batch's interop data and its source's records are one
// statement per chunk, both halves land, both stay in the caller's tenant,
// and a batch larger than one chunk writes every record.

import (
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/internal/testdb/sqlcount"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

func TestStoreSightingData_OneStatementBothHalves_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)
	mine := f.findingByTool(f.tenant, f.asset, "fp-sd", "nessus")
	theirs := f.findingByTool(other, otherAsset, "fp-sd", "nessus")

	counter := &sqlcount.Counter{}
	cdb, err := sqlcount.Open(testdb.URL(), counter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cdb.Close() })
	repo := NewFindingRepository(&DB{DB: cdb})

	vals := sourceValues("fp-sd", "a", time.Now().UTC())
	interop := []vulnerability.InteropUpdate{{Fingerprint: "fp-sd", Tool: "nessus", Data: vals.Interop}}
	counter.Reset()
	if err := repo.StoreSightingData(f.ctx, f.tenant, interop,
		vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"}, []vulnerability.SourceRecordValues{vals}); err != nil {
		t.Fatalf("store sighting data: %v", err)
	}
	if n := counter.Snapshot().Statements; n != 1 {
		t.Errorf("%d statements, want 1 (interop and source records together)", n)
	}

	recs := f.sources(f.tenant, mine)
	if len(recs) != 1 {
		t.Fatalf("%d source records, want 1", len(recs))
	}
	checkSourceValues(t, recs[0], "a")
	if c := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND id = $2 AND location_key = 'host:22/a'`,
		f.tenant.String(), mine.String()); c != 1 {
		t.Error("the interop data was not written on the tenant's finding")
	}

	// Another tenant's finding with the same fingerprint gets neither half.
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE tenant_id = $1`, other.String()); c != 0 {
		t.Errorf("another tenant got %d records", c)
	}
	if c := f.count(`SELECT count(*) FROM findings WHERE id = $1 AND location_key IS NOT NULL`, theirs.String()); c != 0 {
		t.Error("another tenant's finding got interop data")
	}
}

// Records without interop data, more than one chunk of them: every one is
// written, one statement per chunk.
func TestStoreSightingData_RecordsOnlyAcrossChunks_DB(t *testing.T) {
	f := newReceiptFixture(t)
	n := maxSourceRecordBatch + 3
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, fingerprint, status, title)
		SELECT gen_random_uuid(), $1, $2, 'va', 'nessus', 'm', 'high', 'fp-chunk-' || g, 'new', 't'
		FROM generate_series(1, $3::int) g`, f.tenant.String(), f.asset.String(), n); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	vals := make([]vulnerability.SourceRecordValues, 0, n)
	for i := 1; i <= n; i++ {
		vals = append(vals, vulnerability.SourceRecordValues{Fingerprint: fmt.Sprintf("fp-chunk-%d", i), Title: "t"})
	}

	counter := &sqlcount.Counter{}
	cdb, err := sqlcount.Open(testdb.URL(), counter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cdb.Close() })
	counter.Reset()
	if err := NewFindingRepository(&DB{DB: cdb}).StoreSightingData(f.ctx, f.tenant, nil,
		vulnerability.SourceIdentity{Channel: "upload", Tool: "nessus"}, vals); err != nil {
		t.Fatalf("store sighting data: %v", err)
	}
	if s := counter.Snapshot().Statements; s != 2 {
		t.Errorf("%d statements, want 2 (one per chunk)", s)
	}
	if c := f.count(`SELECT count(*) FROM finding_source_records WHERE tenant_id = $1`, f.tenant.String()); c != n {
		t.Errorf("%d records, want %d", c, n)
	}
}
