package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/ctemid"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// PostgreSQL refuses a statement with more than 65535 bind parameters. The
// re-sighting enrich UPDATE binds 75 parameters per finding; at 1000 rows per
// statement (75,000 parameters) every rescan that re-saw more than 873
// findings failed the enrich step, and ingest fell back to updating only the
// scan id, dropping the new scanner data.
func TestEnrichBatch_MoreRowsThanOneStatementHolds(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenant)

	const n = 1000 // > floor(65535/75) = 873
	initial := make([]*vulnerability.Finding, 0, n)
	again := make([]*vulnerability.Finding, 0, n)
	for i := range n {
		f, err := vulnerability.NewFinding(tenant, assetID, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityLow, "m")
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint(fmt.Sprintf("fp-bulk-%s-%d", tenant, i))
		initial = append(initial, f)

		g, _ := vulnerability.NewFinding(tenant, assetID, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "m")
		g.SetFingerprint(f.Fingerprint())
		again = append(again, g)
	}
	if err := repo.CreateBatch(ctx, initial); err != nil {
		t.Fatalf("create: %v", err)
	}

	enriched, err := repo.EnrichBatchByFingerprints(ctx, tenant, again, "scan-2")
	if err != nil {
		t.Fatalf("enrich %d findings: %v", n, err)
	}
	if enriched != n {
		t.Fatalf("enriched = %d, want %d", enriched, n)
	}
	var high int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND severity = 'high'`, tenant.String()).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != n {
		t.Fatalf("findings carrying the new scan's severity = %d, want %d", high, n)
	}
}

// The asset upsert binds 37 parameters per asset in one statement: more than
// 1771 assets used to fail the multi-row statement and fall back to one
// statement per asset inside one transaction.
func TestAssetUpsertMultiRow_MoreRowsThanOneStatementHolds(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	const n = 2000 // > floor(65535/37) = 1771
	assets := make([]*asset.Asset, 0, n)
	for i := range n {
		a, err := asset.NewAssetWithTenant(tenant, fmt.Sprintf("bulk-%d.example.com", i), asset.AssetTypeDomain, asset.CriticalityLow)
		if err != nil {
			t.Fatal(err)
		}
		assets = append(assets, a)
	}
	created, updated, ids, err := repo.upsertBatchMultiRow(ctx, assets)
	if err != nil {
		t.Fatalf("multi-row upsert of %d assets: %v", n, err)
	}
	if created != n || updated != 0 || len(ids) != n {
		t.Fatalf("created=%d updated=%d ids=%d, want %d/0/%d", created, updated, len(ids), n, n)
	}
}

// 17 parameters per CVE: a report with more than 3855 distinct CVEs failed the
// catalog step.
func TestUpsertBatchByCVE_MoreRowsThanOneStatementHolds(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewVulnerabilityRepository(&DB{DB: db})
	prefix := fmt.Sprint(10000 + time.Now().UnixNano()%89999)

	const n = 4000
	vulns := make([]*vulnerability.Vulnerability, 0, n)
	for i := range n {
		v, err := vulnerability.NewVulnerability(fmt.Sprintf("CVE-2098-%s%05d", prefix, i), "t", vulnerability.SeverityLow)
		if err != nil {
			t.Fatal(err)
		}
		vulns = append(vulns, v)
	}
	if err := repo.UpsertBatchByCVE(ctx, vulns); err != nil {
		t.Fatalf("upsert %d CVEs: %v", n, err)
	}
	var got int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM vulnerabilities WHERE cve_id LIKE $1`, "CVE-2098-"+prefix+"%").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("stored %d CVEs, want %d", got, n)
	}
}

// 18 parameters per exposure: the certificate and DNS monitors pass thousands
// of events in one call.
func TestExposureBulkUpsert_MoreRowsThanOneStatementHolds(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewExposureRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	const n = 4000
	events := make([]*exposure.ExposureEvent, 0, n)
	for i := range n {
		e, err := exposure.NewExposureEvent(tenant, exposure.EventTypePortOpen, exposure.SeverityLow, fmt.Sprintf("Port %d open", i), "nmap", map[string]any{"port": i})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if err := repo.BulkUpsert(ctx, events); err != nil {
		t.Fatalf("bulk upsert %d events: %v", n, err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	written, err := repo.BulkUpsertInTx(ctx, tx, events)
	if err != nil {
		t.Fatalf("bulk upsert in tx of %d events: %v", n, err)
	}
	if len(written) != n {
		t.Fatalf("in-tx upsert reported %d rows, want %d", len(written), n)
	}
	var got int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE tenant_id = $1`, tenant.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("stored %d exposures, want %d", got, n)
	}
}

// 9 parameters per catalog entry: a feed of more than 7281 entries failed.
func TestCTEMIDUpsertBatch_MoreRowsThanOneStatementHolds(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewCTEMIDRepository(&DB{DB: db})
	prefix := "BULK-" + shared.NewID().String()[:8]

	const n = 8000
	entries := make([]*ctemid.CTEMID, 0, n)
	for i := range n {
		entries = append(entries, ctemid.NewCTEMID(fmt.Sprintf("%s-%d", prefix, i), ctemid.CategoryCredentialDumps, "t", "d", "low", "", nil, nil))
	}
	if err := repo.UpsertBatch(ctx, entries); err != nil {
		t.Fatalf("upsert %d entries: %v", n, err)
	}
	var got int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ctem_id_catalog WHERE ctem_id LIKE $1`, prefix+"-%").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("stored %d entries, want %d", got, n)
	}
}

func TestAuditCreateBatch_MoreRowsThanOneStatementHolds(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAuditRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	const n = 4000
	logs := make([]*audit.AuditLog, 0, n)
	for i := range n {
		l, err := audit.NewAuditLog(audit.ActionUserCreated, audit.ResourceTypeUser, fmt.Sprint(i), audit.ResultSuccess)
		if err != nil {
			t.Fatal(err)
		}
		logs = append(logs, l.WithTenantID(tenant))
	}
	if err := repo.CreateBatch(ctx, logs); err != nil {
		t.Fatalf("create %d audit rows: %v", n, err)
	}
	var got int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1`, tenant.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("stored %d audit rows, want %d", got, n)
	}
}

// Id lists taken from a request body bind one array parameter, so a long
// list is answered, not refused by the database. Other tenants' groups still
// fail the check.
func TestIDListsFromRequests_NoBindLimit(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	ids := make([]shared.ID, 70000)
	for i := range ids {
		ids[i] = shared.NewID()
	}
	n, err := NewAttachmentRepository(&DB{DB: db}).LinkToContext(ctx, tenant, ids, shared.NewID(), "finding", shared.NewID().String())
	if err != nil || n != 0 {
		t.Fatalf("link %d unknown attachments = %d, %v; want 0, nil", len(ids), n, err)
	}

	ac := NewAccessControlRepository(&DB{DB: db})
	if err := ac.ValidateAssetGroupsBelongToTenant(ctx, tenant, ids); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("validate %d unknown groups = %v, want a validation error", len(ids), err)
	}
	group := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_groups (id, tenant_id, name, environment, criticality) VALUES ($1, $2, $3, 'production', 'low')`,
		group.String(), other.String(), "g-"+group.String()); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := ac.ValidateAssetGroupsBelongToTenant(ctx, other, []shared.ID{group}); err != nil {
		t.Fatalf("own group refused: %v", err)
	}
	if err := ac.ValidateAssetGroupsBelongToTenant(ctx, tenant, []shared.ID{group}); err == nil {
		t.Fatal("another tenant's group accepted")
	}
}
