package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The finding repository never wrote or read finding_type and the secret_*,
// compliance_*, web3_* and misconfig_* columns: ingest set them on the entity,
// the API returned them, and a stored finding came back without them. These
// tests write a finding through each write path and read it back.

type typeDetailsFixture struct {
	db    *sql.DB
	repo  *postgres.FindingRepository
	tid   shared.ID
	asset shared.ID
}

func newTypeDetailsFixture(t *testing.T) typeDetailsFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping finding type-details DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tid, aid := shared.NewID(), shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Type details IT', $2)`,
		tid.String(), "ftd-it-"+strings.ReplaceAll(uuid.NewString()[:13], "-", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'repo-ftd', 'repository')`,
		aid.String(), tid.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tid.String())
		_, _ = db.ExecContext(bg, `DELETE FROM assets WHERE tenant_id = $1`, tid.String())
		_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tid.String())
	})
	return typeDetailsFixture{db: db, repo: postgres.NewFindingRepository(&postgres.DB{DB: db}), tid: tid, asset: aid}
}

func (fx typeDetailsFixture) newFinding(t *testing.T, source vulnerability.FindingSource, fingerprint string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(fx.tid, fx.asset, source, "scanner", vulnerability.SeverityHigh, "msg "+fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	f.SetFingerprint(fingerprint)
	return f
}

func TestFindingTypeDetails_SecretRoundTripsThroughCreate(t *testing.T) {
	fx := newTypeDetailsFixture(t)
	ctx := context.Background()

	valid, revoked := true, false
	entropy := 4.82
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	f := fx.newFinding(t, vulnerability.FindingSourceSecret, "ftd-secret-1")
	f.SetFindingType(vulnerability.FindingTypeSecret)
	f.SetSecretDetails("api_key", "Stripe", &valid, &revoked, &entropy, &expires)
	if err := fx.repo.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := fx.repo.GetByID(ctx, fx.tid, f.ID())
	if err != nil {
		t.Fatal(err)
	}
	d := got.TypeDetails()
	if d.FindingType != vulnerability.FindingTypeSecret || d.SecretType != "api_key" || d.SecretService != "Stripe" {
		t.Fatalf("secret details lost: %+v", d)
	}
	if d.SecretValid == nil || !*d.SecretValid || d.SecretRevoked == nil || *d.SecretRevoked {
		t.Errorf("validity lost: valid=%v revoked=%v", d.SecretValid, d.SecretRevoked)
	}
	if d.SecretEntropy == nil || *d.SecretEntropy != 4.82 || d.SecretExpiresAt == nil || !d.SecretExpiresAt.Equal(expires) {
		t.Errorf("entropy/expiry lost: %v %v", d.SecretEntropy, d.SecretExpiresAt)
	}
}

func TestFindingTypeDetails_MisconfigThroughBatchUpsertAndUpdate(t *testing.T) {
	fx := newTypeDetailsFixture(t)
	ctx := context.Background()

	f := fx.newFinding(t, vulnerability.FindingSourceIaC, "ftd-misconfig-1")
	f.SetFindingType(vulnerability.FindingTypeMisconfiguration)
	f.SetMisconfigPolicyID("AVD-AWS-0088")
	f.SetMisconfigResourceType("aws_s3_bucket")
	f.SetMisconfigResourceName("logs")
	f.SetMisconfigResourcePath("terraform/s3.tf")
	f.SetMisconfigExpected("encryption on")
	f.SetMisconfigActual("not set")
	// The ingest path: multi-row INSERT … ON CONFLICT.
	if res, err := fx.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{f}); err != nil || res.Created != 1 {
		t.Fatalf("batch create: %v %+v", err, res)
	}
	got, err := fx.repo.GetByID(ctx, fx.tid, f.ID())
	if err != nil {
		t.Fatal(err)
	}
	if d := got.TypeDetails(); d.FindingType != vulnerability.FindingTypeMisconfiguration ||
		d.MisconfigPolicyID != "AVD-AWS-0088" || d.MisconfigActual != "not set" || d.MisconfigResourcePath != "terraform/s3.tf" {
		t.Fatalf("misconfig details lost on batch insert: %+v", d)
	}

	// A re-sighting that knows nothing about the type keeps what is stored.
	again := fx.newFinding(t, vulnerability.FindingSourceIaC, "ftd-misconfig-1")
	if _, err := fx.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{again}); err != nil {
		t.Fatal(err)
	}
	got, _ = fx.repo.GetByID(ctx, fx.tid, f.ID())
	if d := got.TypeDetails(); d.FindingType != vulnerability.FindingTypeMisconfiguration || d.MisconfigPolicyID != "AVD-AWS-0088" {
		t.Fatalf("re-sighting wiped the type details: %+v", d)
	}

	// Update persists a change.
	got.SetMisconfigActual("aws:kms")
	if err := fx.repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, _ := fx.repo.GetByID(ctx, fx.tid, f.ID())
	if after.TypeDetails().MisconfigActual != "aws:kms" {
		t.Fatalf("update did not persist: %+v", after.TypeDetails())
	}
}

func TestFindingTypeDetails_OddScannerValuesDoNotFailTheInsert(t *testing.T) {
	fx := newTypeDetailsFixture(t)
	ctx := context.Background()

	f := fx.newFinding(t, vulnerability.FindingSourceIaC, "ftd-compliance-1")
	f.SetFindingType(vulnerability.FindingTypeCompliance)
	f.SetComplianceDetails("cis", "1.1", "Ensure MFA", "PASSED-ish", "IAM")
	f.SetMisconfigPolicyID(strings.Repeat("x", 300)) // column is VARCHAR(100)
	if res, err := fx.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{f}); err != nil || res.Created != 1 {
		t.Fatalf("batch create: %v %+v", err, res)
	}
	got, err := fx.repo.GetByID(ctx, fx.tid, f.ID())
	if err != nil {
		t.Fatal(err)
	}
	d := got.TypeDetails()
	if d.ComplianceFramework != "cis" || d.ComplianceControlID != "1.1" {
		t.Errorf("compliance details lost: %+v", d)
	}
	if d.ComplianceResult != "" {
		t.Errorf("a result the CHECK rejects should be stored empty, got %q", d.ComplianceResult)
	}
	if len(d.MisconfigPolicyID) != 100 {
		t.Errorf("long policy id should be clipped to 100, got %d", len(d.MisconfigPolicyID))
	}

	// A finding with no type at all gets the column's default.
	plain := fx.newFinding(t, vulnerability.FindingSourceSCA, "ftd-plain-1")
	if err := fx.repo.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := fx.db.QueryRowContext(ctx, `SELECT finding_type FROM findings WHERE id = $1`, plain.ID().String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "vulnerability" {
		t.Errorf("finding_type = %q, want the default vulnerability", stored)
	}
}

// The facts without a column live in type_details, and no part of the row
// (columns, metadata, the document) holds the secret a scanner reported.
func TestFindingTypeDetails_ExtrasPersistAndTheSecretNeverDoes(t *testing.T) {
	fx := newTypeDetailsFixture(t)
	ctx := context.Background()
	const raw = "fake-token-51HxyzABCDEFGHIJKLMNOPQRSTUV1234Qx"

	rotation := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	f := fx.newFinding(t, vulnerability.FindingSourceSecret, "ftd-secret-extras")
	f.SetFindingType(vulnerability.FindingTypeSecret)
	f.SetSecretType("api_key")
	f.SetSecretService("Stripe")
	f.SetSecretMaskedValue(raw) // a scanner that masks nothing
	f.SetSecretFingerprint(vulnerability.NewSecretFingerprinter([]byte("server-secret")).Fingerprint(f.TenantID(), raw))
	f.SetSecretScopes([]string{"charges:write", "refunds:write"})
	f.SetSecretRotationDueAt(&rotation)
	f.SetSecretCommitCount(3)
	f.SetSecretInHistoryOnly(true)
	if res, err := fx.repo.CreateBatchWithResult(ctx, []*vulnerability.Finding{f}); err != nil || res.Created != 1 {
		t.Fatalf("batch create: %v %+v", err, res)
	}

	var row string
	if err := fx.db.QueryRowContext(ctx, `SELECT row_to_json(findings)::text FROM findings WHERE id = $1`, f.ID().String()).Scan(&row); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{raw, raw[4 : len(raw)-4], "ABCDEFGH"} {
		if strings.Contains(row, leak) {
			t.Fatalf("the stored row contains the secret (%q)", leak)
		}
	}

	got, err := fx.repo.GetByID(ctx, fx.tid, f.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.SecretMaskedValue() != "fake…34Qx" || got.SecretFingerprint() != f.SecretFingerprint() || got.SecretFingerprint() == "" {
		t.Errorf("preview %q fingerprint %q", got.SecretMaskedValue(), got.SecretFingerprint())
	}
	if len(got.SecretScopes()) != 2 || got.SecretCommitCount() != 3 || !got.SecretInHistoryOnly() ||
		got.SecretRotationDueAt() == nil || !got.SecretRotationDueAt().Equal(rotation) {
		t.Errorf("secret extras lost: scopes=%v commits=%d history=%v rotation=%v",
			got.SecretScopes(), got.SecretCommitCount(), got.SecretInHistoryOnly(), got.SecretRotationDueAt())
	}

	// Misconfiguration extras.
	m := fx.newFinding(t, vulnerability.FindingSourceIaC, "ftd-misconfig-extras")
	m.SetFindingType(vulnerability.FindingTypeMisconfiguration)
	m.SetMisconfigPolicyID("AVD-AWS-0088")
	m.SetMisconfigPolicyName("S3 bucket has no server-side encryption")
	m.SetMisconfigCause("no server_side_encryption_configuration block")
	if err := fx.repo.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	gm, err := fx.repo.GetByID(ctx, fx.tid, m.ID())
	if err != nil {
		t.Fatal(err)
	}
	if gm.MisconfigPolicyName() != "S3 bucket has no server-side encryption" || gm.MisconfigCause() == "" {
		t.Errorf("misconfig extras lost: %q %q", gm.MisconfigPolicyName(), gm.MisconfigCause())
	}
}
