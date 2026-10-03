package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Migration 000300 retypes the secret-scanner findings that were stored as
// 'vulnerability' (before #823 no insert wrote finding_type; betterleaks SARIF
// arrived with the generic type). It must change exactly those rows: secret
// technique or a known secret scanner, still at the default type.
func TestMigration000300_SecretTypeBackfill_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	up, err := os.ReadFile("../../../migrations/000300_findings_secret_type_backfill.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	seed := func(source, tool, findingType string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status, fingerprint, finding_type)
			VALUES ($1, $2, $3, $4, $5, 'm', 'high', 'new', $6, $7)`,
			id.String(), tenantID.String(), assetID.String(), source, tool, "st-fp-"+id.String(), findingType); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		return id
	}
	cases := []struct {
		name, source, tool, typ, want string
	}{
		{"betterleaks, secret technique", "secret", "betterleaks", "vulnerability", "secret"},
		{"gitleaks under another technique", "sast", "Gitleaks", "vulnerability", "secret"},
		{"trufflehog", "external", "trufflehog", "vulnerability", "secret"},
		{"already a secret", "secret", "betterleaks", "secret", "secret"},
		{"a scanner's real vulnerability", "sca", "trivy", "vulnerability", "vulnerability"},
		{"a misconfiguration from a secret technique is left alone", "secret", "checkov", "misconfiguration", "misconfiguration"},
	}
	ids := make([]shared.ID, len(cases))
	for i, c := range cases {
		ids[i] = seed(c.source, c.tool, c.typ)
	}

	if _, err := db.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("run 000300 up: %v", err)
	}
	for i, c := range cases {
		var got string
		if err := db.QueryRowContext(ctx, `SELECT finding_type FROM findings WHERE id = $1`, ids[i].String()).Scan(&got); err != nil {
			t.Fatalf("%s: read: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: finding_type %q, want %q", c.name, got, c.want)
		}
	}
}
