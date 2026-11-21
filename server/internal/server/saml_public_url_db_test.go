package server

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/testdb"
)

// A production server without APP_URL starts only while no organization has
// SAML sign-in enabled.
//
// The check runs inside one transaction against a temporary table shaped
// like saml_providers (it shadows the real one for this session), so SAML
// rows other tests keep in the shared test database do not decide the result.
func TestRequireSAMLPublicURL_DB(t *testing.T) {
	ctx := context.Background()
	db := testdb.OpenMigrator(t)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE saml_providers (LIKE public.saml_providers INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
		t.Fatalf("shadow table: %v", err)
	}
	insert := func(enabled bool) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, `INSERT INTO saml_providers (tenant_id, idp_entity_id, idp_sso_url, idp_certificate, enabled)
			VALUES (gen_random_uuid(), $1, $2, $3, $4)`, "https://idp.example.org/entity", "https://idp.example.org/sso", "-", enabled); err != nil {
			t.Fatalf("insert provider: %v", err)
		}
	}
	prod := samlURLConfig(config.EnvProduction, "")

	if err := requireSAMLPublicURL(ctx, tx, prod); err != nil {
		t.Fatalf("no SAML configuration: %v, want a start", err)
	}
	insert(false)
	if err := requireSAMLPublicURL(ctx, tx, prod); err != nil {
		t.Fatalf("SAML configured but switched off: %v, want a start", err)
	}
	insert(true)
	insert(true)
	err = requireSAMLPublicURL(ctx, tx, prod)
	if err == nil {
		t.Fatal("production, APP_URL unset, SAML enabled: the server must refuse to start")
	}
	if !strings.Contains(err.Error(), "APP_URL") || !strings.Contains(err.Error(), "2 organization(s)") {
		t.Errorf("refusal %q must name APP_URL and the number of organizations", err)
	}
	// The same database starts once APP_URL is set, and outside production.
	if err := requireSAMLPublicURL(ctx, tx, samlURLConfig(config.EnvProduction, "https://ctem.example.com")); err != nil {
		t.Errorf("APP_URL set: %v, want a start", err)
	}
	if err := requireSAMLPublicURL(ctx, tx, samlURLConfig("development", "")); err != nil {
		t.Errorf("development: %v, want a start", err)
	}
}
