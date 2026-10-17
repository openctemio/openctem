package integration

// Migrations lifecycle_catalog .. findings_sub_status_index
// (docs/rfcs/RFC-110-tenant-lifecycles.md): the catalog tables, the findings
// sub-status column with its composite foreign key and the trigger that keeps
// every platform writer working. Up, down and up again; the database itself
// refuses a sub-status of another tenant or another status, a change of a
// sub-status's category, and a change of a published version.

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationLifecycleCatalog(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "miglc", dir)
	first := testdb.MigrationVersion(t, dir, "lifecycle_catalog")
	last := testdb.MigrationVersion(t, dir, "findings_sub_status_index")

	// The private database is migrated to the end; walk the four down and up.
	testdb.Migrate(t, db, dir, first, last, true)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'findings' AND column_name = 'sub_status_id'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after down: sub_status_id columns = %d (%v)", n, err)
	}
	testdb.Migrate(t, db, dir, first, last, false)

	exec := func(q string, args ...any) error {
		_, err := db.Exec(q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	refused := func(label, q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
	const (
		tenantA = "bbbbbbbb-1111-4111-8111-111111111111"
		tenantB = "bbbbbbbb-1111-4111-8111-222222222222"
		assetA  = "bbbbbbbb-2222-4222-8222-111111111111"
		inDev   = "bbbbbbbb-3333-4333-8333-111111111111" // A, in_progress
		review  = "bbbbbbbb-3333-4333-8333-222222222222" // A, in_progress
		bounty  = "bbbbbbbb-3333-4333-8333-333333333333" // A, resolved / fixed
		otherB  = "bbbbbbbb-3333-4333-8333-444444444444" // B, in_progress
		finding = "bbbbbbbb-4444-4444-8444-111111111111"
	)
	must(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-lc-a'), ($2, 'b', 'mig-lc-b')`, tenantA, tenantB)
	must(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h', 'host')`, assetA, tenantA)
	sub := func(id, tenant, key, status, reason string) {
		t.Helper()
		must(`INSERT INTO lifecycle_sub_statuses (id, tenant_id, canonical_status, closure_reason, key, name, color)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5, 'blue')`, id, tenant, status, reason, key)
	}
	sub(inDev, tenantA, "in_dev", "in_progress", "")
	sub(review, tenantA, "in_review", "in_progress", "")
	sub(bounty, tenantA, "bounty_paid", "resolved", "fixed")
	sub(otherB, tenantB, "in_dev", "in_progress", "")

	// The catalog's own rules.
	refused("open status with a reason", `INSERT INTO lifecycle_sub_statuses (id, tenant_id, canonical_status, closure_reason, key, name, color)
		VALUES (gen_random_uuid(), $1, 'confirmed', 'fixed', 'x_reason', 'x', 'blue')`, tenantA)
	refused("closed status without a reason", `INSERT INTO lifecycle_sub_statuses (id, tenant_id, canonical_status, key, name, color)
		VALUES (gen_random_uuid(), $1, 'accepted', 'x_accept', 'x', 'blue')`, tenantA)
	refused("pentest status", `INSERT INTO lifecycle_sub_statuses (id, tenant_id, canonical_status, key, name, color)
		VALUES (gen_random_uuid(), $1, 'draft', 'x_draft', 'x', 'blue')`, tenantA)
	refused("duplicate key", `INSERT INTO lifecycle_sub_statuses (id, tenant_id, canonical_status, key, name, color)
		VALUES (gen_random_uuid(), $1, 'confirmed', 'in_dev', 'x', 'blue')`, tenantA)
	refused("category change", `UPDATE lifecycle_sub_statuses SET canonical_status = 'confirmed' WHERE id = $1`, inDev)
	refused("closure reason change", `UPDATE lifecycle_sub_statuses SET closure_reason = 'mitigated' WHERE id = $1`, bounty)
	refused("key change", `UPDATE lifecycle_sub_statuses SET key = 'renamed' WHERE id = $1`, inDev)
	must(`UPDATE lifecycle_sub_statuses SET name = 'In development', color = 'green' WHERE id = $1`, inDev)

	must(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sast', 't', 'm', 'medium', 'lc-1', 'in_progress')`, finding, tenantA, assetA)
	subOf := func() string {
		t.Helper()
		var s *string
		if err := db.QueryRow(`SELECT sub_status_id::text FROM findings WHERE id = $1`, finding).Scan(&s); err != nil {
			t.Fatal(err)
		}
		if s == nil {
			return ""
		}
		return *s
	}

	// A sub-status of the finding's own tenant and status is kept.
	must(`UPDATE findings SET sub_status_id = $2 WHERE id = $1`, finding, inDev)
	if got := subOf(); got != inDev {
		t.Fatalf("sub-status = %q, want in_dev", got)
	}
	// Another tenant's sub-status, or one of another status, is refused.
	refused("another tenant's sub-status", `UPDATE findings SET sub_status_id = $2 WHERE id = $1`, finding, otherB)
	refused("a sub-status of another status", `UPDATE findings SET sub_status_id = $2 WHERE id = $1`, finding, bounty)
	if got := subOf(); got != inDev {
		t.Fatalf("a refused write changed the sub-status to %q", got)
	}
	// A move between sub-statuses of the same status.
	must(`UPDATE findings SET sub_status_id = $2 WHERE id = $1`, finding, review)

	// Any writer that moves the status without naming a sub-status lands on
	// the default label: the foreign key never fails a platform writer.
	must(`UPDATE findings SET status = 'fix_applied' WHERE id = $1`, finding)
	if got := subOf(); got != "" {
		t.Errorf("a status move kept sub-status %q", got)
	}

	// A move that names a closed sub-status needs its closure reason.
	must(`UPDATE findings SET status = 'resolved', closure_reason = 'fixed', verification = 'attested', resolved_at = NOW(), sub_status_id = $2 WHERE id = $1`, finding, bounty)
	if got := subOf(); got != bounty {
		t.Fatalf("closed sub-status = %q, want bounty_paid", got)
	}
	// The platform changing the closure reason drops the label it no longer fits.
	must(`UPDATE findings SET closure_reason = 'mitigated' WHERE id = $1`, finding)
	if got := subOf(); got != "" {
		t.Errorf("closure reason change kept sub-status %q", got)
	}
	// Choosing a closed sub-status against the finding's reason is refused.
	err := exec(`UPDATE findings SET sub_status_id = $2 WHERE id = $1`, finding, bounty)
	if err == nil || !strings.Contains(err.Error(), "closure reason") {
		t.Errorf("mismatching closed sub-status: err = %v", err)
	}

	// Versions: one draft per scheme; a published version never changes.
	const scheme = "bbbbbbbb-5555-4555-8555-111111111111"
	const v1 = "bbbbbbbb-6666-4666-8666-111111111111"
	must(`INSERT INTO lifecycle_schemes (id, tenant_id, key, name) VALUES ($1, $2, 'default', 'Default')`, scheme, tenantA)
	refused("second default scheme", `INSERT INTO lifecycle_schemes (id, tenant_id, key, name) VALUES (gen_random_uuid(), $1, 'other', 'Other')`, tenantA)
	must(`INSERT INTO lifecycle_scheme_versions (id, tenant_id, scheme_id, version, spec, spec_hash) VALUES ($1, $2, $3, 1, '{}', 'h1')`, v1, tenantA, scheme)
	refused("second draft", `INSERT INTO lifecycle_scheme_versions (id, tenant_id, scheme_id, version, spec, spec_hash) VALUES (gen_random_uuid(), $1, $2, 2, '{}', 'h2')`, tenantA, scheme)
	refused("version of another tenant's scheme", `INSERT INTO lifecycle_scheme_versions (id, tenant_id, scheme_id, version, spec, spec_hash) VALUES (gen_random_uuid(), $1, $2, 3, '{}', 'h3')`, tenantB, scheme)
	must(`UPDATE lifecycle_scheme_versions SET spec = '{"defaults": {}}', spec_hash = 'h1b' WHERE id = $1`, v1)
	must(`UPDATE lifecycle_scheme_versions SET state = 'published', published_at = NOW() WHERE id = $1`, v1)
	must(`UPDATE lifecycle_schemes SET published_version_id = $2 WHERE id = $1`, scheme, v1)
	refused("edit a published spec", `UPDATE lifecycle_scheme_versions SET spec = '{}' WHERE id = $1`, v1)
	refused("published back to draft", `UPDATE lifecycle_scheme_versions SET state = 'draft' WHERE id = $1`, v1)
	must(`UPDATE lifecycle_scheme_versions SET state = 'superseded' WHERE id = $1`, v1)
	refused("superseded back to published", `UPDATE lifecycle_scheme_versions SET state = 'published' WHERE id = $1`, v1)

	// Deleting the tenant removes its catalog, schemes and findings together.
	must(`DELETE FROM tenants WHERE id = $1`, tenantA)
	if err := db.QueryRow(`SELECT count(*) FROM lifecycle_sub_statuses WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 0 {
		t.Errorf("sub-statuses left after tenant delete: %d (%v)", n, err)
	}
}
