package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/audit/chainclassify"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	cryptopkg "github.com/openctemio/openctem/server/pkg/crypto"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The database chains every audit row in the inserting transaction over the
// whole row, and refuses to change audit rows (migration audit_log_db_chain).
// DB-gated: DATABASE_URL must name a migrated *_test database.

// A row written straight into audit_logs (as repository transactions and data
// migrations do) used to stay unchained. It is now chained, as version 2, and
// verifies.
func TestDBChain_DirectInsertIsChainedAndVerifies(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, actor := seedRebaselineTenant(ctx, t, db)

	logTenantEvents(ctx, t, svc, tenant, 1)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_logs (tenant_id, actor_id, action, resource_type, resource_id, result, severity, message, metadata, changes)
		VALUES ($1, $2, 'finding.duplicate_marked', 'finding', 'f-1', 'success', 'medium', 'Ünïcode message',
		        '{"big": 12345678901234567890, "f": 1.50, "nested": {"b": [1, "x"], "a": null}}', '{"before": {"s": "a"}}')`,
		tenant.String(), actor.String()); err != nil {
		t.Fatalf("direct insert: %v", err)
	}

	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM audit_logs l WHERE l.tenant_id = $1
		AND NOT EXISTS (SELECT 1 FROM audit_log_chain c WHERE c.audit_log_id = l.id)`, tenant.String()); n != 0 {
		t.Fatalf("%d audit rows of the tenant are unchained", n)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM audit_log_chain WHERE tenant_id = $1 AND hash_version = 2`, tenant.String()); n != 2 {
		t.Fatalf("version 2 chain rows = %d, want 2", n)
	}
	res, err := svc.VerifyChain(ctx, tenant, 0)
	if err != nil || !res.OK || res.Verified != 2 {
		t.Fatalf("verify: ok=%v verified=%d breaks=%+v err=%v", res != nil && res.OK, verified(res), breaks(res), err)
	}

	// The Go hash agrees with the database hash for every row.
	rows, err := db.QueryContext(ctx, `
		SELECT c.prev_hash, c.hash, audit_log_row_payload(l)
		  FROM audit_log_chain c JOIN audit_logs l ON l.id = c.audit_log_id
		 WHERE c.tenant_id = $1`, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var prev, hash, payload string
		if err := rows.Scan(&prev, &hash, &payload); err != nil {
			t.Fatal(err)
		}
		if got := cryptopkg.ComputeAuditRowHash(prev, payload); got != hash {
			t.Fatalf("Go hash %s != database hash %s for payload %s", got, hash, payload)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// Audit rows and chain rows cannot be edited or truncated; a chain row's
// hashes change only in a transaction that declares a rebaseline, and even
// then nothing but prev_hash and hash.
func TestDBChain_AuditRowsAreAppendOnly(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 1)

	for _, q := range []string{
		`UPDATE audit_logs SET actor_id = NULL WHERE tenant_id = $1`,
		`UPDATE audit_logs SET metadata = '{"forged": true}' WHERE tenant_id = $1`,
		`UPDATE audit_log_chain SET hash = repeat('0', 64) WHERE tenant_id = $1`,
	} {
		_, err := db.ExecContext(ctx, q, tenant.String())
		assertInsufficientPrivilege(t, q, err)
	}
	for _, q := range []string{`TRUNCATE audit_logs CASCADE`, `TRUNCATE audit_log_chain CASCADE`} {
		_, err := db.ExecContext(ctx, q)
		assertInsufficientPrivilege(t, q, err)
	}
	// A rebaseline transaction may not move a row or change its version.
	err := tamperChain(ctx, db, `UPDATE audit_log_chain SET hash_version = 1 WHERE tenant_id = $1`, tenant.String())
	assertInsufficientPrivilege(t, "hash_version under rebaseline", err)
	err = tamperChain(ctx, db, `UPDATE audit_log_chain SET tenant_id = gen_random_uuid() WHERE tenant_id = $1`, tenant.String())
	assertInsufficientPrivilege(t, "tenant_id under rebaseline", err)
}

// Deleting a user or an organization no longer rewrites their audit rows: the
// ids stay as recorded, the rows stay in their organization's chain, and the
// chain still verifies.
func TestDBChain_DeletingUserAndTenantKeepsAuditRows(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, actor := seedRebaselineTenant(ctx, t, db)
	ev := auditapp.NewSuccessEvent(auditdom.ActionSettingsUpdated, auditdom.ResourceTypeSettings, "s-1")
	if err := svc.LogEvent(ctx, auditapp.AuditContext{TenantID: tenant.String(), ActorID: actor.String()}, ev); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, actor.String()); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenant.String()); err != nil {
		t.Fatalf("delete tenant: %v", err)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND actor_id = $2`,
		tenant.String(), actor.String()); n != 1 {
		t.Fatalf("audit rows still naming the tenant and actor = %d, want 1", n)
	}
	res, err := svc.VerifyChain(ctx, tenant, 0)
	if err != nil || !res.OK {
		t.Fatalf("verify after deletes: ok=%v breaks=%+v err=%v", res != nil && res.OK, breaks(res), err)
	}
}

// A forged version 2 hash is not explained by any known defect, so it blocks
// a rebaseline; an intact version 2 chain verifies and a rebaseline of it
// rewrites nothing.
func TestDBChain_V2ForgeryIsUnexplained(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, admin := seedRebaselineTenant(ctx, t, db)
	other, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 3)
	logTenantEvents(ctx, t, svc, other, 2)

	rep, err := svc.ClassifyChain(ctx, tenant)
	if err != nil || rep.Counts.Verifies != 3 || !rep.RebaselineAllowed() {
		t.Fatalf("intact classify: %+v err=%v", rep, err)
	}
	res, err := svc.RebaselineChain(ctx, tenant, auditapp.AuditContext{ActorID: admin.String()})
	if err != nil || res.EntriesRewritten != 0 {
		t.Fatalf("rebaseline of an intact v2 chain: %+v err=%v", res, err)
	}

	chain := readChain(ctx, t, db, tenant)
	// An attacker who can declare a rebaseline rewrites a middle row's hash.
	if err := tamperChain(ctx, db, `UPDATE audit_log_chain SET hash = repeat('a', 64) WHERE audit_log_id = $1`,
		chain[1].AuditLogID); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	vr, err := svc.VerifyChain(ctx, tenant, 0)
	if err != nil || vr.OK {
		t.Fatalf("forged chain must not verify: ok=%v err=%v", vr != nil && vr.OK, err)
	}
	rep, err = svc.ClassifyChain(ctx, tenant)
	if err != nil || rep.Counts.Unexplained == 0 || rep.RebaselineAllowed() {
		t.Fatalf("forged v2 row must be unexplained and block a rebaseline: %+v err=%v", rep.Counts, err)
	}
	// The other tenant's chain is untouched.
	if ok, err := svc.VerifyChain(ctx, other, 0); err != nil || !ok.OK {
		t.Fatalf("other tenant chain: %+v err=%v", ok, err)
	}
}

// The classifier treats version 2 rows by the version 2 hash only.
func TestDBChain_ClassifyV2(t *testing.T) {
	payload := `[2, "id", null]`
	good := chainclassify.Row{AuditLogID: "id", HashVersion: 2, RowPayload: payload,
		Hash: cryptopkg.ComputeAuditRowHash("", payload)}
	if got := chainclassify.Classify(good).Class; got != chainclassify.Verifies {
		t.Fatalf("intact v2 row: %s", got)
	}
	edited := good
	edited.RowPayload = `[2, "id", "forged"]`
	if got := chainclassify.Classify(edited).Class; got != chainclassify.Unexplained {
		t.Fatalf("edited v2 row: %s", got)
	}
}

func assertInsufficientPrivilege(t *testing.T, what string, err error) {
	t.Helper()
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "42501" {
		t.Fatalf("%s: want insufficient_privilege, got %v", what, err)
	}
}

func verified(r *auditapp.ChainVerifyResult) int {
	if r == nil {
		return 0
	}
	return r.Verified
}

func breaks(r *auditapp.ChainVerifyResult) []auditapp.ChainBreak {
	if r == nil {
		return nil
	}
	return r.Breaks
}
