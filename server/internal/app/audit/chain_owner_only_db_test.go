package audit_test

import (
	"context"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The API's database role may append audit rows and read them, nothing more:
// deleting or rewriting audit history goes only through the schema owner's
// functions audit_chain_prune_prefix (365-day floor, anchored prefix) and
// audit_chain_rebaseline_apply (archived, checked hashes). Before migration
// audit_chain_owner_only the API role could delete rows from the middle of a
// chain, set openctem.audit_rebaseline, re-hash the rest and delete the
// rebaseline evidence, and verification still passed.
//
// DB-gated: DATABASE_URL must name a migrated *_test database. CI connects as
// the least-privilege API role; a local run as the schema owner checks what
// the triggers alone refuse (an owner can always change its own tables).

func TestAuditChain_APIRoleCannotRewriteHistory_DB(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 4)
	chain := readChain(ctx, t, db, tenant)
	if len(chain) != 4 {
		t.Fatalf("chain = %d entries, want 4", len(chain))
	}
	middle := chain[1].AuditLogID

	var owner bool
	if err := db.QueryRowContext(ctx, `SELECT pg_has_role(current_user, relowner, 'USAGE')
		FROM pg_class WHERE oid = 'public.audit_logs'::regclass`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner {
		t.Log("connected as the schema owner: only the trigger refusals are checked")
	}

	attacks := []struct {
		name string
		// ownerToo: refused for the owner as well (by a trigger); otherwise
		// only the API role is refused (by its grants).
		ownerToo bool
		stmts    []string
	}{
		{"rewrite chain hashes with the old rebaseline setting", true, []string{
			`SET LOCAL openctem.audit_rebaseline = 'on'`,
			`UPDATE audit_log_chain SET hash = repeat('ab', 32) WHERE tenant_id = $1`,
		}},
		{"rewrite chain hashes with the functions' setting", false, []string{
			`SET LOCAL openctem.audit_chain_op = 'rebaseline'`,
			`UPDATE audit_log_chain SET hash = repeat('ab', 32) WHERE tenant_id = $1`,
		}},
		{"delete a chain row", true, []string{
			`DELETE FROM audit_log_chain WHERE tenant_id = $1 AND audit_log_id = $2`,
		}},
		{"delete an audit row", true, []string{
			`DELETE FROM audit_logs WHERE tenant_id = $1 AND id = $2`,
		}},
		{"delete with the functions' setting", false, []string{
			`SET LOCAL openctem.audit_chain_op = 'prune'`,
			`DELETE FROM audit_log_chain WHERE tenant_id = $1 AND audit_log_id = $2`,
		}},
		{"update an audit row", true, []string{
			`UPDATE audit_logs SET message = 'forged' WHERE tenant_id = $1 AND id = $2`,
		}},
		{"delete rebaseline records", true, []string{
			`DELETE FROM audit_chain_rebaselines WHERE tenant_id = $1`,
		}},
		{"delete rebaseline entries", true, []string{
			`DELETE FROM audit_chain_rebaseline_entries WHERE tenant_id = $1`,
		}},
		{"delete retention anchors", true, []string{
			`DELETE FROM audit_chain_anchors WHERE tenant_id = $1`,
		}},
		{"plant a retention anchor", false, []string{
			`INSERT INTO audit_chain_anchors (tenant_id, anchor_hash, last_chain_position, pruned_count,
				oldest_logged_at, newest_logged_at, archive_path, archive_sha256)
			 VALUES ($1, repeat('cd', 32), 1, 1, now(), now(), 'x', repeat('ef', 32))`,
		}},
		{"plant a rebaseline record", false, []string{
			`INSERT INTO audit_chain_rebaselines (id, tenant_id, entries_total, entries_rewritten)
			 VALUES (gen_random_uuid(), $1, 0, 0)`,
		}},
		{"truncate the chain", true, []string{`TRUNCATE audit_log_chain`}},
		{"truncate rebaseline entries", true, []string{`TRUNCATE audit_chain_rebaseline_entries`}},
		{"truncate retention anchors", true, []string{`TRUNCATE audit_chain_anchors`}},
	}
	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			if owner && !a.ownerToo {
				t.Skip("the schema owner may do this; the API role may not")
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			var last error
			for _, q := range a.stmts {
				var args []any
				switch {
				case strings.Contains(q, "$2"):
					args = []any{tenant.String(), middle}
				case strings.Contains(q, "$1"):
					args = []any{tenant.String()}
				}
				if _, last = tx.ExecContext(ctx, q, args...); last != nil {
					break
				}
			}
			if last == nil {
				t.Fatalf("allowed: %v", a.stmts)
			}
		})
	}

	if got := readChain(ctx, t, db, tenant); len(got) != 4 || got[1].Hash != chain[1].Hash {
		t.Fatalf("chain changed: %d entries", len(got))
	}
	res, err := svc.VerifyChain(ctx, tenant, 0)
	if err != nil || !res.OK {
		t.Fatalf("verify after refused attacks = %+v, err %v", res, err)
	}
}

// A deletion that bypasses the functions (here the superuser with triggers
// off, the one path left) is caught by verification: the chain no longer
// links where the row was.
func TestAuditChain_DeletionOutsideTheFunctionsIsDetected_DB(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	tenant, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 4)
	chain := readChain(ctx, t, db, tenant)

	tx, err := testdb.OpenAdmin(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`SET LOCAL session_replication_role = replica`,
		`DELETE FROM audit_log_chain WHERE tenant_id = $1 AND audit_log_id = $2`,
		`DELETE FROM audit_logs WHERE tenant_id = $1 AND id = $2`,
	} {
		var args []any
		if strings.Contains(q, "$1") {
			args = []any{tenant.String(), chain[1].AuditLogID}
		}
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	res, err := svc.VerifyChain(ctx, tenant, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || len(res.Breaks) == 0 {
		t.Fatalf("verify after a deletion = %+v, want a break", res)
	}
}
