package audit_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The five tables that hold an organization's audit history (audit_logs,
// audit_log_chain and the evidence tables audit_chain_anchors,
// audit_chain_rebaselines, audit_chain_rebaseline_entries) may be changed only
// through the schema owner's functions audit_chain_prune_prefix and
// audit_chain_rebaseline_apply (migration audit_chain_owner_only). These
// tests run as the API role in CI (DATABASE_URL); see
// docs/architecture/audit-hash-chain.md.

var auditHistoryTables = []string{
	"audit_logs", "audit_log_chain", "audit_chain_anchors", "audit_chain_rebaselines", "audit_chain_rebaseline_entries",
}

// connectedAsAuditOwner reports whether the test connection owns audit_logs
// (a single-role run); CI connects as the API role.
func connectedAsAuditOwner(ctx context.Context, t *testing.T, db *postgres.DB) bool {
	t.Helper()
	var owner bool
	if err := db.QueryRowContext(ctx, `SELECT pg_has_role(current_user, relowner, 'USAGE')
		FROM pg_class WHERE oid = 'public.audit_logs'::regclass`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	return owner
}

func sqlStateOf(err error) string {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return string(pqErr.Code)
	}
	return ""
}

// chainWithEvidence gives a tenant a row in each of the five tables, written
// through the sanctioned paths only: two old rows (one pruned, which leaves a
// retention anchor) and a rebaseline that re-signs the remaining entry with
// the hashes it already has (a rebaseline record and one archived entry).
func chainWithEvidence(ctx context.Context, t *testing.T, db *postgres.DB) (shared.ID, []chainRow) {
	t.Helper()
	tenant, admin := seedRebaselineTenant(ctx, t, db)
	logOldTenantEvents(ctx, t, db, tenant, 2, 400)
	chain := readChain(ctx, t, db, tenant)
	if len(chain) != 2 {
		t.Fatalf("chain = %d entries, want 2", len(chain))
	}
	if _, err := db.ExecContext(ctx, `SELECT audit_chain_prune_prefix($1, $2, $3, $4, 'test://archive', repeat('ab', 32))`,
		tenant.String(), chain[0].Position, chain[0].Hash, pq.Array([]string{chain[0].AuditLogID})); err != nil {
		t.Fatalf("prune through the function: %v", err)
	}
	c := chain[1]
	if _, err := db.ExecContext(ctx, `SELECT audit_chain_rebaseline_apply($1, $2, $3, 1, $4, $5, $6, $7, $8, $7, $8)`,
		shared.NewID().String(), tenant.String(), admin.String(), c.Position,
		pq.Array([]string{c.AuditLogID}), pq.Array([]int64{c.Position}),
		pq.Array([]string{c.PrevHash}), pq.Array([]string{c.Hash})); err != nil {
		t.Fatalf("rebaseline through the function: %v", err)
	}
	for _, tbl := range auditHistoryTables {
		if n := countRows(ctx, t, db, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, tenant.String()); n == 0 {
			t.Fatalf("%s: no row for the tenant", tbl)
		}
	}
	return tenant, readChain(ctx, t, db, tenant)
}

// Every UPDATE, DELETE and TRUNCATE on each of the five tables is refused for
// the API role, with or without the setting the owner's functions use; so is
// an INSERT into an evidence table. The history is unchanged afterwards and
// still verifies.
func TestAuditChain_EveryDirectWriteIsRefused_DB(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	owner := connectedAsAuditOwner(ctx, t, db)
	if owner {
		t.Log("connected as the schema owner: only the trigger refusals are checked (CI runs this as the API role)")
	}
	tenant, chain := chainWithEvidence(ctx, t, db)
	before := map[string]int{}
	for _, tbl := range auditHistoryTables {
		before[tbl] = countRows(ctx, t, db, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, tenant.String())
	}

	stmts := map[string][]string{
		"audit_logs": {
			`UPDATE audit_logs SET message = 'forged' WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
		},
		"audit_log_chain": {
			`UPDATE audit_log_chain SET hash = repeat('ab', 32) WHERE tenant_id = $1`,
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
		},
		"audit_chain_anchors": {
			`UPDATE audit_chain_anchors SET anchor_hash = repeat('ab', 32) WHERE tenant_id = $1`,
			`DELETE FROM audit_chain_anchors WHERE tenant_id = $1`,
			`INSERT INTO audit_chain_anchors (tenant_id, anchor_hash, last_chain_position, pruned_count,
				oldest_logged_at, newest_logged_at, archive_path, archive_sha256)
			 VALUES ($1, repeat('cd', 32), 99, 1, now(), now(), 'x', repeat('ef', 32))`,
		},
		"audit_chain_rebaselines": {
			`UPDATE audit_chain_rebaselines SET entries_rewritten = 0 WHERE tenant_id = $1`,
			`DELETE FROM audit_chain_rebaselines WHERE tenant_id = $1`,
			`INSERT INTO audit_chain_rebaselines (id, tenant_id, entries_total, entries_rewritten)
			 VALUES (gen_random_uuid(), $1, 0, 0)`,
		},
		"audit_chain_rebaseline_entries": {
			`UPDATE audit_chain_rebaseline_entries SET old_hash = repeat('ab', 32) WHERE tenant_id = $1`,
			`DELETE FROM audit_chain_rebaseline_entries WHERE tenant_id = $1`,
		},
	}
	for _, tbl := range auditHistoryTables {
		for _, op := range []string{"", "prune", "rebaseline"} {
			for _, q := range append(stmts[tbl], `TRUNCATE `+tbl) {
				verb := strings.Fields(q)[0]
				name := tbl + "/" + verb
				if op != "" {
					name += "/with " + op + " setting"
				}
				t.Run(name, func(t *testing.T) {
					// An INSERT is the owner's own right (no trigger refuses it), and
					// with the functions' setting so are the deletes and updates
					// those functions make: only the API role is refused there.
					if owner && (verb == "INSERT" || op != "") {
						t.Skip("the schema owner may do this; the API role may not")
					}
					tx, err := db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback() }()
					if op != "" {
						if _, err := tx.ExecContext(ctx, `SELECT set_config('openctem.audit_chain_op', $1, true)`, op); err != nil {
							t.Fatal(err)
						}
					}
					var args []any
					if strings.Contains(q, "$1") {
						args = []any{tenant.String()}
					}
					_, err = tx.ExecContext(ctx, q, args...)
					if err == nil {
						t.Fatalf("allowed: %s", q)
					}
					// The API role fails on its grants (or, for the owner, the
					// guard trigger; a TRUNCATE of audit_logs may first meet the
					// foreign keys that reference it).
					if s := sqlStateOf(err); !owner && s != "42501" {
						t.Fatalf("%s: SQLSTATE %s (%v), want 42501", q, s, err)
					}
				})
			}
		}
	}

	for _, tbl := range auditHistoryTables {
		if n := countRows(ctx, t, db, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, tenant.String()); n != before[tbl] {
			t.Errorf("%s: %d rows, want %d", tbl, n, before[tbl])
		}
	}
	if got := readChain(ctx, t, db, tenant); len(got) != len(chain) || got[0].Hash != chain[0].Hash {
		t.Fatalf("chain changed")
	}
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	if res, err := svc.VerifyChain(ctx, tenant, 0); err != nil || !res.OK {
		t.Fatalf("verify after refused writes = %+v, err %v", res, err)
	}
}

// The two functions bind every statement to the one chain named: entries of
// another organization, a stale read, a forged version 2 hash or a recent
// prefix are refused and nothing changes.
func TestAuditChain_FunctionsRefuseForeignAndStaleInput_DB(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	a, admin := seedRebaselineTenant(ctx, t, db)
	b, _ := seedRebaselineTenant(ctx, t, db)
	logOldTenantEvents(ctx, t, db, a, 2, 400)
	logOldTenantEvents(ctx, t, db, b, 2, 400)
	chainA, chainB := readChain(ctx, t, db, a), readChain(ctx, t, db, b)

	prune := func(tenant shared.ID, pos int64, hash string, ids ...string) error {
		_, err := db.ExecContext(ctx, `SELECT audit_chain_prune_prefix($1, $2, $3, $4, 'test://archive', repeat('ab', 32))`,
			tenant.String(), pos, hash, pq.Array(ids))
		return err
	}
	rebaseline := func(tenant shared.ID, last int64, rows []chainRow, newHash string) error {
		ids, pos, prev, old, nh := []string{}, []int64{}, []string{}, []string{}, []string{}
		for _, r := range rows {
			ids, pos, prev, old = append(ids, r.AuditLogID), append(pos, r.Position), append(prev, r.PrevHash), append(old, r.Hash)
			h := r.Hash
			if newHash != "" {
				h = newHash
			}
			nh = append(nh, h)
		}
		_, err := db.ExecContext(ctx, `SELECT audit_chain_rebaseline_apply($1, $2, $3, $4, $5, $6, $7, $8, $9, $8, $10)`,
			shared.NewID().String(), tenant.String(), admin.String(), len(rows), last,
			pq.Array(ids), pq.Array(pos), pq.Array(prev), pq.Array(old), pq.Array(nh))
		return err
	}
	cases := []struct {
		name  string
		run   func() error
		state string
	}{
		{"prune of another organization's rows under this one", func() error {
			return prune(a, chainB[0].Position, chainB[0].Hash, chainB[0].AuditLogID)
		}, "OC409"},
		{"prune of this prefix plus another organization's row", func() error {
			return prune(a, chainA[0].Position, chainA[0].Hash, chainA[0].AuditLogID, chainB[0].AuditLogID)
		}, "OC409"},
		{"prune with a stale anchor hash", func() error {
			return prune(a, chainA[0].Position, strings.Repeat("a", 64), chainA[0].AuditLogID)
		}, "OC409"},
		{"prune of a non-prefix", func() error {
			return prune(a, chainA[1].Position, chainA[1].Hash, chainA[1].AuditLogID)
		}, "OC409"},
		{"rebaseline of another organization's entries under this one", func() error {
			return rebaseline(a, chainA[1].Position, chainB, "")
		}, "OC409"},
		{"rebaseline with a stale tail", func() error {
			return rebaseline(a, chainA[0].Position, chainA[:1], "")
		}, "OC409"},
		{"rebaseline with a forged version 2 hash", func() error {
			return rebaseline(a, chainA[1].Position, chainA[1:], strings.Repeat("e", 64))
		}, "22023"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if err == nil || sqlStateOf(err) != c.state {
				t.Fatalf("err = %v (SQLSTATE %s), want SQLSTATE %s", err, sqlStateOf(err), c.state)
			}
		})
	}

	// A recent prefix is refused by the database clock.
	c, _ := seedRebaselineTenant(ctx, t, db)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	logTenantEvents(ctx, t, svc, c, 1)
	chainC := readChain(ctx, t, db, c)
	if err := prune(c, chainC[0].Position, chainC[0].Hash, chainC[0].AuditLogID); sqlStateOf(err) != "23514" {
		t.Fatalf("recent prune: err = %v, want SQLSTATE 23514", err)
	}
	// A suspended organization is on hold.
	if _, err := db.ExecContext(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, b.String()); err != nil {
		t.Fatal(err)
	}
	if err := prune(b, chainB[0].Position, chainB[0].Hash, chainB[0].AuditLogID); sqlStateOf(err) != "OC409" {
		t.Fatalf("prune of a suspended organization: err = %v, want SQLSTATE OC409", err)
	}

	for _, tc := range []struct {
		id    shared.ID
		chain []chainRow
	}{{a, chainA}, {b, chainB}, {c, chainC}} {
		got := readChain(ctx, t, db, tc.id)
		if len(got) != len(tc.chain) {
			t.Fatalf("refused calls changed a chain: %d entries, want %d", len(got), len(tc.chain))
		}
		for i := range got {
			if got[i] != tc.chain[i] {
				t.Fatalf("refused calls rewrote entry %d", i)
			}
		}
		for _, tbl := range []string{"audit_chain_anchors", "audit_chain_rebaselines", "audit_chain_rebaseline_entries"} {
			if n := countRows(ctx, t, db, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, tc.id.String()); n != 0 {
				t.Fatalf("refused calls left %d rows in %s", n, tbl)
			}
		}
	}
}

// Deleting an organization (the real tenant delete, as the API role) works
// with the guard in place and keeps the organization's audit history: the
// five tables have no foreign key to tenants, and the rows age out through
// retention like any other. Another organization's chain is not touched and
// still verifies.
func TestAuditChain_OrganizationDeletionKeepsHistoryAndOtherChains_DB(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	gone, goneChain := chainWithEvidence(ctx, t, db)
	logTenantEvents(ctx, t, svc, gone, 2)
	other, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, other, 3)
	otherChain := readChain(ctx, t, db, other)
	before := map[string]int{}
	for _, tbl := range auditHistoryTables {
		before[tbl] = countRows(ctx, t, db, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, gone.String())
	}

	if err := postgres.NewTenantRepository(db).Delete(ctx, gone); err != nil {
		t.Fatalf("delete organization: %v", err)
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, gone.String()).Scan(&exists); err != nil || exists {
		t.Fatalf("organization still there (exists %v, err %v)", exists, err)
	}

	for _, tbl := range auditHistoryTables {
		if n := countRows(ctx, t, db, `SELECT count(*) FROM `+tbl+` WHERE tenant_id = $1`, gone.String()); n != before[tbl] {
			t.Errorf("%s: %d rows of the deleted organization, want %d (kept)", tbl, n, before[tbl])
		}
	}
	if got := readChain(ctx, t, db, gone); len(got) != len(goneChain)+2 || got[0] != goneChain[0] {
		t.Fatalf("deleted organization's chain changed")
	}
	got := readChain(ctx, t, db, other)
	if len(got) != len(otherChain) {
		t.Fatalf("other organization's chain: %d entries, want %d", len(got), len(otherChain))
	}
	for i := range got {
		if got[i] != otherChain[i] {
			t.Fatalf("other organization's entry %d changed", i)
		}
	}
	for _, id := range []shared.ID{other, gone} {
		if res, err := svc.VerifyChain(ctx, id, 0); err != nil || !res.OK {
			t.Fatalf("verify %s after the deletion = %+v, err %v", id, res, err)
		}
	}
}
