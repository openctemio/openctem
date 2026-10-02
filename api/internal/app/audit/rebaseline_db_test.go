package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Rebaselining overwrites the tamper-evident chain. These tests pin down what
// makes that defensible: the overwritten hashes are archived in the same
// transaction as the rewrite, the rewrite is all-or-nothing, the action leaves
// an audit_logs row of its own, and only the caller's tenant is touched.
//
// DB-gated: DATABASE_URL must name a migrated *_test database.

type chainRow struct {
	AuditLogID string
	PrevHash   string
	Hash       string
	Position   int64
}

// seedRebaselineTenant creates a tenant and an admin user and registers
// cleanup for everything the audit trail writes for that tenant.
func seedRebaselineTenant(ctx context.Context, t *testing.T, db *postgres.DB) (tenantID, userID shared.ID) {
	t.Helper()
	tenantID = shared.NewID()
	userID = shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'rebaseline test', $2)`,
		tenantID.String(), "rebaseline-"+tenantID.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'Rebaseline Admin')`,
		userID.String(), "rebaseline-"+userID.String()+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		tid := tenantID.String()
		_, _ = db.ExecContext(bg, `DELETE FROM audit_chain_rebaseline_entries WHERE tenant_id = $1`, tid)
		_, _ = db.ExecContext(bg, `DELETE FROM audit_chain_rebaselines WHERE tenant_id = $1`, tid)
		_, _ = db.ExecContext(bg, `DELETE FROM audit_log_chain WHERE tenant_id = $1`, tid)
		_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid)
		_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tid)
		_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, userID.String())
	})
	return tenantID, userID
}

// logTenantEvents writes n chained audit events for the tenant through the
// production LogEvent path.
func logTenantEvents(ctx context.Context, t *testing.T, svc *auditapp.AuditService, tenantID shared.ID, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := auditapp.NewSuccessEvent(auditdom.ActionSettingsUpdated, auditdom.ResourceTypeSettings, shared.NewID().String())
		if err := svc.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String()}, ev); err != nil {
			t.Fatalf("log event %d: %v", i, err)
		}
	}
}

func readChain(ctx context.Context, t *testing.T, db *postgres.DB, tenantID shared.ID) []chainRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT audit_log_id, prev_hash, hash, chain_position
		  FROM audit_log_chain WHERE tenant_id = $1 ORDER BY chain_position`, tenantID.String())
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []chainRow
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.AuditLogID, &r.PrevHash, &r.Hash, &r.Position); err != nil {
			t.Fatalf("scan chain: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate chain: %v", err)
	}
	return out
}

func countRows(ctx context.Context, t *testing.T, db *postgres.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		t.Fatalf("count (%s): %v", q, err)
	}
	return n
}

func TestRebaselineChain_ArchivesOldHashesAndAudits(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	tenantA, admin := seedRebaselineTenant(ctx, t, db)
	tenantB, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenantA, 3)
	logTenantEvents(ctx, t, svc, tenantB, 2)

	// Give entry 2 of tenant A a hash its data does not produce, and link
	// entry 3 to it — the shape the legacy timestamp-precision bug left. Both
	// must be re-signed; entry 1 is intact and must be left alone.
	chainA := readChain(ctx, t, db, tenantA)
	if len(chainA) != 3 {
		t.Fatalf("tenant A chain has %d entries, want 3", len(chainA))
	}
	bogus := strings.Repeat("0", 64)
	if _, err := db.ExecContext(ctx, `UPDATE audit_log_chain SET hash = $2 WHERE audit_log_id = $1`,
		chainA[1].AuditLogID, bogus); err != nil {
		t.Fatalf("corrupt entry 2: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE audit_log_chain SET prev_hash = $2 WHERE audit_log_id = $1`,
		chainA[2].AuditLogID, bogus); err != nil {
		t.Fatalf("relink entry 3: %v", err)
	}
	chainA = readChain(ctx, t, db, tenantA)
	if res, err := svc.VerifyChain(ctx, tenantA, 0); err != nil || res.OK {
		t.Fatalf("precondition: the corrupted chain must fail verification (ok=%v err=%v)", res != nil && res.OK, err)
	}
	chainBBefore := readChain(ctx, t, db, tenantB)

	res, err := svc.RebaselineChain(ctx, tenantA, auditapp.AuditContext{
		TenantID:   tenantA.String(),
		ActorID:    admin.String(),
		ActorEmail: "rebaseline-admin@example.test",
	})
	if err != nil {
		t.Fatalf("RebaselineChain: %v", err)
	}
	if res.EntriesTotal != 3 || res.EntriesRewritten != 2 {
		t.Fatalf("result total=%d rewritten=%d, want 3/2", res.EntriesTotal, res.EntriesRewritten)
	}
	if _, err := shared.IDFromString(res.RebaselineID); err != nil {
		t.Fatalf("rebaseline id %q is not a UUID", res.RebaselineID)
	}

	// The chain verifies again, including the rebaseline's own audit row,
	// which is appended after the rewrite.
	after, err := svc.VerifyChain(ctx, tenantA, 0)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !after.OK {
		t.Fatalf("chain still broken after rebaseline: %+v", after.Breaks)
	}
	if after.Total != 4 {
		t.Errorf("chain has %d entries after rebaseline, want 4 (3 + the rebaseline event)", after.Total)
	}

	// Header row.
	var actorID, gotTenant string
	var total, rewritten int
	if err := db.QueryRowContext(ctx, `
		SELECT tenant_id, COALESCE(actor_id::text, ''), entries_total, entries_rewritten
		  FROM audit_chain_rebaselines WHERE id = $1`, res.RebaselineID).
		Scan(&gotTenant, &actorID, &total, &rewritten); err != nil {
		t.Fatalf("no archive header for the rebaseline: %v", err)
	}
	if gotTenant != tenantA.String() || actorID != admin.String() || total != 3 || rewritten != 2 {
		t.Errorf("header tenant=%s actor=%s total=%d rewritten=%d, want %s/%s/3/2",
			gotTenant, actorID, total, rewritten, tenantA, admin)
	}

	// Exactly the rewritten entries are archived, with the hashes they had.
	chainAAfter := readChain(ctx, t, db, tenantA)
	byID := make(map[string]chainRow, len(chainAAfter))
	for _, r := range chainAAfter {
		byID[r.AuditLogID] = r
	}
	rows, err := db.QueryContext(ctx, `
		SELECT audit_log_id, chain_position, old_prev_hash, old_hash, new_prev_hash, new_hash, tenant_id
		  FROM audit_chain_rebaseline_entries WHERE rebaseline_id = $1 ORDER BY chain_position`, res.RebaselineID)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var archived []chainRow
	for rows.Next() {
		var r chainRow
		var newPrev, newHash, tid string
		var oldPrev string
		if err := rows.Scan(&r.AuditLogID, &r.Position, &oldPrev, &r.Hash, &newPrev, &newHash, &tid); err != nil {
			t.Fatalf("scan archive: %v", err)
		}
		r.PrevHash = oldPrev
		if tid != tenantA.String() {
			t.Errorf("archive entry tenant = %s, want %s", tid, tenantA)
		}
		now, ok := byID[r.AuditLogID]
		if !ok || now.Position != r.Position {
			t.Fatalf("archive entry %s at position %d does not map to the chain", r.AuditLogID, r.Position)
		}
		if newPrev != now.PrevHash || newHash != now.Hash {
			t.Errorf("archive new hashes for position %d do not match the chain now", r.Position)
		}
		archived = append(archived, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate archive: %v", err)
	}
	if len(archived) != 2 {
		t.Fatalf("archived %d entries, want exactly the 2 rewritten ones", len(archived))
	}
	for i, want := range chainA[1:] {
		got := archived[i]
		if got.AuditLogID != want.AuditLogID || got.PrevHash != want.PrevHash || got.Hash != want.Hash {
			t.Errorf("archive[%d] = %+v, want the pre-rebaseline values %+v", i, got, want)
		}
	}
	if chainAAfter[0] != chainA[0] {
		t.Errorf("entry 1 was intact and must not be rewritten: before %+v after %+v", chainA[0], chainAAfter[0])
	}

	// One audit_logs row records the rebaseline.
	var (
		evID, evActor, evSeverity, evResource string
		evMeta                                []byte
	)
	if err := db.QueryRowContext(ctx, `
		SELECT id, COALESCE(actor_id::text, ''), severity, resource_id, metadata
		  FROM audit_logs WHERE tenant_id = $1 AND action = $2`,
		tenantA.String(), string(auditdom.ActionAuditChainRebaselined)).
		Scan(&evID, &evActor, &evSeverity, &evResource, &evMeta); err != nil {
		t.Fatalf("no %s audit row: %v", auditdom.ActionAuditChainRebaselined, err)
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`,
		tenantA.String(), string(auditdom.ActionAuditChainRebaselined)); n != 1 {
		t.Errorf("%d rebaseline audit rows, want 1", n)
	}
	if evActor != admin.String() || evSeverity != string(auditdom.SeverityCritical) || evResource != res.RebaselineID {
		t.Errorf("audit row actor=%s severity=%s resource=%s, want %s/critical/%s",
			evActor, evSeverity, evResource, admin, res.RebaselineID)
	}
	var meta map[string]any
	if err := json.Unmarshal(evMeta, &meta); err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta["entries_total"] != float64(3) || meta["entries_rewritten"] != float64(2) || meta["rebaseline_id"] != res.RebaselineID {
		t.Errorf("audit metadata = %v, want entries_total=3 entries_rewritten=2 rebaseline_id=%s", meta, res.RebaselineID)
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_log_chain WHERE audit_log_id = $1`, evID); n != 1 {
		t.Errorf("the rebaseline audit row is not on the chain")
	}

	// Tenant B is untouched.
	chainBAfter := readChain(ctx, t, db, tenantB)
	if len(chainBAfter) != len(chainBBefore) {
		t.Fatalf("tenant B chain length changed: %d -> %d", len(chainBBefore), len(chainBAfter))
	}
	for i := range chainBBefore {
		if chainBBefore[i] != chainBAfter[i] {
			t.Errorf("tenant B entry %d changed: %+v -> %+v", i, chainBBefore[i], chainBAfter[i])
		}
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_chain_rebaselines WHERE tenant_id = $1`, tenantB.String()); n != 0 {
		t.Errorf("tenant B has %d rebaseline records, want 0", n)
	}
}

// A rebaseline over an intact chain is still recorded, with zero rewrites.
func TestRebaselineChain_IntactChainRecordsZeroRewrites(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	tenantID, admin := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenantID, 2)

	res, err := svc.RebaselineChain(ctx, tenantID, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: admin.String()})
	if err != nil {
		t.Fatalf("RebaselineChain: %v", err)
	}
	if res.EntriesTotal != 2 || res.EntriesRewritten != 0 {
		t.Fatalf("total=%d rewritten=%d, want 2/0", res.EntriesTotal, res.EntriesRewritten)
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_chain_rebaselines WHERE id = $1 AND entries_rewritten = 0`, res.RebaselineID); n != 1 {
		t.Errorf("no header row for a zero-rewrite rebaseline")
	}
	if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`,
		tenantID.String(), string(auditdom.ActionAuditChainRebaselined)); n != 1 {
		t.Errorf("%d rebaseline audit rows, want 1", n)
	}
}

// The rewrite is one transaction: if any part fails, the chain keeps every old
// hash and nothing is archived.
func TestApplyChainRebaseline_IsAtomic(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	tenantID, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenantID, 3)
	before := readChain(ctx, t, db, tenantID)

	rewrite := func(i int, newHash string) auditdom.ChainRewrite {
		return auditdom.ChainRewrite{
			AuditLogID:    shared.MustIDFromString(before[i].AuditLogID),
			ChainPosition: before[i].Position,
			OldPrevHash:   before[i].PrevHash,
			OldHash:       before[i].Hash,
			NewPrevHash:   before[i].PrevHash,
			NewHash:       newHash,
		}
	}
	base := func() auditdom.ChainRebaseline {
		return auditdom.ChainRebaseline{
			ID:                shared.NewID(),
			TenantID:          tenantID,
			EntriesTotal:      3,
			LastChainPosition: before[2].Position,
		}
	}
	assertUnchanged := func(t *testing.T, rbID shared.ID) {
		t.Helper()
		now := readChain(ctx, t, db, tenantID)
		for i := range before {
			if now[i] != before[i] {
				t.Errorf("entry %d changed by a failed rebaseline: %+v -> %+v", i, before[i], now[i])
			}
		}
		if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_chain_rebaselines WHERE id = $1`, rbID.String()); n != 0 {
			t.Errorf("failed rebaseline left a header row")
		}
		if n := countRows(ctx, t, db, `SELECT count(*) FROM audit_chain_rebaseline_entries WHERE rebaseline_id = $1`, rbID.String()); n != 0 {
			t.Errorf("failed rebaseline left %d archive rows", n)
		}
	}

	t.Run("a failing write mid-rewrite rolls everything back", func(t *testing.T) {
		rb := base()
		// The first rewrite is valid; the second violates the hash CHECK.
		rb.Rewrites = []auditdom.ChainRewrite{rewrite(0, strings.Repeat("a", 64)), rewrite(1, "not-a-hash")}
		if err := repo.ApplyChainRebaseline(ctx, rb); err == nil {
			t.Fatal("expected the invalid hash to fail the rebaseline")
		}
		assertUnchanged(t, rb.ID)
	})

	t.Run("an entry that changed since it was read is a conflict", func(t *testing.T) {
		rb := base()
		stale := rewrite(1, strings.Repeat("b", 64))
		stale.OldHash = strings.Repeat("c", 64)
		rb.Rewrites = []auditdom.ChainRewrite{rewrite(0, strings.Repeat("a", 64)), stale}
		err := repo.ApplyChainRebaseline(ctx, rb)
		if !errors.Is(err, auditdom.ErrChainRebaselineConflict) {
			t.Fatalf("err = %v, want ErrChainRebaselineConflict", err)
		}
		assertUnchanged(t, rb.ID)
	})

	t.Run("a chain that grew past the walked tail is a conflict", func(t *testing.T) {
		rb := base()
		rb.LastChainPosition = before[1].Position
		rb.Rewrites = []auditdom.ChainRewrite{rewrite(0, strings.Repeat("a", 64))}
		err := repo.ApplyChainRebaseline(ctx, rb)
		if !errors.Is(err, auditdom.ErrChainRebaselineConflict) {
			t.Fatalf("err = %v, want ErrChainRebaselineConflict", err)
		}
		assertUnchanged(t, rb.ID)
	})

	t.Run("another tenant's entry cannot be rewritten", func(t *testing.T) {
		other, _ := seedRebaselineTenant(ctx, t, db)
		rb := base()
		rb.TenantID = other
		rb.LastChainPosition = 0
		rb.Rewrites = []auditdom.ChainRewrite{rewrite(0, strings.Repeat("a", 64))}
		err := repo.ApplyChainRebaseline(ctx, rb)
		if !errors.Is(err, auditdom.ErrChainRebaselineConflict) {
			t.Fatalf("err = %v, want ErrChainRebaselineConflict", err)
		}
		assertUnchanged(t, rb.ID)
	})
}
