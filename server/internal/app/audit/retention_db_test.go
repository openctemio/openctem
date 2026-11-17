package audit_test

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/infra/storage"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Audit retention prunes the oldest prefix of a hash chain without breaking
// verification: the pruned rows are archived, the chain head they leave is
// anchored, and verify / classify / rebaseline / append all continue from the
// anchor. Before this, the retention DELETE hit the chain's ON DELETE
// RESTRICT foreign key and failed on every run.

// logOldTenantEvents writes n audit rows logged daysAgo days ago (the chain
// trigger chains them like any other). Retention only ever removes rows older
// than 365 days, a floor the database function enforces against its own
// clock, so the rows a test prunes are written old.
func logOldTenantEvents(ctx context.Context, t *testing.T, db *postgres.DB, tenantID shared.ID, n, daysAgo int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := db.ExecContext(ctx, `
			INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, result, severity, logged_at)
			VALUES ($1, 'settings.updated', 'settings', $2, 'success', 'low', now() - make_interval(days => $3))`,
			tenantID.String(), shared.NewID().String(), daysAgo); err != nil {
			t.Fatalf("log old event %d: %v", i, err)
		}
	}
}

func TestPruneChain_ArchivesAnchorsAndChainStillVerifies(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	tenantA, _ := seedRebaselineTenant(ctx, t, db)
	tenantB, _ := seedRebaselineTenant(ctx, t, db)
	tenantC, _ := seedRebaselineTenant(ctx, t, db)

	logOldTenantEvents(ctx, t, db, tenantA, 3, 500)
	logOldTenantEvents(ctx, t, db, tenantB, 2, 500)
	logOldTenantEvents(ctx, t, db, tenantC, 2, 400)
	logTenantEvents(ctx, t, svc, tenantA, 2)

	before := readChain(ctx, t, db, tenantA)
	if len(before) != 5 {
		t.Fatalf("tenant A chain = %d entries, want 5", len(before))
	}

	dir := t.TempDir()
	cfg := auditapp.RetentionConfig{
		RetentionDays: 30, // raised to the 365-day minimum
		Store:         storage.NewLocalStorage(dir),
	}

	// No archive location: nothing is deleted.
	if _, _, err := svc.PruneChain(ctx, tenantA, auditapp.RetentionConfig{}); !errors.Is(err, auditapp.ErrNoAuditArchiveStore) {
		t.Fatalf("prune without archive dir: err = %v", err)
	}
	if n := len(readChain(ctx, t, db, tenantA)); n != 5 {
		t.Fatalf("pruned without an archive: %d entries left", n)
	}

	n, archives, err := svc.PruneChain(ctx, tenantA, cfg)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 3 || len(archives) != 1 {
		t.Fatalf("pruned %d entries into %d archives, want 3 into 1", n, len(archives))
	}

	// Archive: 3 lines, the pruned chain entries and rows; SHA matches the anchor.
	lines := readArchive(t, filepath.Join(dir, archives[0]))
	if len(lines) != 3 {
		t.Fatalf("archive has %d lines, want 3", len(lines))
	}
	for i, l := range lines {
		if l["hash"] != before[i].Hash || l["audit_log_id"] != before[i].AuditLogID {
			t.Fatalf("archive line %d = %v, want entry %+v", i, l, before[i])
		}
	}
	var anchorHash, archiveSHA string
	var pruned int
	if err := db.QueryRowContext(ctx, `SELECT anchor_hash, archive_sha256, pruned_count FROM audit_chain_anchors WHERE tenant_id = $1`,
		tenantA.String()).Scan(&anchorHash, &archiveSHA, &pruned); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if anchorHash != before[2].Hash || pruned != 3 || archiveSHA != fileSHA(t, filepath.Join(dir, archives[0])) {
		t.Fatalf("anchor = %s/%s/%d, want %s/<file sha>/3", anchorHash, archiveSHA, pruned, before[2].Hash)
	}

	// The pruned audit rows are gone; the rest of A and all of B are intact.
	var left int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1`, tenantA.String()).Scan(&left)
	if left != 2 {
		t.Fatalf("tenant A audit rows left = %d, want 2", left)
	}
	if n := len(readChain(ctx, t, db, tenantB)); n != 2 {
		t.Fatalf("tenant B chain touched: %d entries", n)
	}

	assertChainOK := func(stage string, tenant shared.ID) {
		t.Helper()
		res, err := svc.VerifyChain(ctx, tenant, 0)
		if err != nil || !res.OK {
			t.Fatalf("%s: verify = %+v, err %v", stage, res, err)
		}
		rep, err := svc.ClassifyChain(ctx, tenant)
		if err != nil || rep.Counts.Blocking() != 0 {
			t.Fatalf("%s: classify = %+v, err %v", stage, rep, err)
		}
	}
	assertChainOK("after prune", tenantA)

	// New events keep linking.
	logTenantEvents(ctx, t, svc, tenantA, 1)
	assertChainOK("after append", tenantA)

	// Recent rows stay, whatever the caller's clock says.
	early := cfg
	early.Now = func() time.Time { return time.Now().AddDate(0, 0, auditdom.MinAuditRetentionDays+1) }
	if _, _, err := svc.PruneChain(ctx, tenantA, early); err == nil {
		t.Fatal("prune of rows newer than 365 days: no error")
	}
	if n := len(readChain(ctx, t, db, tenantA)); n != 3 {
		t.Fatalf("prune of recent rows deleted entries: %d left, want 3", n)
	}

	// Prune a whole chain: the next event links to the anchor, not to "".
	if _, _, err := svc.PruneChain(ctx, tenantC, cfg); err != nil {
		t.Fatalf("prune all: %v", err)
	}
	if n := len(readChain(ctx, t, db, tenantC)); n != 0 {
		t.Fatalf("chain not empty after full prune: %d", n)
	}
	logTenantEvents(ctx, t, svc, tenantC, 1)
	assertChainOK("append after full prune", tenantC)

	// A rebaseline of a pruned chain re-signs from the anchor and still verifies.
	if _, err := svc.RebaselineChain(ctx, tenantC, auditapp.AuditContext{TenantID: tenantC.String()}); err != nil {
		t.Fatalf("rebaseline: %v", err)
	}
	assertChainOK("after rebaseline", tenantC)
}

// The prune refuses (and deletes nothing) when the chain no longer matches
// what was read: here, a wrong anchor hash.
func TestPruneChainPrefix_RefusesAStaleRead(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())
	tenant, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, tenant, 2)
	chain := readChain(ctx, t, db, tenant)

	id, _ := shared.IDFromString(chain[0].AuditLogID)
	err := repo.PruneChainPrefix(ctx, auditdom.ChainAnchor{
		TenantID: tenant, AnchorHash: strings.Repeat("a", 64), LastChainPosition: chain[0].Position,
		PrunedCount: 1, OldestLoggedAt: time.Now(), NewestLoggedAt: time.Now(),
		ArchivePath: "/nowhere", ArchiveSHA256: strings.Repeat("b", 64),
	}, []shared.ID{id})
	if !errors.Is(err, auditdom.ErrChainPruneConflict) {
		t.Fatalf("stale prune: err = %v, want ErrChainPruneConflict", err)
	}
	// Pruning a non-prefix (the second entry alone) is refused too.
	id2, _ := shared.IDFromString(chain[1].AuditLogID)
	err = repo.PruneChainPrefix(ctx, auditdom.ChainAnchor{
		TenantID: tenant, AnchorHash: chain[1].Hash, LastChainPosition: chain[1].Position,
		PrunedCount: 1, OldestLoggedAt: time.Now(), NewestLoggedAt: time.Now(),
		ArchivePath: "/nowhere", ArchiveSHA256: strings.Repeat("b", 64),
	}, []shared.ID{id2})
	if !errors.Is(err, auditdom.ErrChainPruneConflict) {
		t.Fatalf("non-prefix prune: err = %v, want ErrChainPruneConflict", err)
	}
	// A true prefix that is less than 365 days old is refused by the database
	// whatever the caller claims: the API role cannot shorten retention.
	err = repo.PruneChainPrefix(ctx, auditdom.ChainAnchor{
		TenantID: tenant, AnchorHash: chain[0].Hash, LastChainPosition: chain[0].Position,
		PrunedCount: 1, OldestLoggedAt: time.Now().AddDate(-2, 0, 0), NewestLoggedAt: time.Now().AddDate(-2, 0, 0),
		ArchivePath: "/nowhere", ArchiveSHA256: strings.Repeat("b", 64),
	}, []shared.ID{id})
	if err == nil || errors.Is(err, auditdom.ErrChainPruneConflict) {
		t.Fatalf("recent prefix prune: err = %v, want a refusal", err)
	}
	if n := len(readChain(ctx, t, db, tenant)); n != 2 {
		t.Fatalf("refused prune deleted entries: %d left", n)
	}
}

func readArchive(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	if st, _ := f.Stat(); st.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %v, want 0600", st.Mode().Perm())
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("archive line: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// A suspended organization (how a legal hold is applied) keeps its audit
// history: its chain is not listed for pruning until it is active again.
func TestChainTenantsWithEntriesBefore_SkipsSuspendedOrganizations(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	held, _ := seedRebaselineTenant(ctx, t, db)
	free, _ := seedRebaselineTenant(ctx, t, db)
	logTenantEvents(ctx, t, svc, held, 2)
	logTenantEvents(ctx, t, svc, free, 2)
	time.Sleep(20 * time.Millisecond)
	cut := time.Now()

	if _, err := db.ExecContext(ctx, `UPDATE tenants SET status = 'suspended' WHERE id = $1`, held.String()); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.ChainTenantsWithEntriesBefore(ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	var sawHeld, sawFree bool
	for _, id := range ids {
		sawHeld = sawHeld || id == held
		sawFree = sawFree || id == free
	}
	if sawHeld || !sawFree {
		t.Fatalf("suspended chain listed=%v, active chain listed=%v; want false, true", sawHeld, sawFree)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tenants SET status = 'active' WHERE id = $1`, held.String()); err != nil {
		t.Fatal(err)
	}
	ids, _ = repo.ChainTenantsWithEntriesBefore(ctx, cut)
	for _, id := range ids {
		sawHeld = sawHeld || id == held
	}
	if !sawHeld {
		t.Fatal("a chain is still held after the suspension was lifted")
	}
}
