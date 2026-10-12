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
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Audit retention prunes the oldest prefix of a hash chain without breaking
// verification: the pruned rows are archived, the chain head they leave is
// anchored, and verify / classify / rebaseline / append all continue from the
// anchor. Before this, the retention DELETE hit the chain's ON DELETE
// RESTRICT foreign key and failed on every run.

func cleanupAnchors(t *testing.T, db *postgres.DB, tenantID shared.ID) {
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM audit_chain_anchors WHERE tenant_id = $1`, tenantID.String())
	})
}

func TestPruneChain_ArchivesAnchorsAndChainStillVerifies(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())

	tenantA, _ := seedRebaselineTenant(ctx, t, db)
	tenantB, _ := seedRebaselineTenant(ctx, t, db)
	cleanupAnchors(t, db, tenantA)
	cleanupAnchors(t, db, tenantB)

	logTenantEvents(ctx, t, svc, tenantA, 3)
	logTenantEvents(ctx, t, svc, tenantB, 2)
	time.Sleep(20 * time.Millisecond)
	cut := time.Now()
	time.Sleep(20 * time.Millisecond)
	logTenantEvents(ctx, t, svc, tenantA, 2)

	before := readChain(ctx, t, db, tenantA)
	if len(before) != 5 {
		t.Fatalf("tenant A chain = %d entries, want 5", len(before))
	}

	dir := t.TempDir()
	cfg := auditapp.RetentionConfig{
		RetentionDays: 30, // raised to the 365-day minimum
		ArchiveDir:    dir,
		Now:           func() time.Time { return cut.AddDate(0, 0, auditdom.MinAuditRetentionDays) },
	}

	// No archive location: nothing is deleted.
	if _, _, err := svc.PruneChain(ctx, tenantA, auditapp.RetentionConfig{Now: cfg.Now}); !errors.Is(err, auditapp.ErrNoAuditArchiveDir) {
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
	lines := readArchive(t, archives[0])
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
	if anchorHash != before[2].Hash || pruned != 3 || archiveSHA != fileSHA(t, archives[0]) {
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

	assertChainOK := func(stage string) {
		t.Helper()
		res, err := svc.VerifyChain(ctx, tenantA, 0)
		if err != nil || !res.OK {
			t.Fatalf("%s: verify = %+v, err %v", stage, res, err)
		}
		rep, err := svc.ClassifyChain(ctx, tenantA)
		if err != nil || rep.Counts.Blocking() != 0 {
			t.Fatalf("%s: classify = %+v, err %v", stage, rep, err)
		}
	}
	assertChainOK("after prune")

	// New events keep linking.
	logTenantEvents(ctx, t, svc, tenantA, 1)
	assertChainOK("after append")

	// Prune everything: the next event links to the anchor, not to "".
	all := cfg
	all.Now = func() time.Time { return time.Now().AddDate(0, 0, auditdom.MinAuditRetentionDays+1) }
	if _, _, err := svc.PruneChain(ctx, tenantA, all); err != nil {
		t.Fatalf("prune all: %v", err)
	}
	if n := len(readChain(ctx, t, db, tenantA)); n != 0 {
		t.Fatalf("chain not empty after full prune: %d", n)
	}
	logTenantEvents(ctx, t, svc, tenantA, 1)
	assertChainOK("append after full prune")

	// A rebaseline of a pruned chain re-signs from the anchor and still verifies.
	if _, err := svc.RebaselineChain(ctx, tenantA, auditapp.AuditContext{TenantID: tenantA.String()}); err != nil {
		t.Fatalf("rebaseline: %v", err)
	}
	assertChainOK("after rebaseline")
}

// The prune refuses (and deletes nothing) when the chain no longer matches
// what was read: here, a wrong anchor hash.
func TestPruneChainPrefix_RefusesAStaleRead(t *testing.T) {
	ctx := context.Background()
	db := openAuditDB(t)
	repo := postgres.NewAuditRepository(db)
	svc := auditapp.NewAuditService(repo, logger.NewNop())
	tenant, _ := seedRebaselineTenant(ctx, t, db)
	cleanupAnchors(t, db, tenant)
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
