package ingest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/ctis"
)

// =============================================================================
// In-memory audit repository with real hash-chain semantics
// =============================================================================

// chainAuditRepo implements audit.Repository. Only the methods the audit
// service actually touches (Create + the three chain methods + GetByTenantAndID)
// carry behavior; the rest are stubs so the interface is satisfied.
type chainAuditRepo struct {
	mu      sync.Mutex
	logs    map[shared.ID]*audit.AuditLog
	chain   []audit.ChainEntry
	nextPos int64
}

func newChainAuditRepo() *chainAuditRepo {
	return &chainAuditRepo{logs: make(map[shared.ID]*audit.AuditLog)}
}

func (r *chainAuditRepo) Create(_ context.Context, log *audit.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs[log.ID()] = log
	return nil
}

func (r *chainAuditRepo) LatestChainHash(_ context.Context, tenantID shared.ID) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.chain) - 1; i >= 0; i-- {
		if r.chain[i].TenantID == tenantID {
			return r.chain[i].Hash, nil
		}
	}
	return "", nil
}

func (r *chainAuditRepo) AppendChainEntry(_ context.Context, entry audit.ChainEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.chain {
		if e.AuditLogID == entry.AuditLogID {
			return nil // idempotent on PK collision, like the SQL repo
		}
	}
	r.nextPos++
	entry.ChainPosition = r.nextPos
	entry.CreatedAt = time.Now()
	r.chain = append(r.chain, entry)
	return nil
}

func (r *chainAuditRepo) ListChainEntries(_ context.Context, tenantID shared.ID, limit int) ([]audit.ChainEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.ChainEntry, 0, len(r.chain))
	for _, e := range r.chain {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out, nil
}

func (r *chainAuditRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*audit.AuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	log, ok := r.logs[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if tid := log.TenantID(); tid == nil || *tid != tenantID {
		return nil, shared.ErrNotFound
	}
	return log, nil
}

func (r *chainAuditRepo) GetSystemByID(_ context.Context, id shared.ID) (*audit.AuditLog, error) {
	return nil, audit.AuditLogNotFoundError(id)
}

// chainEntryFor returns the chain row covering an audit log, if any.
func (r *chainAuditRepo) chainEntryFor(id shared.ID) (audit.ChainEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.chain {
		if e.AuditLogID == id {
			return e, true
		}
	}
	return audit.ChainEntry{}, false
}

// logsWithAction returns every persisted audit log for the given action.
func (r *chainAuditRepo) logsWithAction(action audit.Action) []*audit.AuditLog {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*audit.AuditLog
	for _, l := range r.logs {
		if l.Action() == action {
			out = append(out, l)
		}
	}
	return out
}

// --- unused interface methods -------------------------------------------

func (r *chainAuditRepo) CreateBatch(context.Context, []*audit.AuditLog) error { return nil }
func (r *chainAuditRepo) GetByID(context.Context, shared.ID) (*audit.AuditLog, error) {
	return nil, shared.ErrNotFound
}

func (r *chainAuditRepo) List(context.Context, audit.Filter, pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}
func (r *chainAuditRepo) Count(context.Context, audit.Filter) (int64, error) { return 0, nil }
func (r *chainAuditRepo) DeleteOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func (r *chainAuditRepo) DeleteOlderThanForTenant(context.Context, shared.ID, time.Time) (int64, error) {
	return 0, nil
}

func (r *chainAuditRepo) GetLatestByResource(context.Context, shared.ID, audit.ResourceType, string) (*audit.AuditLog, error) {
	return nil, shared.ErrNotFound
}

func (r *chainAuditRepo) ListByActor(context.Context, shared.ID, shared.ID, pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (r *chainAuditRepo) ListByResource(context.Context, shared.ID, audit.ResourceType, string, pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (r *chainAuditRepo) CountByAction(context.Context, *shared.ID, audit.Action, time.Time) (int64, error) {
	return 0, nil
}

func (r *chainAuditRepo) UpdateChainEntryHashes(context.Context, shared.ID, string, string) error {
	return nil
}

// =============================================================================
// Tests
// =============================================================================

// newIngestAuditFixture builds a minimal ingest service whose only live
// dependency is the audit stack.
func newIngestAuditFixture(t *testing.T) (*Service, *auditapp.AuditService, *chainAuditRepo) {
	t.Helper()
	repo := newChainAuditRepo()
	log := logger.NewNop()
	auditSvc := auditapp.NewAuditService(repo, log)

	svc := NewService(nil, nil, nil, nil, nil, nil, nil, repo, log)
	svc.SetAuditService(auditSvc)
	return svc, auditSvc, repo
}

func ingestReport() *ctis.Report {
	return &ctis.Report{
		Tool: &ctis.Tool{Name: "trivy"},
		Metadata: ctis.ReportMetadata{
			SourceType: "sca",
		},
	}
}

// waitForChainEntries blocks until the repo holds n chain rows for the tenant,
// or fails the test. createIngestAuditLog persists asynchronously.
func waitForChainEntries(t *testing.T, repo *chainAuditRepo, tenantID shared.ID, n int) []audit.ChainEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := repo.ListChainEntries(context.Background(), tenantID, 0)
		if err != nil {
			t.Fatalf("ListChainEntries: %v", err)
		}
		if len(entries) >= n {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d chain entries; got %d — the ingest audit log was persisted without extending the tamper-evident chain", n, len(entries))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestIngestAuditLogIsChained is the regression guard for the gap where the
// async ingest path wrote tenant-scoped audit_logs directly through the
// repository, bypassing AuditService and therefore audit_log_chain. Every
// tenant-scoped audit event must carry a chain row.
func TestIngestAuditLogIsChained(t *testing.T) {
	svc, auditSvc, repo := newIngestAuditFixture(t)
	tenantID := shared.NewID()
	ctx := context.Background()

	// A prior tenant-scoped event so the ingest entry has something to link onto.
	if err := auditSvc.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String()},
		auditapp.NewSuccessEvent(audit.ActionAgentActivated, audit.ResourceTypeAgent, shared.NewID().String())); err != nil {
		t.Fatalf("seed LogEvent: %v", err)
	}

	agt := &agent.Agent{ID: shared.NewID(), Name: "scanner-01"}
	svc.createIngestAuditLog(ctx, agt, tenantID, ingestReport(), &Output{
		ReportID:        "report-abc",
		FindingsCreated: 3,
		FindingsUpdated: 1,
	})

	waitForChainEntries(t, repo, tenantID, 2)

	logs := repo.logsWithAction(audit.ActionIngestCompleted)
	if len(logs) != 1 {
		t.Fatalf("expected 1 ingest.completed audit log, got %d", len(logs))
	}
	if _, ok := repo.chainEntryFor(logs[0].ID()); !ok {
		t.Fatalf("ingest.completed audit log %s has no audit_log_chain entry — tenant-scoped audit events must be chained", logs[0].ID())
	}

	// The chain must still verify: hashes recompute and prev_hash links.
	res, err := auditSvc.VerifyChain(ctx, tenantID, 0)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain does not verify after ingest audit log: %+v", res.Breaks)
	}
	if res.Total != 2 || res.Verified != 2 {
		t.Fatalf("expected 2 verified chain entries, got total=%d verified=%d", res.Total, res.Verified)
	}
}

// TestIngestPartialSuccessAuditLogIsChained covers the other action the live
// database showed unchained.
func TestIngestPartialSuccessAuditLogIsChained(t *testing.T) {
	svc, auditSvc, repo := newIngestAuditFixture(t)
	tenantID := shared.NewID()
	ctx := context.Background()

	agt := &agent.Agent{ID: shared.NewID(), Name: "scanner-01"}
	svc.createIngestAuditLog(ctx, agt, tenantID, ingestReport(), &Output{
		ReportID:        "report-partial",
		FindingsCreated: 2,
		Errors:          []string{"finding 7: bad severity"},
		FailedFindings:  []FailedFinding{{Index: 7, RuleID: "CVE-2024-1", Error: "bad severity"}},
	})

	entries := waitForChainEntries(t, repo, tenantID, 1)

	logs := repo.logsWithAction(audit.ActionIngestPartialSuccess)
	if len(logs) != 1 {
		t.Fatalf("expected 1 ingest.partial_success audit log, got %d", len(logs))
	}
	if entries[0].AuditLogID != logs[0].ID() {
		t.Fatalf("chain entry references %s, expected the ingest audit log %s", entries[0].AuditLogID, logs[0].ID())
	}
	if entries[0].PrevHash != "" {
		t.Fatalf("first chain entry for a fresh tenant must have an empty prev_hash, got %q", entries[0].PrevHash)
	}

	res, err := auditSvc.VerifyChain(ctx, tenantID, 0)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain does not verify: %+v", res.Breaks)
	}
}

// TestIngestAuditChainLinksSequentially proves repeated ingests extend one
// linked list rather than writing sibling entries off the same prev_hash.
func TestIngestAuditChainLinksSequentially(t *testing.T) {
	svc, auditSvc, repo := newIngestAuditFixture(t)
	tenantID := shared.NewID()
	ctx := context.Background()
	agt := &agent.Agent{ID: shared.NewID(), Name: "scanner-01"}

	const ingests = 5
	for i := 0; i < ingests; i++ {
		svc.createIngestAuditLog(ctx, agt, tenantID, ingestReport(), &Output{
			ReportID:        fmt.Sprintf("report-%d", i),
			FindingsCreated: i + 1,
		})
	}

	entries := waitForChainEntries(t, repo, tenantID, ingests)
	if len(entries) != ingests {
		t.Fatalf("expected %d chain entries, got %d", ingests, len(entries))
	}
	prev := ""
	for i, e := range entries {
		if e.PrevHash != prev {
			t.Fatalf("chain entry %d prev_hash=%q, expected %q — the chain is not a linked list", i, e.PrevHash, prev)
		}
		prev = e.Hash
	}

	res, err := auditSvc.VerifyChain(ctx, tenantID, 0)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain does not verify after %d ingests: %+v", ingests, res.Breaks)
	}
}
