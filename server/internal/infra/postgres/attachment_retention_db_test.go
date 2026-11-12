package postgres

// Attachment retention against a migrated database and a real local store:
// evidence of a deleted finding or campaign is marked, kept through the grace
// period and then purged (file and row, audited in its own tenant); a parent
// in another tenant never keeps a file; never-linked uploads go after their
// retention; authorization letter files are never touched; a row linked in
// the meantime is not deleted; a file whose storage is unreachable keeps its
// row.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingAuditor struct {
	mu     sync.Mutex
	events []recordedAudit
}

type recordedAudit struct {
	tenant, resource string
	action           auditdom.Action
	reason           any
}

func (r *recordingAuditor) LogEvent(_ context.Context, actx auditapp.AuditContext, e auditapp.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, recordedAudit{tenant: actx.TenantID, resource: e.ResourceID, action: e.Action, reason: e.Metadata["reason"]})
	return nil
}

func (r *recordingAuditor) byResource() map[string]recordedAudit {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]recordedAudit{}
	for _, e := range r.events {
		out[e.resource] = e
	}
	return out
}

//nolint:cyclop // one scenario, one assertion per case
func TestAttachmentRetention_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenantA)
	base := t.TempDir()
	store := storage.NewLocalStorage(base)
	repo := NewAttachmentRepository(&DB{DB: db})

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	newFinding := func() string {
		id := shared.NewID().String()
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
			VALUES ($1, $2, $3, 'manual', 'retention', 'low', 'm', $4)`, id, tenantA.String(), asset.String(), "ret-"+id)
		return id
	}
	newCampaign := func() string {
		id := shared.NewID().String()
		exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, $3)`, id, tenantA.String(), "ret "+id)
		return id
	}
	type file struct {
		id, tenant, key, provider string
	}
	put := func(tenant shared.ID, ctxType, ctxID, provider string, age time.Duration) file {
		t.Helper()
		key, err := store.Upload(ctx, tenant.String(), "evidence.txt", "text/plain", strings.NewReader("evidence "+ctxType))
		if err != nil {
			t.Fatal(err)
		}
		id := shared.NewID().String()
		exec(`INSERT INTO attachments (id, tenant_id, filename, content_type, size, storage_key, context_type, context_id, content_hash, storage_provider, created_at)
			VALUES ($1, $2, 'evidence.txt', 'text/plain', 10, $3, $4, $5, 'h', $6, now() - $7::interval)`,
			id, tenant.String(), key, ctxType, ctxID, provider, age.String())
		return file{id: id, tenant: tenant.String(), key: key, provider: provider}
	}
	onDisk := func(f file) bool {
		_, err := os.Stat(filepath.Join(base, f.tenant, f.key))
		return err == nil
	}
	rowExists := func(f file) bool {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM attachments WHERE id = $1`, f.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	liveFinding, deletedFinding := newFinding(), newFinding()
	liveCampaign, deletedCampaign := newCampaign(), newCampaign()

	kept := map[string]file{
		"live finding":      put(tenantA, "finding", liveFinding, "local", 0),
		"live retest":       put(tenantA, "retest", liveFinding, "local", 0),
		"live campaign":     put(tenantA, "campaign", liveCampaign, "local", 0),
		"recent unlinked":   put(tenantA, "finding", "", "local", time.Hour),
		"letter":            put(tenantA, "authorization_letter", "", "local", 90*24*time.Hour),
		"unknown context":   put(tenantA, "custom", "", "local", 90*24*time.Hour),
		"unknown + orphan":  put(tenantA, "control", shared.NewID().String(), "local", 90*24*time.Hour),
		"own bucket orphan": put(tenantA, "finding", deletedFinding, "s3", 0),
	}
	purged := map[string]file{
		"deleted finding":      put(tenantA, "finding", deletedFinding, "local", 0),
		"deleted campaign":     put(tenantA, "campaign", deletedCampaign, "local", 0),
		"malformed id":         put(tenantA, "retest", "not-a-uuid", "local", 0),
		"other tenant parent":  put(tenantB, "finding", liveFinding, "local", 0),
		"old unlinked":         put(tenantA, "", "", "local", 48*time.Hour),
		"old unlinked finding": put(tenantB, "finding", "", "local", 48*time.Hour),
	}
	exec(`DELETE FROM findings WHERE id = $1`, deletedFinding)
	exec(`DELETE FROM pentest_campaigns WHERE id = $1`, deletedCampaign)

	auditor := &recordingAuditor{}
	svc := integration.NewAttachmentService(repo, store, logger.NewNop())
	svc.SetRetention(repo, integration.RetentionSettings{OrphanGrace: 7 * 24 * time.Hour, UnlinkedRetention: 24 * time.Hour}, auditor)

	// First sweep: orphans are marked, nothing of theirs is purged yet
	// (grace period); the old unlinked uploads go at once.
	n, err := svc.SweepRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("first sweep purged %d, want the 2 old unlinked uploads", n)
	}
	var marked int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM attachments WHERE tenant_id = ANY($1) AND orphaned_at IS NOT NULL`,
		pq.Array([]string{tenantA.String(), tenantB.String()})).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if marked != 5 { // deleted finding, deleted campaign, malformed, other tenant parent, own bucket orphan
		t.Fatalf("marked %d orphans, want 5", marked)
	}

	// The grace period passes.
	exec(`UPDATE attachments SET orphaned_at = now() - interval '8 days' WHERE tenant_id = ANY($1) AND orphaned_at IS NOT NULL`,
		pq.Array([]string{tenantA.String(), tenantB.String()}))
	if _, err := svc.SweepRetention(ctx); err != nil {
		t.Fatal(err)
	}

	events := auditor.byResource()
	for name, f := range purged {
		if rowExists(f) || onDisk(f) {
			t.Errorf("%s: row %v, file %v; want both gone", name, rowExists(f), onDisk(f))
		}
		ev, ok := events[f.id]
		if !ok || ev.action != auditdom.ActionAttachmentPurged {
			t.Errorf("%s: no attachment.purged audit event", name)
			continue
		}
		if ev.tenant != f.tenant {
			t.Errorf("%s: audited in tenant %s, want its own tenant %s", name, ev.tenant, f.tenant)
		}
	}
	if r := events[purged["old unlinked"].id].reason; r != string(attachment.PurgeNeverLinked) {
		t.Errorf("unlinked reason = %v", r)
	}
	if r := events[purged["deleted finding"].id].reason; r != string(attachment.PurgeParentDeleted) {
		t.Errorf("orphan reason = %v", r)
	}
	for name, f := range kept {
		if !rowExists(f) || !onDisk(f) {
			t.Errorf("%s: row %v, file %v; want both kept", name, rowExists(f), onDisk(f))
		}
		if _, ok := events[f.id]; ok {
			t.Errorf("%s: audited as purged", name)
		}
	}
}

func TestAttachmentRetention_DeleteOnlyWhileStillPurgeable_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	repo := NewAttachmentRepository(&DB{DB: db})
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO attachments (id, tenant_id, filename, content_type, size, storage_key, context_type, context_id, storage_provider, created_at)
		VALUES ($1, $2, 'a.txt', 'text/plain', 1, 'k_a.txt', 'finding', '', 'local', now() - interval '3 days')`,
		id.String(), tenantA.String()); err != nil {
		t.Fatal(err)
	}
	policy := attachment.RetentionPolicy{UnlinkedBefore: time.Now().Add(-24 * time.Hour)}

	// Another tenant's id never deletes the row.
	if ok, err := repo.DeletePurgeable(ctx, tenantB, id, policy); err != nil || ok {
		t.Fatalf("cross-tenant delete: ok=%v err=%v", ok, err)
	}
	// Linked after it was listed: no longer purgeable.
	if _, err := db.ExecContext(ctx, `UPDATE attachments SET context_id = $1 WHERE id = $2`, shared.NewID().String(), id.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.DeletePurgeable(ctx, tenantA, id, policy); err != nil || ok {
		t.Fatalf("delete of a linked row: ok=%v err=%v", ok, err)
	}
	// A disabled class purges nothing.
	if _, err := db.ExecContext(ctx, `UPDATE attachments SET context_id = '' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.ListPurgeable(ctx, attachment.RetentionPolicy{}, 10); err != nil || containsAttachment(got, id) {
		t.Fatalf("zero policy listed the row: %v", err)
	}
	if ok, err := repo.DeletePurgeable(ctx, tenantA, id, policy); err != nil || !ok {
		t.Fatalf("purgeable row not deleted: ok=%v err=%v", ok, err)
	}
	if _, err := repo.GetByID(ctx, tenantA, id); !errors.Is(err, attachment.ErrNotFound) {
		t.Fatalf("row still there: %v", err)
	}
}

func containsAttachment(cs []attachment.PurgeCandidate, id shared.ID) bool {
	for _, c := range cs {
		if c.Attachment.ID() == id {
			return true
		}
	}
	return false
}
