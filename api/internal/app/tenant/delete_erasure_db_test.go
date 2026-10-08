package tenant_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type erasureFixture struct {
	raw     *sql.DB
	db      *postgres.DB
	userID  string
	tenants []string
}

func newErasureFixture(t *testing.T, tenants int) *erasureFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	f := &erasureFixture{raw: raw, db: &postgres.DB{DB: raw}, userID: shared.NewID().String()}
	if _, err := raw.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1,$2,'Owner')`,
		f.userID, "erasure-"+f.userID+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	for i := 0; i < tenants; i++ {
		id := shared.NewID().String()
		if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,'Erasure Org',$2)`,
			id, "erasure-"+id); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		f.tenants = append(f.tenants, id)
	}
	t.Cleanup(func() {
		for _, id := range f.tenants {
			_, _ = raw.ExecContext(context.Background(), `DELETE FROM tenants WHERE id=$1`, id)
		}
		_, _ = raw.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, f.userID)
	})
	return f
}

func (f *erasureFixture) upload(t *testing.T, svc *integration.AttachmentService, tenantID string) *attachment.Attachment {
	t.Helper()
	att, err := svc.Upload(context.Background(), integration.UploadInput{
		TenantID: tenantID, Filename: "evidence.txt", ContentType: "text/plain", Size: 8,
		Reader: strings.NewReader("evidence-" + tenantID), UploadedBy: f.userID,
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	return att
}

func (f *erasureFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.raw.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// Deleting an organization deletes its stored files on the server storage
// (local, in a temp dir here) along with its rows, and leaves another
// organization's files and rows untouched.
func TestDeleteTenant_ErasesStoredFiles_OnlyThatTenant(t *testing.T) {
	f := newErasureFixture(t, 2)
	tenantA, tenantB := f.tenants[0], f.tenants[1]
	ctx := context.Background()
	log := logger.NewNop()

	base := t.TempDir()
	attachments := integration.NewAttachmentService(postgres.NewAttachmentRepository(f.db), storage.NewLocalStorage(base), log)
	f.upload(t, attachments, tenantA)
	f.upload(t, attachments, tenantA)
	attB := f.upload(t, attachments, tenantB)

	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(f.db), log)
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(f.db), log, tenantapp.WithTenantAuditService(auditSvc))
	svc.SetBlobEraser(attachments)

	if err := svc.DeleteTenant(ctx, auditapp.AuditContext{TenantID: tenantA, ActorID: f.userID}, tenantA); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}

	if _, err := os.Stat(filepath.Join(base, tenantA)); !os.IsNotExist(err) {
		t.Errorf("tenant A's files are still on disk (err=%v)", err)
	}
	if n := f.count(t, `SELECT count(*) FROM attachments WHERE tenant_id=$1`, tenantA); n != 0 {
		t.Errorf("tenant A attachment rows = %d, want 0", n)
	}
	rc, _, _, err := attachments.Download(ctx, tenantB, attB.ID().String())
	if err != nil {
		t.Fatalf("tenant B's file is gone: %v", err)
	}
	body, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(body) != "evidence-"+tenantB {
		t.Errorf("tenant B's file content = %q", body)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE action='tenant.deleted' AND resource_id=$1
		AND result='success' AND (metadata->>'files_erased')::int = 2`, tenantA); n != 1 {
		t.Errorf("tenant.deleted audit with files_erased=2: %d rows, want 1", n)
	}
}

type downStorage struct{ attachment.FileStorage }

func (downStorage) EraseTenant(context.Context, string) (int, error) {
	return 0, errors.New("dial tcp 10.0.0.5:9000: connection refused")
}

// When the files cannot be erased the organization is not deleted: its rows
// (including the attachment rows naming the files) remain, so nothing is lost
// and the owner can retry; the refusal is audited on its own chain.
func TestDeleteTenant_StorageDown_RefusedAndNothingLost(t *testing.T) {
	f := newErasureFixture(t, 1)
	tenantA := f.tenants[0]
	ctx := context.Background()
	log := logger.NewNop()

	local := storage.NewLocalStorage(t.TempDir())
	attachments := integration.NewAttachmentService(postgres.NewAttachmentRepository(f.db), local, log)
	f.upload(t, attachments, tenantA)

	broken := integration.NewAttachmentService(postgres.NewAttachmentRepository(f.db), downStorage{local}, log)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(f.db), log)
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(f.db), log, tenantapp.WithTenantAuditService(auditSvc))
	svc.SetBlobEraser(broken)

	err := svc.DeleteTenant(ctx, auditapp.AuditContext{TenantID: tenantA, ActorID: f.userID}, tenantA)
	if !errors.Is(err, tenantapp.ErrStoredFilesNotErased) {
		t.Fatalf("err = %v, want ErrStoredFilesNotErased", err)
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE id=$1`, tenantA); n != 1 {
		t.Fatal("tenant deleted although its files were not erased")
	}
	if n := f.count(t, `SELECT count(*) FROM attachments WHERE tenant_id=$1`, tenantA); n != 1 {
		t.Errorf("attachment rows = %d, want 1 (the record of the stored file)", n)
	}
	if n := f.count(t, `SELECT count(*) FROM audit_logs WHERE action='tenant.deleted' AND resource_id=$1
		AND tenant_id::text=$1 AND result='failure' AND metadata::text NOT LIKE '%10.0.0.5%'`, tenantA); n != 1 {
		t.Errorf("refused-deletion audit rows without the storage cause = %d, want 1", n)
	}

	// Storage back: the retry erases and deletes.
	svc.SetBlobEraser(attachments)
	if err := svc.DeleteTenant(ctx, auditapp.AuditContext{TenantID: tenantA, ActorID: f.userID}, tenantA); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM tenants WHERE id=$1`, tenantA); n != 0 {
		t.Fatal("retry did not delete the tenant")
	}
}
