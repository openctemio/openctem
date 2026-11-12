package postgres

// Malware scanning against a migrated database: with a scanner configured an
// upload starts pending, the worker records clean / infected (audited in the
// file's tenant) / error, an unreachable scanner leaves files pending, and a
// result can only be recorded in the row's own tenant.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/storage"
	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeScanner struct{ down bool }

func (f *fakeScanner) Scan(_ context.Context, r io.Reader) (attachment.Verdict, error) {
	if f.down {
		return attachment.Verdict{}, fmt.Errorf("%w: connection refused", attachment.ErrScannerUnavailable)
	}
	b, _ := io.ReadAll(r)
	switch {
	case bytes.Contains(b, []byte("EICAR")):
		return attachment.Verdict{Infected: true, Signature: "Eicar-Test-Signature"}, nil
	case bytes.Contains(b, []byte("BIG")):
		return attachment.Verdict{}, fmt.Errorf("%w: INSTREAM size limit exceeded", attachment.ErrScanRefused)
	}
	return attachment.Verdict{}, nil
}

func TestAttachmentMalwareScan_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	repo := NewAttachmentRepository(&DB{DB: db})
	scanner := &fakeScanner{down: true}
	auditor := &recordingAuditor{}
	svc := integration.NewAttachmentService(repo, storage.NewLocalStorage(t.TempDir()), logger.NewNop())
	svc.SetMalwareScanner(scanner, repo, auditor)

	uploader := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'scan', 'active')`,
		uploader, uploader+"@scan.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, uploader) })
	upload := func(tenant shared.ID, body string) *attachment.Attachment {
		t.Helper()
		att, err := svc.Upload(ctx, integration.UploadInput{
			TenantID: tenant.String(), Filename: "poc.txt", ContentType: "text/plain",
			Size: int64(len(body)), Reader: strings.NewReader(body), UploadedBy: uploader,
		})
		if err != nil {
			t.Fatal(err)
		}
		return att
	}
	status := func(a *attachment.Attachment) (attachment.ScanStatus, string) {
		t.Helper()
		got, err := repo.GetByID(ctx, a.TenantID(), a.ID())
		if err != nil {
			t.Fatal(err)
		}
		return got.ScanStatus(), got.ScanResult()
	}
	clean, infected, refused := upload(tenantA, "plain notes"), upload(tenantB, "sample EICAR body"), upload(tenantA, "BIG archive")
	for _, a := range []*attachment.Attachment{clean, infected, refused} {
		if s, _ := status(a); s != attachment.ScanPending {
			t.Fatalf("new upload status %q, want pending", s)
		}
	}

	// Scanner down: nothing is recorded, files stay pending.
	if _, err := svc.ScanPending(ctx); err == nil {
		t.Fatal("unreachable scanner reported no error")
	}
	if s, _ := status(clean); s != attachment.ScanPending {
		t.Fatalf("status %q after a failed pass, want pending", s)
	}

	// A result names the row's tenant: another tenant's id changes nothing.
	if ok, err := repo.SetScanResult(ctx, tenantA, infected.ID(), attachment.ScanClean, ""); err != nil || ok {
		t.Fatalf("cross-tenant result recorded: ok=%v err=%v", ok, err)
	}

	scanner.down = false
	for {
		n, err := svc.ScanPending(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	if s, _ := status(clean); s != attachment.ScanClean {
		t.Errorf("clean file: %q", s)
	}
	if s, r := status(infected); s != attachment.ScanInfected || r != "Eicar-Test-Signature" {
		t.Errorf("infected file: %q %q", s, r)
	}
	if s, r := status(refused); s != attachment.ScanError || !strings.Contains(r, "size limit") {
		t.Errorf("refused file: %q %q", s, r)
	}
	ev, ok := auditor.byResource()[infected.ID().String()]
	if !ok || ev.action != auditdom.ActionAttachmentMalwareDetected || ev.tenant != tenantB.String() {
		t.Errorf("malware audit: %+v (ok %v), want it in the file's tenant", ev, ok)
	}
	if _, ok := auditor.byResource()[clean.ID().String()]; ok {
		t.Error("clean file audited as malware")
	}
	// A recorded result is final: the row is no longer pending.
	if ok, _ := repo.SetScanResult(ctx, tenantB, infected.ID(), attachment.ScanClean, ""); ok {
		t.Error("a scanned row was overwritten")
	}
	// Reports never embed a flagged file.
	if _, _, err := svc.ReadAttachment(ctx, tenantB.String(), infected.ID().String(), 1<<20); err == nil {
		t.Error("flagged file read for a report")
	}
}
