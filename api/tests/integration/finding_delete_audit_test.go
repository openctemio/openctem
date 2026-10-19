package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/activity"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type failingAudit struct{}

func (failingAudit) LogEvent(context.Context, auditapp.AuditContext, auditapp.AuditEvent) error {
	return errors.New("audit store down")
}

// DELETE /findings/{id} removes the finding and, by cascade, its activity
// timeline. The audit log is the retained record, so the service writes a
// finding.deleted event first and refuses the delete when that write fails.
func TestDeleteFinding_WritesAuditEventFirst(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	tenant := createTestTenant(t, db, "del-audit")
	other := createTestTenant(t, db, "del-audit-other")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM audit_logs WHERE tenant_id IN ($1, $2)`, tenant.String(), other.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenant.String(), other.String())
		_ = db.Close()
	})
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewFindingRepository(pdb)
	svc := finding.NewVulnerabilityService(nil, repo, logger.NewNop())
	svc.SetActivityService(activity.NewFindingActivityService(postgres.NewFindingActivityRepository(pdb), repo, logger.NewNop()))
	svc.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(pdb), logger.NewNop()))

	actor := shared.NewID()
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'deleter')`, actor.String(), actor.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id = $1`, actor.String()) })
	asset := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'del-host', 'host')`, asset.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	newFinding := func(fp string) shared.ID {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status, cve_id)
			VALUES ($1, $2, $3, 'sast', 'del-tool', 'm', 'Critical RCE in parser', 'critical', $4, 'confirmed', 'CVE-2030-1111')`,
			id.String(), tenant.String(), asset.String(), fp); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := db.Exec(`INSERT INTO finding_activities (id, tenant_id, finding_id, activity_type) VALUES ($1, $2, $3, 'created')`,
				shared.NewID().String(), tenant.String(), id.String()); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	exists := func(id shared.ID) bool {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM findings WHERE id = $1`, id.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	auditRows := func(id shared.ID) int {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE action = 'finding.deleted' AND resource_id = $1`, id.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	actx := auditapp.AuditContext{TenantID: tenant.String(), ActorID: actor.String()}

	// Success: one event, with the actor and the finding's identity.
	id := newFinding("del-1")
	if err := svc.DeleteFinding(ctx, id.String(), tenant.String(), actx); err != nil {
		t.Fatal(err)
	}
	if exists(id) {
		t.Error("finding still exists after delete")
	}
	if n := auditRows(id); n != 1 {
		t.Fatalf("%d finding.deleted audit rows, want 1", n)
	}
	var actorID, name, severity, cve, removed, resType string
	if err := db.QueryRow(`SELECT actor_id::text, resource_name, resource_type, metadata->>'severity', metadata->>'cve_id', metadata->>'activities_removed'
		FROM audit_logs WHERE action = 'finding.deleted' AND resource_id = $1`, id.String()).
		Scan(&actorID, &name, &resType, &severity, &cve, &removed); err != nil {
		t.Fatal(err)
	}
	if actorID != actor.String() || name != "Critical RCE in parser" || resType != "finding" || severity != "critical" || cve != "CVE-2030-1111" || removed != "2" {
		t.Errorf("audit row: actor=%s name=%q type=%s severity=%s cve=%s removed=%s", actorID, name, resType, severity, cve, removed)
	}

	// Another tenant's finding id: not found, no audit row, finding kept.
	kept := newFinding("del-2")
	if err := svc.DeleteFinding(ctx, kept.String(), other.String(), auditapp.AuditContext{TenantID: other.String(), ActorID: actor.String()}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("cross-tenant delete: %v, want not found", err)
	}
	if !exists(kept) || auditRows(kept) != 0 {
		t.Errorf("cross-tenant delete touched the finding (exists=%v audit rows=%d)", exists(kept), auditRows(kept))
	}

	// Audit failure: the delete is refused and the finding stays.
	svc.SetAuditService(failingAudit{})
	if err := svc.DeleteFinding(ctx, kept.String(), tenant.String(), actx); err == nil {
		t.Error("delete succeeded although the audit write failed")
	}
	if !exists(kept) {
		t.Error("finding deleted although the audit write failed")
	}
}
