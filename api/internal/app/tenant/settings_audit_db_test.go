package tenant_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Organization settings changes are audited with a field-level diff and a
// severity that flags weakening changes, and secrets never reach the diff.

type auditRow struct {
	action, severity string
	changes          map[string]map[string]any
	raw              string
}

func newAuditedSettingsFixture(t *testing.T) (*settingsFixture, string) {
	t.Helper()
	f := newSettingsFixture(t)
	db := &postgres.DB{DB: f.raw}
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())
	f.svc = tenantapp.NewTenantService(postgres.NewTenantRepository(db), logger.NewNop(), tenantapp.WithTenantAuditService(auditSvc))

	actor := shared.NewID().String()
	if _, err := f.raw.Exec(`INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, actor, "admin-"+actor+"@example.com"); err != nil {
		t.Fatalf("seed actor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.raw.Exec(`DELETE FROM audit_log_chain WHERE tenant_id=$1`, f.tenantID)
		_, _ = f.raw.Exec(`DELETE FROM audit_logs WHERE tenant_id=$1`, f.tenantID)
		_, _ = f.raw.Exec(`DELETE FROM users WHERE id=$1`, actor)
	})
	return f, actor
}

func lastAudit(t *testing.T, raw *sql.DB, tenantID, action string) auditRow {
	t.Helper()
	var r auditRow
	var changes sql.NullString
	err := raw.QueryRow(`SELECT action, severity, changes::text FROM audit_logs
		WHERE tenant_id=$1 AND action=$2 ORDER BY logged_at DESC LIMIT 1`, tenantID, action).
		Scan(&r.action, &r.severity, &changes)
	if err != nil {
		t.Fatalf("no %s audit row: %v", action, err)
	}
	r.raw = changes.String
	_ = json.Unmarshal([]byte(changes.String), &r.changes)
	return r
}

func TestSettingsAudit_SecurityDowngradeIsCriticalWithDiff(t *testing.T) {
	f, actor := newAuditedSettingsFixture(t)
	ctx := context.Background()
	actx := auditapp.AuditContext{ActorID: actor}

	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		MFARequired: boolPtr(true), IPWhitelist: []string{"10.0.0.0/8"},
	}, actx); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := lastAudit(t, f.raw, f.tenantID, "tenant.settings_updated"); got.severity != "medium" {
		t.Fatalf("tightening severity = %s, want medium", got.severity)
	}

	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		MFARequired: boolPtr(false),
	}, actx); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got := lastAudit(t, f.raw, f.tenantID, "tenant.settings_updated")
	if got.severity != "critical" {
		t.Fatalf("MFA off severity = %s, want critical", got.severity)
	}
	if got.changes["before"]["mfa_required"] != true || got.changes["after"]["mfa_required"] != false {
		t.Fatalf("diff = %s, want mfa_required true -> false", got.raw)
	}
	if _, ok := got.changes["after"]["ip_whitelist"]; ok {
		t.Fatalf("unchanged field in diff: %s", got.raw)
	}

	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		IPWhitelist: []string{},
	}, actx); err != nil {
		t.Fatalf("empty allowlist: %v", err)
	}
	if got := lastAudit(t, f.raw, f.tenantID, "tenant.settings_updated"); got.severity != "critical" {
		t.Fatalf("allowlist emptied severity = %s, want critical", got.severity)
	}
}

func TestSettingsAudit_ProfileAndSlugChangesAreAudited(t *testing.T) {
	f, actor := newAuditedSettingsFixture(t)
	ctx := context.Background()
	actx := auditapp.AuditContext{ActorID: actor}

	if _, err := f.svc.UpdateTenant(ctx, f.tenantID, tenantapp.UpdateTenantInput{Name: strPtr("Renamed Org")}, actx); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got := lastAudit(t, f.raw, f.tenantID, "tenant.updated")
	if got.severity != "low" || got.changes["after"]["name"] != "Renamed Org" {
		t.Fatalf("rename audit = %s / %s", got.severity, got.raw)
	}

	newSlug := "renamed-" + f.tenantID[:8]
	if _, err := f.svc.UpdateTenant(ctx, f.tenantID, tenantapp.UpdateTenantInput{Slug: &newSlug, CallerIsOwner: true}, actx); err != nil {
		t.Fatalf("slug: %v", err)
	}
	got = lastAudit(t, f.raw, f.tenantID, "tenant.updated")
	if got.severity != "high" || got.changes["after"]["slug"] != newSlug {
		t.Fatalf("slug audit = %s / %s, want high with the new slug", got.severity, got.raw)
	}
}

func TestSettingsAudit_InvitationDeleteIsAudited(t *testing.T) {
	f, actor := newAuditedSettingsFixture(t)
	ctx := context.Background()
	invID := shared.NewID().String()
	if _, err := f.raw.Exec(`INSERT INTO tenant_invitations (id, tenant_id, email, role, token, invited_by, expires_at, created_at)
		VALUES ($1,$2,'invitee@example.com','member',$3,$4,NOW() + INTERVAL '1 day',NOW())`,
		invID, f.tenantID, "tok-"+invID, actor); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	if err := f.svc.DeleteInvitation(ctx, f.tenantID, invID, auditapp.AuditContext{ActorID: actor}); err != nil {
		t.Fatalf("delete invitation: %v", err)
	}
	var n int
	if err := f.raw.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='invitation.deleted' AND resource_id=$2 AND actor_id=$3`,
		f.tenantID, invID, actor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("invitation.deleted rows = %d (err %v), want 1", n, err)
	}
}
