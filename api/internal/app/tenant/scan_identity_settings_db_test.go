package tenant_test

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/scanident"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The organization's rotation list, query parameter and requirement persist
// in its settings, reach its own jobs' tool HTTP layer only, are audited
// (turning the requirement off at high severity), and an invalid change
// (a list with a single User-Agent) stores nothing.
func TestScanIdentitySettingsPersistAuditedAndTenantScoped(t *testing.T) {
	f, actor := newAuditedSettingsFixture(t)
	ctx := context.Background()
	actx := auditapp.AuditContext{ActorID: actor}
	tid, _ := shared.IDFromString(f.tenantID)

	list := []string{"scanner/1", " scanner/2 ", ""}
	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		ToolHTTPUserAgents: &list, ToolHTTPQuery: &scanident.Query{Name: "scan", Value: "corp-1"},
		ToolHTTPIdentificationRequired: boolPtr(true), ToolHTTPHeaders: &[]scanident.Header{{Name: "X-Scan", Value: "corp"}},
	}, actx); err != nil {
		t.Fatalf("save: %v", err)
	}
	sec := f.section(t, "security")
	if sec["tool_http_identification_required"] != true {
		t.Fatalf("stored %v", sec)
	}
	pol, err := f.svc.ToolHTTPPolicy(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.UserAgents) != 2 || pol.UserAgents[1] != "scanner/2" || pol.Query == nil || pol.Query.Value != "corp-1" ||
		!pol.IdentificationRequired || pol.Headers["X-Scan"] != "corp" {
		t.Fatalf("policy %+v", pol)
	}
	if got := lastAudit(t, f.raw, f.tenantID, "tenant.settings_updated"); got.changes["after"]["tool_http_identification_required"] != true {
		t.Fatalf("audit %s", got.raw)
	}

	// Both a single User-Agent and the list: refused, nothing stored.
	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		ToolHTTPUserAgent: strPtr("single"),
	}, actx); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("both set: %v", err)
	}
	if pol, _ := f.svc.ToolHTTPPolicy(ctx, tid); pol.UserAgent != "" {
		t.Fatalf("a refused change was stored: %+v", pol)
	}

	// Turning the requirement off is a weakening change.
	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		ToolHTTPIdentificationRequired: boolPtr(false),
	}, actx); err != nil {
		t.Fatal(err)
	}
	if got := lastAudit(t, f.raw, f.tenantID, "tenant.settings_updated"); got.severity != "high" {
		t.Fatalf("requirement off severity %s", got.severity)
	}

	// SECURITY (tenant isolation): another organization's layer is its own.
	other := shared.NewID()
	if _, err := f.raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug, settings) VALUES ($1,'Other Org',$2,'{}'::jsonb)`,
		other.String(), "other-"+other.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.raw.ExecContext(context.Background(), `DELETE FROM tenants WHERE id=$1`, other.String())
	})
	if pol, err := f.svc.ToolHTTPPolicy(ctx, other); err != nil || !pol.IsZero() {
		t.Fatalf("another organization got this one's identification: %+v %v", pol, err)
	}
}
