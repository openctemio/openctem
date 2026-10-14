package integration

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	codescanapp "github.com/openctemio/openctem/api/internal/app/codescan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Code scanning end to end on the real repositories: a repository inherits
// the template until it has its own settings, re-baseline queues exactly its
// protected branches (recording the default branch first), and every change
// is audited. Another tenant can neither read nor queue anything.
func TestCodeScanSettingsAndRebaseline(t *testing.T) {
	sqldb := setupTestDB(t)
	t.Cleanup(func() { _ = sqldb.Close() })
	db := &postgres.DB{DB: sqldb}
	ctx := context.Background()
	log := logger.NewNop()
	svc := codescanapp.NewService(postgres.NewCodeScanRepository(db), auditapp.NewAuditService(postgres.NewAuditRepository(db), log), log)

	newTenant := func() shared.ID {
		id := shared.NewID()
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "cs-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		})
		return id
	}
	tenant, other := newTenant(), newTenant()
	repoID := shared.NewID()
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'acme/api', 'repository')`,
		repoID.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO asset_repositories (asset_id, default_branch) VALUES ($1, 'main')`, repoID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.ExecContext(ctx, `INSERT INTO repository_branches (repository_id, name) VALUES ($1, 'develop'), ($1, 'feature/x')`, repoID.String()); err != nil {
		t.Fatal(err)
	}
	actor := codescanapp.Actor{Email: "admin@acme.test"}
	audits := func(action string) int {
		var n int
		_ = sqldb.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`, tenant.String(), action).Scan(&n)
		return n
	}

	// Defaults until the tenant sets a template.
	if _, src, err := svc.Template(ctx, tenant); err != nil || src != codescan.SourceDefault {
		t.Fatalf("template: %s %v", src, err)
	}
	if _, err := svc.UpdateTemplate(ctx, tenant, codescanapp.SettingsInput{ProtectedBranches: []string{"{default}"},
		Capabilities: []string{"sast", "secrets"}, Schedule: "daily", Routing: "tenant", Enabled: true}, actor); err != nil {
		t.Fatal(err)
	}
	st, err := svc.Repository(ctx, tenant, repoID)
	if err != nil || st.Source != codescan.SourceTemplate || st.Settings.Schedule != "daily" {
		t.Fatalf("inherits the template: %+v %v", st, err)
	}

	// Its own settings protect develop too.
	st, err = svc.UpdateRepository(ctx, tenant, repoID, codescanapp.SettingsInput{ProtectedBranches: []string{"{default}", "develop"},
		Capabilities: []string{"sast", "sca"}, Schedule: "weekly", Routing: "auto", Enabled: true}, actor)
	if err != nil || st.Source != codescan.SourceRepository {
		t.Fatalf("own settings: %+v %v", st, err)
	}

	// Re-baseline: main is recorded, main and develop are queued, the
	// feature branch is not.
	n, st, err := svc.Rebaseline(ctx, tenant, repoID, actor)
	if err != nil || n != 2 {
		t.Fatalf("rebaseline: %d %v", n, err)
	}
	states := map[string]string{}
	for _, b := range st.Branches {
		states[b.Name] = b.BaselineState
	}
	if states["main"] != codescan.BaselineQueued || states["develop"] != codescan.BaselineQueued || states["feature/x"] != codescan.BaselineNone {
		t.Fatalf("branch states: %v", states)
	}
	if sum := st.Summary(); sum[codescan.BaselineQueued] != 2 {
		t.Fatalf("summary: %v", sum)
	}
	if n, _, _ := svc.Rebaseline(ctx, tenant, repoID, actor); n != 0 {
		t.Fatal("queued branches were queued again")
	}

	// Another tenant: not found everywhere.
	if _, err := svc.Repository(ctx, other, repoID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	if _, _, err := svc.Rebaseline(ctx, other, repoID, actor); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant rebaseline: %v", err)
	}
	if _, err := svc.UpdateRepository(ctx, other, repoID, codescanapp.SettingsInput{ProtectedBranches: []string{"main"},
		Capabilities: []string{"sast"}, Schedule: "weekly", Routing: "auto", Enabled: true}, actor); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}

	// Turned off: no re-baseline.
	if _, err := svc.UpdateRepository(ctx, tenant, repoID, codescanapp.SettingsInput{ProtectedBranches: []string{"main"},
		Capabilities: []string{"sast"}, Schedule: "off", Routing: "auto", Enabled: false}, actor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Rebaseline(ctx, tenant, repoID, actor); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rebaseline while off: %v", err)
	}
	if st, err := svc.ResetRepository(ctx, tenant, repoID, actor); err != nil || st.Source != codescan.SourceTemplate {
		t.Fatalf("reset: %+v %v", st, err)
	}

	if got := audits("code_scan_settings.updated"); got != 4 {
		t.Fatalf("settings changes audited %d times, want 4", got)
	}
	if got := audits("code_scan.rebaseline_requested"); got != 2 {
		t.Fatalf("re-baselines audited %d times, want 2", got)
	}
}
