package bountyprogram

import (
	"context"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	moduledom "github.com/openctemio/openctem/server/pkg/domain/module"
)

type scopeOff map[string]bool

func (o scopeOff) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	if o[tenantID] {
		return map[string]bool{moduledom.ModuleScopeConfig: true}
	}
	return nil
}

// A program of a tenant with the scope module off is not read from its source
// (no outbound lookup, no scope change) until the module is back on.
func TestSyncDue_SkipsTenantWithScopeOff(t *testing.T) {
	ctx := context.Background()
	svc, _, fetch, p, user := syncService(t)
	if _, err := svc.ConfigureSource(ctx, p.TenantID, user, p.ID, bp.SyncSourceInput{Source: bp.ScopeSourceAPI,
		Handle: "acme", Username: "jdoe", Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	fetch.text = "*.acme.example\nacme.example\n-admin.acme.example\nshop.acme.example\n"
	fetch.token = ""

	svc.SetModuleGuard(scopeOff{p.TenantID.String(): true})
	if n, err := svc.SyncDue(ctx, time.Hour, 10); err != nil || n != 0 || fetch.token != "" {
		t.Fatalf("a tenant with scope off must not be synced: n=%d err=%v looked up=%v", n, err, fetch.token != "")
	}

	svc.SetModuleGuard(scopeOff{})
	if n, err := svc.SyncDue(ctx, time.Hour, 10); err != nil || n != 1 {
		t.Fatalf("the same tenant with scope on is synced: n=%d err=%v", n, err)
	}
}
