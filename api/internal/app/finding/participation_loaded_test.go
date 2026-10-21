package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The fan-out reuses the finding it already holds, but only for that exact
// finding in that tenant.
func TestLoadedFinding_OnlyTheSameFindingAndTenant(t *testing.T) {
	tenant := shared.NewID()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSAST, "tool", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	ctx := withLoadedFinding(context.Background(), f)
	if got, ok := loadedFinding(ctx, tenant, f.ID()); !ok || got != f {
		t.Fatal("the held finding was not reused")
	}
	if _, ok := loadedFinding(ctx, tenant, shared.NewID()); ok {
		t.Error("reused for another finding")
	}
	if _, ok := loadedFinding(ctx, shared.NewID(), f.ID()); ok {
		t.Error("reused across tenants")
	}
	if _, ok := loadedFinding(context.Background(), tenant, f.ID()); ok {
		t.Error("reused without being handed one")
	}
}
