package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/taggov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeGov struct {
	byTenant map[shared.ID]taggov.Set
	err      error
}

func (f fakeGov) For(_ context.Context, t shared.ID) (taggov.Set, error) { return f.byTenant[t], f.err }

// A report may not set a tag that a rule of the tenant reads: the team access
// rule that matches it would grant the asset to the team, the approval rule
// that matches it would catch the scan.
func TestDropGoverningTags(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	gov := fakeGov{byTenant: map[shared.ID]taggov.Set{
		tenantA: taggov.NewSet([]taggov.Ref{{Tag: "team:payments", Req: taggov.Requirement{Rule: taggov.RuleAccessScope, Permission: "team:groups:write"}}}),
	}}
	p := &AssetProcessor{logger: logger.NewNop(), tagGovernor: gov}

	rep := func() *ctis.Report {
		return &ctis.Report{Assets: []ctis.Asset{{ID: "a", Tags: []string{"team:payments", "Team:Other", "free"}}}}
	}
	r := rep()
	p.dropGoverningTags(context.Background(), tenantA, r)
	if got := r.Assets[0].Tags; len(got) != 1 || got[0] != "free" {
		t.Fatalf("tenant A report kept %v, want [free] (the key team: is governing)", got)
	}
	// Tenant B has no such rule: the same tags are fine there (isolation).
	r = rep()
	p.dropGoverningTags(context.Background(), tenantB, r)
	if got := r.Assets[0].Tags; len(got) != 3 {
		t.Fatalf("tenant B report kept %v, want all three", got)
	}
	// The set cannot be read: fail closed.
	p.tagGovernor = fakeGov{err: errors.New("db down")}
	r = rep()
	p.dropGoverningTags(context.Background(), tenantA, r)
	if got := r.Assets[0].Tags; len(got) != 0 {
		t.Fatalf("fail closed: kept %v", got)
	}
}
