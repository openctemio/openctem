package integration

// Repository scope entries on a real database (RFC-054, "Repository
// entries"): one canonical spelling, the shared-code-host guardrail, and
// tenant isolation.

import (
	"context"
	"errors"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestScopeRepositoryEntries_DB(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	pdb := &postgres.DB{DB: db}
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(pdb), postgres.NewScopeExclusionRepository(pdb),
		postgres.NewAssetRepository(pdb), logger.NewNop())
	create := func(tenant, pattern string) (*scopedom.Target, error) {
		return svc.CreateTarget(ctx, scopeapp.CreateTargetInput{TenantID: tenant, TargetType: "repository", Pattern: pattern})
	}

	// A whole shared code host is never an organization's claim.
	for _, p := range []string{"gitlab.com/*", "https://GitHub.com/**", "bitbucket.org/*"} {
		if _, err := create(tenantA.String(), p); !errors.Is(err, scopedom.ErrSharedCodeHost) {
			t.Errorf("%s: %v, want SHARED_CODE_HOST", p, err)
		}
	}

	// A namespace is stored in its canonical form, and another spelling of
	// it is a duplicate.
	ns, err := create(tenantA.String(), "https://GitLab.com/0xManhnv/**")
	if err != nil {
		t.Fatal(err)
	}
	if ns.Pattern() != "gitlab.com/0xmanhnv/*" {
		t.Fatalf("stored pattern %q", ns.Pattern())
	}
	var dup *scopedom.DuplicateError
	if _, err := create(tenantA.String(), "gitlab.com/0xmanhnv/*"); !errors.As(err, &dup) {
		t.Fatalf("second spelling: %v, want a duplicate", err)
	}

	// A host no other organization shares may be claimed whole.
	if _, err := create(tenantA.String(), "git.example.com/*"); err != nil {
		t.Fatalf("self-hosted host: %v", err)
	}

	// Another organization's entry is invisible and does not block its own.
	if _, err := create(tenantB.String(), "gitlab.com/0xmanhnv/*"); err != nil {
		t.Fatalf("tenant B's own entry: %v", err)
	}
	activeB, err := svc.ListActiveTargets(ctx, tenantB.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range activeB {
		if e.TenantID() != tenantB || e.Pattern() == "git.example.com/*" {
			t.Fatalf("tenant B lists %s of tenant %s", e.Pattern(), e.TenantID())
		}
	}
}
