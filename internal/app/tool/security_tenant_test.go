package tool

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	tooldom "github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
)

// fakeToolRepo satisfies tooldom.Repository via embedding; only the methods the
// tests below exercise are overridden. Any other method panics if hit, which
// keeps the tests honest about what they actually depend on.
type fakeToolRepo struct {
	tooldom.Repository
	tool    *tooldom.Tool
	updated bool
}

func (f *fakeToolRepo) GetByID(context.Context, shared.ID) (*tooldom.Tool, error) {
	return f.tool, nil
}

func (f *fakeToolRepo) Update(context.Context, *tooldom.Tool) error {
	f.updated = true
	return nil
}

func newToolTestService(repo tooldom.Repository) *Service {
	return &Service{toolRepo: repo, logger: logger.NewNop()}
}

// ListTools must fail closed when no caller tenant is supplied — otherwise the
// query would return every tenant's private custom tools.
func TestListTools_RequiresTenant(t *testing.T) {
	s := newToolTestService(&fakeToolRepo{})
	_, err := s.ListTools(context.Background(), ListInput{TenantID: ""})
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error for empty tenant, got %v", err)
	}
}

// A tenant must not be able to (de)activate a platform tool — those are shared
// across all tenants and agents run them.
func TestActivateTool_RejectsPlatformTool(t *testing.T) {
	platform, err := tooldom.NewTool("nmap", "Nmap", nil, tooldom.InstallBinary)
	if err != nil {
		t.Fatalf("build platform tool: %v", err)
	}
	repo := &fakeToolRepo{tool: platform}
	s := newToolTestService(repo)

	if _, err := s.ActivateTool(context.Background(), shared.NewID().String(), platform.ID.String()); err == nil {
		t.Fatal("expected activation of a platform tool by a tenant to be rejected")
	}
	if repo.updated {
		t.Fatal("platform tool must not be mutated by a tenant")
	}
}

// A tenant must not be able to (de)activate another tenant's custom tool.
func TestActivateTool_RejectsForeignTenantCustomTool(t *testing.T) {
	owner := shared.NewID()
	attacker := shared.NewID()
	custom, err := tooldom.NewTenantCustomTool(owner, shared.ID{}, "mytool", "My Tool", nil, tooldom.InstallBinary)
	if err != nil {
		t.Fatalf("build custom tool: %v", err)
	}
	repo := &fakeToolRepo{tool: custom}
	s := newToolTestService(repo)

	if _, err := s.ActivateTool(context.Background(), attacker.String(), custom.ID.String()); err == nil {
		t.Fatal("expected activation of another tenant's custom tool to be rejected")
	}
	if repo.updated {
		t.Fatal("foreign tenant's custom tool must not be mutated")
	}
}

// The owning tenant CAN activate its own custom tool — the guard tightens, it
// does not break the legitimate path.
func TestActivateTool_AllowsOwningTenant(t *testing.T) {
	owner := shared.NewID()
	custom, err := tooldom.NewTenantCustomTool(owner, shared.ID{}, "mytool", "My Tool", nil, tooldom.InstallBinary)
	if err != nil {
		t.Fatalf("build custom tool: %v", err)
	}
	repo := &fakeToolRepo{tool: custom}
	s := newToolTestService(repo)

	if _, err := s.ActivateTool(context.Background(), owner.String(), custom.ID.String()); err != nil {
		t.Fatalf("owning tenant must be allowed to activate its own tool: %v", err)
	}
	if !repo.updated {
		t.Fatal("expected the owning tenant's activation to persist")
	}
}

// DeactivateTool enforces the same tenant-ownership gate as ActivateTool.
func TestDeactivateTool_RejectsForeignTenantCustomTool(t *testing.T) {
	owner := shared.NewID()
	attacker := shared.NewID()
	custom, err := tooldom.NewTenantCustomTool(owner, shared.ID{}, "mytool", "My Tool", nil, tooldom.InstallBinary)
	if err != nil {
		t.Fatalf("build custom tool: %v", err)
	}
	repo := &fakeToolRepo{tool: custom}
	s := newToolTestService(repo)

	if _, err := s.DeactivateTool(context.Background(), attacker.String(), custom.ID.String()); err == nil {
		t.Fatal("expected deactivation of another tenant's custom tool to be rejected")
	}
	if repo.updated {
		t.Fatal("foreign tenant's custom tool must not be mutated")
	}
}
