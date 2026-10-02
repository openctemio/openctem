package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/role"
)

// GET /roles/{roleId}/members for another tenant's role answered 200 [].
func TestListRoleMembers_ForeignRoleNotFound(t *testing.T) {
	svc, repo, _ := newTestRoleService()
	foreign := seedCustomRole(repo, role.NewID(), "foreign", "Foreign", nil)

	_, err := svc.ListRoleMembers(context.Background(), role.NewID().String(), foreign.ID().String())
	if !errors.Is(err, role.ErrRoleNotFound) {
		t.Fatalf("want role not found, got %v", err)
	}
	own := seedCustomRole(repo, *foreign.TenantID(), "own", "Own", nil)
	if _, err := svc.ListRoleMembers(context.Background(), foreign.TenantID().String(), own.ID().String()); err != nil {
		t.Fatalf("own role: %v", err)
	}
}
