package accesscontrol

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIAnalystRoles gives AI analysts the role of their preset through the role
// service, as the acting person: the role is created from the preset's
// template on first use, and assigning it passes the role grant ceiling
// like any other assignment (docs/architecture/ai-analysis.md).
type AIAnalystRoles struct{ Roles *RoleService }

// aiAnalystRoleLevel is the hierarchy level of the preset roles (well below
// administrators).
const aiAnalystRoleLevel = 10

// EnsurePresetRole returns the organization's role for templateID, creating
// it first when the organization has none.
func (a AIAnalystRoles) EnsurePresetRole(ctx context.Context, tenantID shared.ID, templateID string, actx auditapp.AuditContext) (shared.ID, error) {
	tid := tenantID.String()
	r, err := a.Roles.GetRoleBySlug(ctx, &tid, templateID)
	if err == nil {
		return shared.IDFromString(r.ID().String())
	}
	if !errors.Is(err, roledom.ErrRoleNotFound) {
		return shared.ID{}, err
	}
	tpl, ok := permission.RoleTemplateByID(templateID)
	if !ok {
		return shared.ID{}, fmt.Errorf("%w: unknown role template", shared.ErrValidation)
	}
	created, err := a.Roles.CreateRole(ctx, CreateRoleInput{
		TenantID: tid, Slug: tpl.ID, Name: tpl.Name, Description: tpl.Description,
		HierarchyLevel: aiAnalystRoleLevel, Permissions: permission.ToStrings(tpl.Permissions), TemplateID: tpl.ID,
	}, actx.ActorID, actx)
	if err != nil {
		return shared.ID{}, err
	}
	return shared.IDFromString(created.ID().String())
}

// SetRoles replaces the analyst's custom roles, as the acting person.
func (a AIAnalystRoles) SetRoles(ctx context.Context, tenantID, userID shared.ID, roleIDs []shared.ID, actx auditapp.AuditContext) error {
	ids := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		ids = append(ids, id.String())
	}
	return a.Roles.SetUserRoles(ctx, SetUserRolesInput{TenantID: tenantID.String(), UserID: userID.String(), RoleIDs: ids}, actx.ActorID, actx)
}
