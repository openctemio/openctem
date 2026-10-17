package accesscontrol

// Role templates and the custom roles created from them
// (docs/rfcs/RFC-095-role-templates-and-invitations.md).
//
// A template is copied into the organization: the role is the organization's
// own and never changes when the template does. The role records the template
// version and the permissions it took; when the catalog has a newer version,
// TemplateStatusOf reports the difference and ApplyTemplateUpdate applies it
// through UpdateRole, so the editor ceiling, the admin-only refusal and the
// team-binding guard apply exactly as for a hand edit. The role's own edits
// are kept: the update adds what the template added and removes what it
// removed. Full data access is never changed by an update.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TemplateStatus describes how a custom role relates to its template.
type TemplateStatus struct {
	TemplateID      string
	TemplateName    string
	VersionTaken    int
	CurrentVersion  int
	UpdateAvailable bool
	// Retired: the template is no longer in the catalog; the role stays as is.
	Retired bool
	Diff    permission.TemplateDiff
}

// TemplateStatusOf returns the template status of a role, or nil for a role
// not created from a template.
func TemplateStatusOf(r *roledom.Role) *TemplateStatus {
	origin := r.Template()
	if origin == nil {
		return nil
	}
	st := &TemplateStatus{TemplateID: origin.ID, VersionTaken: origin.Version,
		Diff: permission.TemplateDiff{Added: []string{}, Removed: []string{}}}
	tpl, ok := permission.RoleTemplateByID(origin.ID)
	if !ok {
		st.Retired = true
		return st
	}
	st.TemplateName = tpl.Name
	st.CurrentVersion = tpl.Version
	if tpl.Version > origin.Version {
		st.Diff = permission.DiffTemplate(origin.Permissions, tpl)
		st.UpdateAvailable = true
	}
	return st
}

// ErrTemplateUpdateStale refuses applying a template version other than the
// one the editor reviewed.
var ErrTemplateUpdateStale = fmt.Errorf("%w: the template changed since you reviewed it; review the update again", shared.ErrConflict)

// ErrNoTemplateUpdate is returned when the role has no template update to apply.
var ErrNoTemplateUpdate = fmt.Errorf("%w: this role has no template update to apply", shared.ErrValidation)

// RoleTemplateStatus returns the template status of one of the tenant's
// custom roles. Another tenant's role is not found.
func (s *RoleService) RoleTemplateStatus(ctx context.Context, tenantID, roleID string) (*roledom.Role, *TemplateStatus, error) {
	r, err := s.GetRole(ctx, tenantID, roleID)
	if err != nil {
		return nil, nil, err
	}
	return r, TemplateStatusOf(r), nil
}

// ApplyTemplateUpdate brings a custom role up to its template's current
// version. version is the template version the editor reviewed; anything
// else is refused as stale.
func (s *RoleService) ApplyTemplateUpdate(ctx context.Context, tenantID, roleID string, version int, actx auditapp.AuditContext) (*roledom.Role, error) {
	r, err := s.GetRole(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	if r.IsSystem() || r.TenantID() == nil {
		return nil, ErrNoTemplateUpdate
	}
	st := TemplateStatusOf(r)
	if st == nil || !st.UpdateAvailable {
		return nil, ErrNoTemplateUpdate
	}
	if version != st.CurrentVersion {
		return nil, ErrTemplateUpdateStale
	}
	tpl, _ := permission.RoleTemplateByID(st.TemplateID)
	perms := permission.ApplyTemplateDiff(r.Permissions(), st.Diff)
	return s.UpdateRole(ctx, tenantID, roleID, UpdateRoleInput{
		Permissions: perms,
		templateOrigin: &roledom.TemplateOrigin{
			ID: tpl.ID, Version: tpl.Version, Permissions: permission.ToStrings(tpl.Permissions),
		},
	}, actx)
}
