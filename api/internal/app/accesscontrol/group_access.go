package accesscontrol

// Team access presets (docs/rfcs/RFC-127-team-access-presets.md).
//
// A team carries access without anyone managing roles: the team's access
// settings name one or more role templates (presets) and a scope mode. Each
// preset becomes a managed role of the team (roles.managed_group_id), bound to
// the team, so members hold it through the same view as any bound role
// (v_user_role_grants). "All assets" is a managed role with full data access
// and no permissions, so the data-scope engine, notifications and every
// full-data guard treat it exactly like has_full_data_access.
//
// Rules, on top of the role binding rules (group_role.go):
//
//   - a managed role is changed only here: not edited, deleted, assigned to a
//     person or bound to another team (service checks and database triggers);
//   - a team is privileged when any of its roles is privileged (all assets, or
//     a preset above the member level). Only an owner sets or changes the
//     access of a privileged team, or the team itself, with a recent sign-in,
//     and the change is audited at critical severity;
//   - adding or removing a member of a privileged managed team needs
//     team:members:write on top of the team permission, so a team lead who
//     holds only team permissions cannot put someone into it;
//   - owner and admin are never granted through a team (only custom roles bind);
//   - an outside member or service account never joins a team that sees all
//     assets (ErrExternalTeamFullData), and an outside member joining a team
//     with a preset above the member level is flagged for the invitation
//     checks, so their two-factor policy applies.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	groupdom "github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Team scope modes.
const (
	TeamScopeSpecific  = "specific"
	TeamScopeAllAssets = "all_assets"
)

// allAssetsTemplateID marks the managed role that gives a team every asset.
const allAssetsTemplateID = "team-all-assets"

// MaxTeamPresets bounds the presets of one team.
const MaxTeamPresets = 8

// ErrManagedRole refuses a hand change to a role a team manages.
var ErrManagedRole = fmt.Errorf("%w: this role belongs to a team's access settings; change it on the team", shared.ErrValidation)

// ErrPrivilegedTeamNeedsMembersManage refuses a membership change of a
// privileged managed team by someone without team:members:write.
var ErrPrivilegedTeamNeedsMembersManage = fmt.Errorf("%w: adding or removing people in a team with elevated access needs the members:write permission", ErrGrantForbidden)

// refuseManaged rejects a managed role on the paths that change a role by hand
// or hand it to a person.
func refuseManaged(r *roledom.Role) error {
	if r.IsManaged() {
		return ErrManagedRole
	}
	return nil
}

// TeamPresetView is one preset of a team, as the API shows it.
type TeamPresetView struct {
	TemplateID        string
	RoleID            string
	Name              string
	VersionTaken      int
	CurrentVersion    int
	UpdateAvailable   bool
	Privileged        bool
	HasFullDataAccess bool
}

// TeamAccessView is the access a team carries.
type TeamAccessView struct {
	Presets   []TeamPresetView
	ScopeMode string
	// Privileged: the team carries elevated access (all assets, or a preset
	// above the member level); only owners change it.
	Privileged bool
	// OtherRoles counts roles bound to the team by hand.
	OtherRoles int
}

// UserTeamAccessView is one role a person holds through a team.
type UserTeamAccessView struct {
	Grant      groupdom.UserTeamGrant
	Privileged bool
}

func (s *GroupService) teamAccessView(roles []*roledom.Role) TeamAccessView {
	v := TeamAccessView{Presets: []TeamPresetView{}, ScopeMode: TeamScopeSpecific}
	for _, r := range roles {
		if isPrivileged(r) {
			v.Privileged = true
		}
		if r.HasFullDataAccess() {
			v.ScopeMode = TeamScopeAllAssets
		}
		if !r.IsManaged() {
			v.OtherRoles++
			continue
		}
		t := r.Template()
		if t == nil || t.ID == allAssetsTemplateID {
			continue
		}
		p := TeamPresetView{
			TemplateID: t.ID, RoleID: r.ID().String(), Name: r.Name(),
			VersionTaken: t.Version, Privileged: isPrivileged(r), HasFullDataAccess: r.HasFullDataAccess(),
		}
		if st := TemplateStatusOf(r); st != nil {
			p.CurrentVersion = st.CurrentVersion
			p.UpdateAvailable = st.UpdateAvailable
		}
		v.Presets = append(v.Presets, p)
	}
	slices.SortFunc(v.Presets, func(a, b TeamPresetView) int { return strings.Compare(a.Name, b.Name) })
	return v
}

// GetTeamAccess returns the access a team carries.
func (s *GroupService) GetTeamAccess(ctx context.Context, tenantID, groupID string) (*TeamAccessView, error) {
	if err := s.requireBindings(); err != nil {
		return nil, err
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}
	g, err := s.groupForTenant(ctx, gid, tenantID)
	if err != nil {
		return nil, err
	}
	roles, err := s.boundRoles(ctx, g)
	if err != nil {
		return nil, err
	}
	v := s.teamAccessView(roles)
	return &v, nil
}

// ListUserTeamAccess returns the roles a person holds through their teams
// ("access from team X"). Another tenant's person has none.
func (s *GroupService) ListUserTeamAccess(ctx context.Context, tenantID string, userID shared.ID) ([]UserTeamAccessView, error) {
	if err := s.requireBindings(); err != nil {
		return nil, err
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	grants, err := s.bindings.ListUserTeamGrants(ctx, tid, userID)
	if err != nil {
		return nil, err
	}
	out := make([]UserTeamAccessView, 0, len(grants))
	for _, gr := range grants {
		r, err := s.roles.roleRepo.GetByID(ctx, asRoleID(tid), asRoleID(gr.RoleID))
		if err != nil {
			return nil, fmt.Errorf("load team role: %w", err)
		}
		out = append(out, UserTeamAccessView{Grant: gr, Privileged: isPrivileged(r)})
	}
	return out, nil
}

// managedRoleSpec describes a managed role to create.
type managedRoleSpec struct {
	templateID  string
	version     int
	name        string
	description string
	permissions []string
	fullData    bool
}

// presetSpec builds the managed role a template (or the all-assets scope)
// gives a team.
func presetSpec(templateID string) (managedRoleSpec, error) {
	if templateID == allAssetsTemplateID {
		return managedRoleSpec{
			templateID: allAssetsTemplateID, version: 1, name: "All assets",
			description: "Sees every asset of the organization. Managed by the team's access settings.",
			permissions: []string{}, fullData: true,
		}, nil
	}
	tpl, ok := permission.RoleTemplateByID(templateID)
	if !ok {
		return managedRoleSpec{}, fmt.Errorf("%w: unknown preset %q", shared.ErrValidation, templateID)
	}
	return managedRoleSpec{
		templateID: tpl.ID, version: tpl.Version, name: tpl.Name,
		description: tpl.Description + " Managed by the team's access settings.",
		permissions: permission.ToStrings(tpl.Permissions), fullData: tpl.HasFullDataAccess,
	}, nil
}

// createManagedRole creates the managed role of team g from spec.
func (s *RoleService) createManagedRole(ctx context.Context, g *groupdom.Group, spec managedRoleSpec, createdBy roledom.ID) (*roledom.Role, error) {
	if err := rejectAdminOnlyPermissions(spec.permissions); err != nil {
		return nil, err
	}
	if len(spec.permissions) > 0 {
		valid, invalid, err := s.permissionRepo.ValidatePermissions(ctx, spec.permissions)
		if err != nil {
			return nil, fmt.Errorf("validate preset permissions: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("%w: invalid permissions: %v", shared.ErrValidation, invalid)
		}
	}
	tenantID := asRoleID(g.TenantID())
	slug := "team-" + strings.ReplaceAll(g.ID().String(), "-", "")[:8] + "-" + spec.templateID
	r := roledom.New(tenantID, slug, spec.name, spec.description, 0, spec.fullData, spec.permissions, createdBy)
	r.SetTemplate(&roledom.TemplateOrigin{ID: spec.templateID, Version: spec.version, Permissions: spec.permissions})
	gid := asRoleID(g.ID())
	r.SetManagedGroup(&gid)
	if err := s.roleRepo.Create(ctx, r); err != nil {
		return nil, fmt.Errorf("create managed role: %w", err)
	}
	return r, nil
}

// SetTeamAccessInput sets the access a team carries.
type SetTeamAccessInput struct {
	GroupID string
	// Presets are role template ids; the team's presets become exactly this set.
	Presets   []string
	ScopeMode string
}

// wantedPresets turns the requested presets and scope mode into the managed
// roles the team should carry, keyed by template id.
func wantedPresets(in SetTeamAccessInput) (map[string]managedRoleSpec, error) {
	if in.ScopeMode != TeamScopeSpecific && in.ScopeMode != TeamScopeAllAssets {
		return nil, fmt.Errorf("%w: scope_mode must be %q or %q", shared.ErrValidation, TeamScopeSpecific, TeamScopeAllAssets)
	}
	want := map[string]managedRoleSpec{}
	for _, id := range in.Presets {
		if id == allAssetsTemplateID {
			return nil, fmt.Errorf("%w: unknown preset %q", shared.ErrValidation, id)
		}
		spec, err := presetSpec(id)
		if err != nil {
			return nil, err
		}
		want[id] = spec
	}
	if len(want) > MaxTeamPresets {
		return nil, fmt.Errorf("%w: a team has at most %d presets", shared.ErrValidation, MaxTeamPresets)
	}
	if in.ScopeMode == TeamScopeAllAssets {
		spec, _ := presetSpec(allAssetsTemplateID)
		want[allAssetsTemplateID] = spec
	}
	return want, nil
}

// accessChange is what setting a team's access adds and removes.
type accessChange struct {
	add    []managedRoleSpec
	remove []*roledom.Role
}

// diffAccess compares the wanted managed roles with the team's current roles.
// It also returns how many roles were bound by hand.
func diffAccess(want map[string]managedRoleSpec, current []*roledom.Role) (accessChange, int) {
	have := map[string]*roledom.Role{}
	handBound := 0
	for _, r := range current {
		t := r.Template()
		if !r.IsManaged() || t == nil {
			handBound++
			continue
		}
		have[t.ID] = r
	}
	var ch accessChange
	for id, spec := range want {
		if _, ok := have[id]; !ok {
			ch.add = append(ch.add, spec)
		}
	}
	for id, r := range have {
		if _, ok := want[id]; !ok {
			ch.remove = append(ch.remove, r)
		}
	}
	slices.SortFunc(ch.add, func(x, y managedRoleSpec) int { return strings.Compare(x.templateID, y.templateID) })
	slices.SortFunc(ch.remove, func(x, y *roledom.Role) int { return strings.Compare(x.Slug(), y.Slug()) })
	return ch, handBound
}

// authorizeAccessChange applies the grant rules to a change of team g's
// access by actor a. It returns whether the change touches elevated access.
func (s *GroupService) authorizeAccessChange(ctx context.Context, g *groupdom.Group, a grantActor, ch accessChange) (bool, error) {
	privileged, fullData := false, false
	for _, spec := range ch.add {
		if err := a.mayCarry(spec.permissions, spec.fullData); err != nil {
			return false, fmt.Errorf("%w (preset %q)", err, spec.name)
		}
		privileged = privileged || permission.IsPrivilegedRole(spec.permissions, spec.fullData)
		fullData = fullData || spec.fullData
	}
	for _, r := range ch.remove {
		if err := a.mayRevoke(r); err != nil {
			return false, err
		}
		privileged = privileged || isPrivileged(r)
	}
	if privileged {
		if err := s.requireOwnerStepUp(ctx, a); err != nil {
			return false, err
		}
	}
	if len(ch.add) > 0 && !a.owner {
		actor, err := shared.IDFromString(a.id)
		if err != nil {
			return false, fmt.Errorf("%w: invalid actor id format", shared.ErrValidation)
		}
		isMember, err := s.repo.IsMember(ctx, g.ID(), actor)
		if err != nil {
			return false, err
		}
		if isMember {
			return false, ErrSelfJoinRoleTeam
		}
	}
	if fullData {
		external, err := s.bindings.HasExternalMembers(ctx, g.TenantID(), g.ID())
		if err != nil {
			return false, err
		}
		if external {
			return false, ErrExternalTeamFullData
		}
	}
	return privileged, nil
}

// applyAccessChange removes and creates the managed roles. A call that fails
// midway is repeatable: the next one computes the remaining difference.
func (s *GroupService) applyAccessChange(ctx context.Context, g *groupdom.Group, a grantActor, ch accessChange, members []shared.ID, actx auditapp.AuditContext) error {
	createdBy, _ := roledom.ParseID(a.id)
	by := asSharedID(createdBy)
	for _, r := range ch.remove {
		if err := s.bindings.UnbindRole(ctx, g.TenantID(), g.ID(), asSharedID(r.ID())); err != nil {
			return err
		}
		if err := s.roles.roleRepo.Delete(ctx, asRoleID(g.TenantID()), r.ID()); err != nil {
			return fmt.Errorf("delete managed role: %w", err)
		}
		s.auditBinding(ctx, actx, g, r, false, len(members))
	}
	for _, spec := range ch.add {
		r, err := s.roles.createManagedRole(ctx, g, spec, createdBy)
		if err != nil {
			return err
		}
		if err := s.bindings.BindRole(ctx, g.TenantID(), g.ID(), asSharedID(r.ID()), &by); err != nil {
			_ = s.roles.roleRepo.Delete(ctx, asRoleID(g.TenantID()), r.ID())
			return err
		}
		s.auditBinding(ctx, actx, g, r, true, len(members))
	}
	return nil
}

// SetTeamAccess makes the team's presets and scope mode what the input says:
// it adds the managed roles that are missing, removes the ones no longer
// named and leaves the rest alone. A call that changes nothing is not an
// error and is not audited.
func (s *GroupService) SetTeamAccess(ctx context.Context, in SetTeamAccessInput, actx auditapp.AuditContext) (*TeamAccessView, error) {
	if err := s.requireBindings(); err != nil {
		return nil, err
	}
	gid, err := shared.IDFromString(in.GroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}
	want, err := wantedPresets(in)
	if err != nil {
		return nil, err
	}
	g, err := s.groupForTenant(ctx, gid, actx.TenantID)
	if err != nil {
		return nil, err
	}
	a, err := s.roles.loadGrantActor(ctx, asRoleID(g.TenantID()), actx.ActorID)
	if err != nil {
		return nil, err
	}
	if a.system {
		return nil, fmt.Errorf("%w: team access is set by a signed-in person", shared.ErrValidation)
	}
	// D13: without full data access the actor needs every asset of the team
	// in their own scope.
	if err := s.requireWholeGroupInScope(ctx, g); err != nil {
		return nil, err
	}
	current, err := s.boundRoles(ctx, g)
	if err != nil {
		return nil, err
	}
	ch, handBound := diffAccess(want, current)
	if handBound+len(want) > groupdom.MaxRoleBindingsPerGroup {
		return nil, groupdom.ErrTooManyBindings
	}
	if len(ch.add) == 0 && len(ch.remove) == 0 {
		v := s.teamAccessView(current)
		return &v, nil
	}
	privileged, err := s.authorizeAccessChange(ctx, g, a, ch)
	if err != nil {
		return nil, err
	}
	members, err := s.bindings.ListActiveMemberIDs(ctx, g.TenantID(), g.ID())
	if err != nil {
		return nil, err
	}
	applyErr := s.applyAccessChange(ctx, g, a, ch, members, actx)
	s.invalidateMembers(ctx, g.TenantID(), members)
	if applyErr != nil {
		return nil, applyErr
	}
	after, err := s.boundRoles(ctx, g)
	if err != nil {
		return nil, err
	}
	v := s.teamAccessView(after)
	s.auditAccessSet(ctx, actx, g, v, privileged, len(members))
	return &v, nil
}

func (s *GroupService) auditAccessSet(ctx context.Context, actx auditapp.AuditContext, g *groupdom.Group, v TeamAccessView, privileged bool, members int) {
	ids := make([]string, 0, len(v.Presets))
	for _, p := range v.Presets {
		ids = append(ids, p.TemplateID)
	}
	severity := audit.SeverityHigh
	if privileged || v.Privileged {
		severity = audit.SeverityCritical
	}
	actx.TenantID = g.TenantID().String()
	event := auditapp.NewSuccessEvent(audit.ActionGroupUpdated, audit.ResourceTypeGroup, g.ID().String()).
		WithResourceName(g.Name()).
		WithMessage(fmt.Sprintf("Access of team %q set: scope %s, %d preset(s)", g.Name(), v.ScopeMode, len(ids))).
		WithMetadata("access", "team").
		WithMetadata("scope_mode", v.ScopeMode).
		WithMetadata("presets", ids).
		WithMetadata("privileged", v.Privileged).
		WithMetadata("member_count", members).
		WithSeverity(severity)
	s.logAudit(ctx, actx, event)
}

// ErrNoPresetUpdate is returned when the preset has no template update.
var ErrNoPresetUpdate = fmt.Errorf("%w: this preset has no update to apply", shared.ErrValidation)

// UpgradeTeamPreset brings a preset of a team to its template's current
// version. version is the template version the editor reviewed; anything else
// is refused as stale. Full data access of the role is never changed by an
// update.
func (s *GroupService) UpgradeTeamPreset(ctx context.Context, groupID, templateID string, version int, actx auditapp.AuditContext) (*TeamAccessView, error) {
	if err := s.requireBindings(); err != nil {
		return nil, err
	}
	gid, err := shared.IDFromString(groupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}
	g, err := s.groupForTenant(ctx, gid, actx.TenantID)
	if err != nil {
		return nil, err
	}
	a, err := s.roles.loadGrantActor(ctx, asRoleID(g.TenantID()), actx.ActorID)
	if err != nil {
		return nil, err
	}
	if a.system {
		return nil, fmt.Errorf("%w: a preset is updated by a signed-in person", shared.ErrValidation)
	}
	if err := s.requireWholeGroupInScope(ctx, g); err != nil {
		return nil, err
	}
	current, err := s.boundRoles(ctx, g)
	if err != nil {
		return nil, err
	}
	var target *roledom.Role
	for _, r := range current {
		if t := r.Template(); r.IsManaged() && t != nil && t.ID == templateID {
			target = r
		}
	}
	if target == nil {
		return nil, fmt.Errorf("%w: preset not found on this team", shared.ErrNotFound)
	}
	st := TemplateStatusOf(target)
	if st == nil || !st.UpdateAvailable || templateID == allAssetsTemplateID {
		return nil, ErrNoPresetUpdate
	}
	if version != st.CurrentVersion {
		return nil, ErrTemplateUpdateStale
	}
	tpl, _ := permission.RoleTemplateByID(templateID)
	newPerms := permission.ToStrings(tpl.Permissions)
	if err := rejectAdminOnlyPermissions(newPerms); err != nil {
		return nil, err
	}
	if err := a.mayEdit(target, newPerms, target.HasFullDataAccess()); err != nil {
		return nil, err
	}
	if isPrivileged(target) || permission.IsPrivilegedRole(newPerms, target.HasFullDataAccess()) {
		if err := s.requireOwnerStepUp(ctx, a); err != nil {
			return nil, err
		}
	}
	if len(newPerms) > 0 {
		valid, invalid, err := s.roles.permissionRepo.ValidatePermissions(ctx, newPerms)
		if err != nil {
			return nil, fmt.Errorf("validate preset permissions: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("%w: invalid permissions: %v", shared.ErrValidation, invalid)
		}
	}
	members, err := s.bindings.ListActiveMemberIDs(ctx, g.TenantID(), g.ID())
	if err != nil {
		return nil, err
	}
	if err := target.SetPermissions(newPerms); err != nil {
		return nil, err
	}
	target.SetTemplate(&roledom.TemplateOrigin{ID: tpl.ID, Version: tpl.Version, Permissions: newPerms})
	if err := s.roles.roleRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("update managed role: %w", err)
	}
	s.invalidateMembers(ctx, g.TenantID(), members)
	after, err := s.boundRoles(ctx, g)
	if err != nil {
		return nil, err
	}
	v := s.teamAccessView(after)
	s.auditAccessSet(ctx, actx, g, v, isPrivileged(target), len(members))
	return &v, nil
}

// requirePrivilegedTeamOwner applies the owner-only rule to a change of the
// team itself when the team carries elevated access.
func (s *GroupService) requirePrivilegedTeamOwner(ctx context.Context, g *groupdom.Group, actorID string) error {
	roles, err := s.boundRoles(ctx, g)
	if err != nil {
		return err
	}
	for _, r := range roles {
		if r.IsManaged() && isPrivileged(r) {
			a, err := s.roles.loadGrantActor(ctx, asRoleID(g.TenantID()), actorID)
			if err != nil {
				return err
			}
			return s.requireOwnerStepUp(ctx, a)
		}
	}
	return nil
}
