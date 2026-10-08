package scim

import (
	"context"
	"fmt"
	"sort"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scimgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GroupMembershipReader resolves a user's tenant membership (tenant.Repository
// satisfies it via GetMembership).
type GroupMembershipReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// RoleManager applies a member's role with full side effects (audit + cache).
// Implemented by an adapter over tenant.TenantService.UpdateMemberRole.
//
// actorID is the person whose action caused the change (a mapping saved in
// the console), or nil when the identity provider caused it through a SCIM
// token. With an actor, the tenant service's peer-administrator rule applies
// to that person; without one, the audit entry names the SCIM token (see
// audit.WithSCIMTokenActor). The entry is severity High either way.
type RoleManager interface {
	UpdateMemberRole(ctx context.Context, tenantID, membershipID shared.ID, role string, actorID *shared.ID) error
}

// AuditLogger writes tenant audit events (satisfied by *audit.AuditService).
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// ErrOwnerRequiredForAdminMapping is returned when someone other than the
// organization's owner tries to map a SCIM group to admin, or to change or
// remove a mapping to admin. A mapping to admin decides who administers the
// organization, which is the owner's call (owner-only rule for changing
// administrators, 23b S-H1).
var ErrOwnerRequiredForAdminMapping = fmt.Errorf(
	"%w: only the organization owner can map a SCIM group to the admin role or change such a mapping", shared.ErrForbidden)

// GroupService implements SCIM Group provisioning. Group membership drives a
// user's tenant role: a group whose displayName (case-insensitive) is member
// or viewer maps its members to that role, and any group can be mapped to a
// role explicitly (SetRoleMappings). A user's effective role is the
// highest-privilege role-group they belong to; when they belong to none, it
// defaults to member.
//
// The admin role is under the owner's control:
//   - only a mapping the owner configured can grant admin (a group named
//     "admin" grants nothing by name alone);
//   - SCIM removes admin from someone only once the owner has configured at
//     least one admin mapping, so an administrator appointed by hand is never
//     demoted by an identity-provider push;
//   - 'owner' is never assignable via SCIM, and the owner is never re-roled.
type GroupService struct {
	groups  scimgroup.Repository
	members GroupMembershipReader
	roles   RoleManager
	audit   AuditLogger
	logger  *logger.Logger
}

// SetAuditService wires the audit log for mapping changes.
func (s *GroupService) SetAuditService(a AuditLogger) { s.audit = a }

// NewGroupService wires the service.
func NewGroupService(groups scimgroup.Repository, members GroupMembershipReader, roles RoleManager, log *logger.Logger) *GroupService {
	return &GroupService{groups: groups, members: members, roles: roles, logger: log.With("service", "scim-groups")}
}

// GroupInput is a normalised SCIM Group create/replace request.
type GroupInput struct {
	DisplayName string
	ExternalID  string
	MemberIDs   []shared.ID
}

// Create provisions a group and reconciles the role of every member.
func (s *GroupService) Create(ctx context.Context, tenantID shared.ID, in GroupInput) (*scimgroup.ScimGroup, error) {
	if strings.TrimSpace(in.DisplayName) == "" {
		return nil, fmt.Errorf("%w: displayName is required", shared.ErrValidation)
	}
	g := scimgroup.New(shared.NewID(), tenantID, in.DisplayName, in.ExternalID, in.MemberIDs)
	if err := s.groups.Create(ctx, g); err != nil {
		return nil, err
	}
	s.reconcileUsers(ctx, tenantID, in.MemberIDs, nil)
	return g, nil
}

// Get returns a group scoped to the tenant.
func (s *GroupService) Get(ctx context.Context, tenantID, id shared.ID) (*scimgroup.ScimGroup, error) {
	return s.groups.GetByID(ctx, tenantID, id)
}

// List returns the tenant's groups.
func (s *GroupService) List(ctx context.Context, tenantID shared.ID) ([]*scimgroup.ScimGroup, error) {
	return s.groups.ListByTenant(ctx, tenantID)
}

// Replace (PUT) sets the group's displayName + full membership, reconciling the
// roles of both the previous and new members.
func (s *GroupService) Replace(ctx context.Context, tenantID, id shared.ID, in GroupInput) (*scimgroup.ScimGroup, error) {
	existing, err := s.groups.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.DisplayName) != "" && in.DisplayName != existing.DisplayName() {
		if uerr := s.groups.UpdateDisplayName(ctx, tenantID, id, in.DisplayName); uerr != nil {
			return nil, uerr
		}
	}
	if err := s.groups.SetMembers(ctx, tenantID, id, in.MemberIDs); err != nil {
		return nil, err
	}
	s.reconcileUsers(ctx, tenantID, union(existing.Members(), in.MemberIDs), nil)
	return s.groups.GetByID(ctx, tenantID, id)
}

// PatchMembers applies incremental add/remove member operations (the common IdP
// PATCH) and reconciles affected users' roles.
func (s *GroupService) PatchMembers(ctx context.Context, tenantID, id shared.ID, add, remove []shared.ID) (*scimgroup.ScimGroup, error) {
	if _, err := s.groups.GetByID(ctx, tenantID, id); err != nil {
		return nil, err
	}
	if len(add) > 0 {
		if err := s.groups.AddMembers(ctx, tenantID, id, add); err != nil {
			return nil, err
		}
	}
	if len(remove) > 0 {
		if err := s.groups.RemoveMembers(ctx, tenantID, id, remove); err != nil {
			return nil, err
		}
	}
	s.reconcileUsers(ctx, tenantID, union(add, remove), nil)
	return s.groups.GetByID(ctx, tenantID, id)
}

// ReplaceMembers sets the group's full membership (SCIM PATCH op=replace on
// members) and reconciles previous + new members.
func (s *GroupService) ReplaceMembers(ctx context.Context, tenantID, id shared.ID, memberIDs []shared.ID) (*scimgroup.ScimGroup, error) {
	existing, err := s.groups.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.groups.SetMembers(ctx, tenantID, id, memberIDs); err != nil {
		return nil, err
	}
	s.reconcileUsers(ctx, tenantID, union(existing.Members(), memberIDs), nil)
	return s.groups.GetByID(ctx, tenantID, id)
}

// Delete removes the group and reconciles its former members' roles.
func (s *GroupService) Delete(ctx context.Context, tenantID, id shared.ID) error {
	existing, err := s.groups.GetByID(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.groups.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	s.reconcileUsers(ctx, tenantID, existing.Members(), nil)
	return nil
}

// reconcileUsers recomputes + applies each user's effective role from their
// current role-group memberships. Best-effort per user (logged, non-fatal) so
// one bad user doesn't fail the whole group operation. actorID: see RoleManager.
func (s *GroupService) reconcileUsers(ctx context.Context, tenantID shared.ID, userIDs []shared.ID, actorID *shared.ID) {
	for _, uid := range dedupe(userIDs) {
		if err := s.reconcileUser(ctx, tenantID, uid, actorID); err != nil {
			s.logger.Warn("scim group: role reconciliation failed",
				"tenant_id", tenantID.String(), "user_id", uid.String(), "error", err)
		}
	}
}

func (s *GroupService) reconcileUser(ctx context.Context, tenantID, userID shared.ID, actorID *shared.ID) error {
	m, err := s.members.GetMembership(ctx, userID, tenantID)
	if err != nil || m == nil {
		// Not a tenant member → nothing to reconcile (the SCIM Users path owns
		// membership). A lookup miss is expected here, not an error.
		return nil //nolint:nilerr // non-member is a skip, not a failure
	}
	if m.IsOwner() {
		return nil // never reassign the owner via SCIM
	}
	names, err := s.groups.RoleGroupNamesForUser(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("group names: %w", err)
	}
	mappings, err := s.groups.GetRoleMappings(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("role mappings: %w", err)
	}
	desired := effectiveRole(names, mappings)
	current := string(m.Role())
	if desired == "" {
		// No role group: least privilege, nothing is raised. Only an
		// administrator falls back (to member), so leaving the admin group
		// still removes admin.
		if current != string(tenantdom.RoleAdmin) {
			return nil
		}
		desired = string(tenantdom.RoleMember)
	}
	if current == desired {
		return nil
	}
	if desired == string(tenantdom.RoleOwner) {
		return fmt.Errorf("%w: SCIM never assigns the owner role", shared.ErrForbidden)
	}
	if current == string(tenantdom.RoleAdmin) && !ownerManagesAdminsViaSCIM(mappings) {
		// An administrator appointed outside SCIM stays one: SCIM takes the
		// admin role away only after the owner configured an admin mapping.
		s.logger.Info("scim group: administrator left unchanged (no owner-configured admin mapping)",
			"tenant_id", tenantID.String(), "user_id", userID.String(), "would_be", desired)
		return nil
	}
	return s.roles.UpdateMemberRole(ctx, tenantID, m.ID(), desired, actorID)
}

// ownerManagesAdminsViaSCIM reports whether the owner configured at least one
// group → admin mapping, i.e. opted into SCIM deciding who is an admin.
func ownerManagesAdminsViaSCIM(mappings map[string]scimgroup.RoleMapping) bool {
	for _, m := range mappings {
		if m.Role == string(tenantdom.RoleAdmin) && m.ConfiguredByOwner {
			return true
		}
	}
	return false
}

// GetRoleMappings returns the tenant's configured group → role overrides.
func (s *GroupService) GetRoleMappings(ctx context.Context, tenantID shared.ID) (map[string]string, error) {
	mappings, err := s.groups.GetRoleMappings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(mappings))
	for name, m := range mappings {
		out[name] = m.Role
	}
	return out, nil
}

// SetRoleMappings replaces the tenant's group → role overrides and
// re-reconciles every current group member so the change takes effect
// immediately. actx names the person saving (ActorID required).
//
//   - Roles are admin, member or viewer; 'owner' is rejected.
//   - Adding, changing or removing a mapping to admin requires the actor to
//     be the organization's owner (checked against the membership table, not
//     the token, inside the write transaction); anyone else gets
//     ErrOwnerRequiredForAdminMapping and nothing is written.
//   - Each changed mapping records who set it and whether they were the
//     owner; an unchanged mapping keeps its provenance.
//   - The change is audited (before/after per group, severity High), and the
//     role changes it causes are made as the actor, so the peer-administrator
//     rule and the audit trail both name them.
func (s *GroupService) SetRoleMappings(ctx context.Context, tenantID shared.ID, mappings map[string]string, actx auditapp.AuditContext) error {
	actorID, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return fmt.Errorf("%w: an acting user is required", shared.ErrValidation)
	}
	desired := make(map[string]string, len(mappings))
	for name, role := range mappings {
		r := strings.ToLower(strings.TrimSpace(role))
		switch r {
		case string(tenantdom.RoleAdmin), string(tenantdom.RoleMember), string(tenantdom.RoleViewer):
		default:
			return fmt.Errorf("%w: role %q must be admin, member, or viewer", shared.ErrValidation, role)
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			return fmt.Errorf("%w: group name must not be empty", shared.ErrValidation)
		}
		desired[key] = r
	}
	actorIsOwner := s.isActiveOwner(ctx, actorID, tenantID)

	var diffs []mappingDiff
	err = s.groups.ReplaceRoleMappings(ctx, tenantID, func(current map[string]scimgroup.RoleMapping) (map[string]scimgroup.RoleMapping, error) {
		diffs = diffMappings(current, desired)
		for _, d := range diffs {
			if d.touchesAdmin() && !actorIsOwner {
				return nil, ErrOwnerRequiredForAdminMapping
			}
		}
		next := make(map[string]scimgroup.RoleMapping, len(desired))
		for key, role := range desired {
			if old, ok := current[key]; ok && old.Role == role {
				next[key] = old // unchanged: keep who configured it
				continue
			}
			by := actorID
			next[key] = scimgroup.RoleMapping{Role: role, ConfiguredBy: &by, ConfiguredByOwner: actorIsOwner}
		}
		return next, nil
	})
	if err != nil {
		return err
	}
	s.auditMappingChange(ctx, tenantID, actx, diffs)

	// Re-reconcile every member of the tenant's groups under the new mapping.
	groups, err := s.groups.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	var affected []shared.ID
	for _, g := range groups {
		affected = append(affected, g.Members()...)
	}
	s.reconcileUsers(ctx, tenantID, affected, &actorID)
	return nil
}

// isActiveOwner reads the actor's membership; any failure is "not the owner".
func (s *GroupService) isActiveOwner(ctx context.Context, userID, tenantID shared.ID) bool {
	m, err := s.members.GetMembership(ctx, userID, tenantID)
	return err == nil && m != nil && m.IsOwner() && !m.IsSuspended()
}

// mappingDiff is one group whose mapped role changes ("" = no mapping).
type mappingDiff struct {
	group, before, after string
}

func (d mappingDiff) touchesAdmin() bool {
	return d.before == string(tenantdom.RoleAdmin) || d.after == string(tenantdom.RoleAdmin)
}

func diffMappings(current map[string]scimgroup.RoleMapping, desired map[string]string) []mappingDiff {
	var out []mappingDiff
	for key, old := range current {
		if role, ok := desired[key]; !ok || role != old.Role {
			out = append(out, mappingDiff{group: key, before: old.Role, after: desired[key]})
		}
	}
	for key, role := range desired {
		if _, ok := current[key]; !ok {
			out = append(out, mappingDiff{group: key, after: role})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].group < out[j].group })
	return out
}

func (s *GroupService) auditMappingChange(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext, diffs []mappingDiff) {
	if s.audit == nil || len(diffs) == 0 {
		return
	}
	changes := auditdom.NewChanges()
	adminChanged := false
	for _, d := range diffs {
		changes.Set("mapping:"+d.group, d.before, d.after)
		adminChanged = adminChanged || d.touchesAdmin()
	}
	actx.TenantID = tenantID.String()
	event := auditapp.NewSuccessEvent(auditdom.ActionSCIMGroupMappingsUpdated, auditdom.ResourceTypeSCIMGroupMapping, tenantID.String()).
		WithChanges(changes).
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("admin_mapping_changed", adminChanged).
		WithMetadata("groups_changed", len(diffs)).
		WithMessage(fmt.Sprintf("SCIM group role mappings changed (%d group(s))", len(diffs)))
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("scim group: audit of mapping change failed", "tenant_id", tenantID.String(), "error", err)
	}
}

// effectiveRole maps a user's group display names to a tenant role. A
// per-tenant mapping (keyed by lowercased display name) takes precedence; groups
// with no mapping fall back to a name-match default (member, viewer). The
// highest-privilege match wins. No match returns "": the caller keeps the
// current role (a group change never raises anyone by default) except that an
// administrator falls back to member. Admin comes only from a mapping the
// owner configured.
func effectiveRole(groupNames []string, mappings map[string]scimgroup.RoleMapping) string {
	best := ""
	bestRank := 0
	for _, n := range groupNames {
		role, ok := resolveGroupRole(n, mappings)
		if !ok {
			continue
		}
		if r := roleRank(role); r > bestRank {
			bestRank = r
			best = role
		}
	}
	return best
}

// resolveGroupRole resolves a single group name to a role: the tenant mapping
// first, then the built-in name-match default. A mapping to admin counts only
// when the owner configured it.
func resolveGroupRole(name string, mappings map[string]scimgroup.RoleMapping) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if m, ok := mappings[key]; ok {
		if m.Role == string(tenantdom.RoleAdmin) && !m.ConfiguredByOwner {
			return "", false
		}
		return m.Role, true
	}
	return roleFromGroupName(name)
}

// roleFromGroupName is the name-match default. There is no "admin" default:
// an identity-provider group named "admin" must not make anyone an
// administrator unless the owner maps it.
func roleFromGroupName(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "member":
		return string(tenantdom.RoleMember), true
	case "viewer":
		return string(tenantdom.RoleViewer), true
	}
	return "", false
}

func roleRank(role string) int {
	switch role {
	case string(tenantdom.RoleAdmin):
		return 3
	case string(tenantdom.RoleMember):
		return 2
	case string(tenantdom.RoleViewer):
		return 1
	}
	return 0
}

func dedupe(ids []shared.ID) []shared.ID {
	seen := make(map[shared.ID]bool, len(ids))
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func union(a, b []shared.ID) []shared.ID {
	return dedupe(append(append([]shared.ID{}, a...), b...))
}
