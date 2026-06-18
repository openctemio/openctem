package scim

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/scimgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// GroupMembershipReader resolves a user's tenant membership (tenant.Repository
// satisfies it via GetMembership).
type GroupMembershipReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// RoleManager applies a member's role with full side effects (audit + cache).
// Implemented by an adapter over tenant.TenantService.UpdateMemberRole.
type RoleManager interface {
	UpdateMemberRole(ctx context.Context, tenantID, membershipID shared.ID, role string) error
}

// GroupService implements SCIM Group provisioning. Group membership drives a
// user's tenant role: a group whose displayName (case-insensitive) is a tenant
// role name (admin/member/viewer) maps its members to that role. A user's
// effective role is the highest-privilege role-group they belong to; when they
// belong to none, it defaults to member. 'owner' is never assignable via SCIM.
type GroupService struct {
	groups  scimgroup.Repository
	members GroupMembershipReader
	roles   RoleManager
	logger  *logger.Logger
}

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
	s.reconcileUsers(ctx, tenantID, in.MemberIDs)
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
	if err := s.groups.SetMembers(ctx, id, in.MemberIDs); err != nil {
		return nil, err
	}
	s.reconcileUsers(ctx, tenantID, union(existing.Members(), in.MemberIDs))
	return s.groups.GetByID(ctx, tenantID, id)
}

// PatchMembers applies incremental add/remove member operations (the common IdP
// PATCH) and reconciles affected users' roles.
func (s *GroupService) PatchMembers(ctx context.Context, tenantID, id shared.ID, add, remove []shared.ID) (*scimgroup.ScimGroup, error) {
	if _, err := s.groups.GetByID(ctx, tenantID, id); err != nil {
		return nil, err
	}
	if len(add) > 0 {
		if err := s.groups.AddMembers(ctx, id, add); err != nil {
			return nil, err
		}
	}
	if len(remove) > 0 {
		if err := s.groups.RemoveMembers(ctx, id, remove); err != nil {
			return nil, err
		}
	}
	s.reconcileUsers(ctx, tenantID, union(add, remove))
	return s.groups.GetByID(ctx, tenantID, id)
}

// ReplaceMembers sets the group's full membership (SCIM PATCH op=replace on
// members) and reconciles previous + new members.
func (s *GroupService) ReplaceMembers(ctx context.Context, tenantID, id shared.ID, memberIDs []shared.ID) (*scimgroup.ScimGroup, error) {
	existing, err := s.groups.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.groups.SetMembers(ctx, id, memberIDs); err != nil {
		return nil, err
	}
	s.reconcileUsers(ctx, tenantID, union(existing.Members(), memberIDs))
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
	s.reconcileUsers(ctx, tenantID, existing.Members())
	return nil
}

// reconcileUsers recomputes + applies each user's effective role from their
// current role-group memberships. Best-effort per user (logged, non-fatal) so
// one bad user doesn't fail the whole group operation.
func (s *GroupService) reconcileUsers(ctx context.Context, tenantID shared.ID, userIDs []shared.ID) {
	for _, uid := range dedupe(userIDs) {
		if err := s.reconcileUser(ctx, tenantID, uid); err != nil {
			s.logger.Warn("scim group: role reconciliation failed",
				"tenant_id", tenantID.String(), "user_id", uid.String(), "error", err)
		}
	}
}

func (s *GroupService) reconcileUser(ctx context.Context, tenantID, userID shared.ID) error {
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
	desired := effectiveRole(names)
	if string(m.Role()) == desired {
		return nil
	}
	return s.roles.UpdateMemberRole(ctx, tenantID, m.ID(), desired)
}

// effectiveRole maps a user's group display names to a tenant role: the
// highest-privilege role-named group wins; none → member (default).
func effectiveRole(groupNames []string) string {
	best := ""
	bestRank := 0
	for _, n := range groupNames {
		role, ok := roleFromGroupName(n)
		if !ok {
			continue
		}
		if r := roleRank(role); r > bestRank {
			bestRank = r
			best = role
		}
	}
	if best == "" {
		return string(tenantdom.RoleMember)
	}
	return best
}

func roleFromGroupName(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "admin":
		return string(tenantdom.RoleAdmin), true
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
