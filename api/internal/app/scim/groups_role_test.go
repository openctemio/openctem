package scim

import (
	"context"
	"errors"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scimgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestEffectiveRole(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   string
	}{
		{"no groups → member default", nil, "member"},
		{"non-role groups → member default", []string{"Engineering", "All Staff"}, "member"},
		{"viewer only", []string{"viewer"}, "viewer"},
		{"member only", []string{"member"}, "member"},
		// No name default for admin: a group named "admin" grants nothing
		// unless the owner maps it (23b S-H1).
		{"admin name alone grants nothing", []string{"admin"}, "member"},
		{"admin name does not beat viewer", []string{"viewer", "admin"}, "viewer"},
		{"member wins over viewer", []string{"viewer", "member"}, "member"},
		{"case-insensitive", []string{"VIEWER"}, "viewer"},
		{"owner is never mapped", []string{"owner"}, "member"},
		{"role group mixed with custom", []string{"Engineering", "viewer"}, "viewer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveRole(tc.groups, nil); got != tc.want {
				t.Errorf("effectiveRole(%v, nil) = %q, want %q", tc.groups, got, tc.want)
			}
		})
	}
}

func TestEffectiveRole_WithMappings(t *testing.T) {
	mappings := map[string]scimgroup.RoleMapping{
		"acme-openctem-admins":  {Role: "admin", ConfiguredByOwner: true},
		"acme-openctem-readers": {Role: "viewer"},
		"legacy-admins":         {Role: "admin"}, // predates provenance / not set by the owner
		"admin":                 {Role: "admin", ConfiguredByOwner: true},
	}
	tests := []struct {
		name   string
		groups []string
		want   string
	}{
		{"owner-configured mapping grants admin", []string{"Acme-OpenCTEM-Admins"}, "admin"},
		{"owner mapped the literal admin group", []string{"admin"}, "admin"},
		{"custom name mapped to viewer", []string{"Acme-OpenCTEM-Readers"}, "viewer"},
		{"case-insensitive custom mapping", []string{"ACME-OPENCTEM-ADMINS"}, "admin"},
		{"mapping wins highest across groups", []string{"Acme-OpenCTEM-Readers", "Acme-OpenCTEM-Admins"}, "admin"},
		{"admin mapping not set by the owner grants nothing", []string{"Legacy-Admins"}, "member"},
		{"non-owner admin mapping does not beat viewer", []string{"Legacy-Admins", "Acme-OpenCTEM-Readers"}, "viewer"},
		{"unmapped falls back to name-match", []string{"viewer"}, "viewer"},
		{"unmapped custom group → member default", []string{"Engineering"}, "member"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveRole(tc.groups, mappings); got != tc.want {
				t.Errorf("effectiveRole(%v, mappings) = %q, want %q", tc.groups, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Service-level tests: owner-only admin mappings and SCIM-driven role changes.
// ---------------------------------------------------------------------------

type fakeGroupRepo struct {
	groups   map[shared.ID]*scimgroup.ScimGroup
	mappings map[string]scimgroup.RoleMapping
}

func newFakeGroupRepo() *fakeGroupRepo {
	return &fakeGroupRepo{groups: map[shared.ID]*scimgroup.ScimGroup{}, mappings: map[string]scimgroup.RoleMapping{}}
}

func (f *fakeGroupRepo) Create(_ context.Context, g *scimgroup.ScimGroup) error {
	f.groups[g.ID()] = g
	return nil
}
func (f *fakeGroupRepo) GetByID(_ context.Context, _, id shared.ID) (*scimgroup.ScimGroup, error) {
	if g, ok := f.groups[id]; ok {
		return g, nil
	}
	return nil, scimgroup.ErrNotFound
}
func (f *fakeGroupRepo) ListByTenant(_ context.Context, _ shared.ID) ([]*scimgroup.ScimGroup, error) {
	out := make([]*scimgroup.ScimGroup, 0, len(f.groups))
	for _, g := range f.groups {
		out = append(out, g)
	}
	return out, nil
}
func (f *fakeGroupRepo) UpdateDisplayName(_ context.Context, _, id shared.ID, n string) error {
	f.groups[id].SetDisplayName(n)
	return nil
}
func (f *fakeGroupRepo) Delete(_ context.Context, _, id shared.ID) error {
	delete(f.groups, id)
	return nil
}
func (f *fakeGroupRepo) SetMembers(_ context.Context, _, id shared.ID, users []shared.ID) error {
	f.groups[id].SetMembers(users)
	return nil
}
func (f *fakeGroupRepo) AddMembers(_ context.Context, _, id shared.ID, users []shared.ID) error {
	f.groups[id].SetMembers(union(f.groups[id].Members(), users))
	return nil
}
func (f *fakeGroupRepo) RemoveMembers(_ context.Context, _, id shared.ID, users []shared.ID) error {
	drop := map[shared.ID]bool{}
	for _, u := range users {
		drop[u] = true
	}
	var keep []shared.ID
	for _, u := range f.groups[id].Members() {
		if !drop[u] {
			keep = append(keep, u)
		}
	}
	f.groups[id].SetMembers(keep)
	return nil
}
func (f *fakeGroupRepo) RoleGroupNamesForUser(_ context.Context, _, userID shared.ID) ([]string, error) {
	var names []string
	for _, g := range f.groups {
		for _, m := range g.Members() {
			if m == userID {
				names = append(names, g.DisplayName())
			}
		}
	}
	return names, nil
}
func (f *fakeGroupRepo) GetRoleMappings(_ context.Context, _ shared.ID) (map[string]scimgroup.RoleMapping, error) {
	out := make(map[string]scimgroup.RoleMapping, len(f.mappings))
	for k, v := range f.mappings {
		out[k] = v
	}
	return out, nil
}
func (f *fakeGroupRepo) ReplaceRoleMappings(ctx context.Context, tenantID shared.ID, plan scimgroup.RoleMappingPlan) error {
	cur, _ := f.GetRoleMappings(ctx, tenantID)
	next, err := plan(cur)
	if err != nil {
		return err
	}
	f.mappings = next
	return nil
}

type roleCall struct {
	membershipID shared.ID
	role         string
	actor        *shared.ID
}

// roleRecorder applies role changes to the member store and records them.
type roleRecorder struct {
	members *memberStore
	calls   []roleCall
}

func (r *roleRecorder) UpdateMemberRole(_ context.Context, _, membershipID shared.ID, role string, actorID *shared.ID) error {
	r.calls = append(r.calls, roleCall{membershipID: membershipID, role: role, actor: actorID})
	mem := r.members.find(membershipID)
	if mem == nil {
		return shared.ErrNotFound
	}
	return mem.UpdateRole(tenantdom.Role(role))
}

type auditRecorder struct {
	events []auditapp.AuditEvent
	actxs  []auditapp.AuditContext
}

func (a *auditRecorder) LogEvent(_ context.Context, actx auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.events = append(a.events, e)
	a.actxs = append(a.actxs, actx)
	return nil
}

type groupFixture struct {
	t       *testing.T
	tenant  shared.ID
	repo    *fakeGroupRepo
	members *memberStore
	roles   *roleRecorder
	audit   *auditRecorder
	svc     *GroupService
}

func newGroupFixture(t *testing.T) *groupFixture {
	t.Helper()
	f := &groupFixture{t: t, tenant: shared.NewID(), repo: newFakeGroupRepo(), members: newMemberStore(), audit: &auditRecorder{}}
	f.roles = &roleRecorder{members: f.members}
	f.svc = NewGroupService(f.repo, f.members, f.roles, logger.NewNop())
	f.svc.SetAuditService(f.audit)
	return f
}

func (f *groupFixture) member(role tenantdom.Role) shared.ID {
	f.t.Helper()
	uid := shared.NewID()
	m, err := tenantdom.NewMembership(uid, f.tenant, role, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	f.members.byUser[uid] = m
	return uid
}

func (f *groupFixture) roleOf(uid shared.ID) tenantdom.Role {
	return f.members.byUser[uid].Role()
}

func (f *groupFixture) group(name string, users ...shared.ID) *scimgroup.ScimGroup {
	f.t.Helper()
	g, err := f.svc.Create(context.Background(), f.tenant, GroupInput{DisplayName: name, MemberIDs: users})
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func (f *groupFixture) setMappings(actor shared.ID, m map[string]string) error {
	return f.svc.SetRoleMappings(context.Background(), f.tenant, m, auditapp.AuditContext{ActorID: actor.String()})
}

// An admin who is not the owner cannot add, change or remove a mapping to
// admin: nothing is written, nobody is re-roled. Before the fix an admin
// demoted a peer administrator by mapping their group to viewer.
func TestSetRoleMappings_AdminMappingsAreOwnerOnly(t *testing.T) {
	f := newGroupFixture(t)
	owner := f.member(tenantdom.RoleOwner)
	admin := f.member(tenantdom.RoleAdmin)
	peer := f.member(tenantdom.RoleAdmin)
	f.group("IT-Admins", peer)

	if err := f.setMappings(owner, map[string]string{"IT-Admins": "admin"}); err != nil {
		t.Fatalf("owner maps a group to admin: %v", err)
	}
	if got := f.repo.mappings["it-admins"]; got.Role != "admin" || !got.ConfiguredByOwner || got.ConfiguredBy == nil || *got.ConfiguredBy != owner {
		t.Fatalf("stored mapping = %+v, want admin configured by the owner", got)
	}
	f.roles.calls = nil
	f.audit.events = nil

	for name, m := range map[string]map[string]string{
		"demote the admin group to viewer": {"IT-Admins": "viewer"},
		"remove the admin mapping":         {},
		"map another group to admin":       {"IT-Admins": "admin", "Contractors": "admin"},
	} {
		err := f.setMappings(admin, m)
		if !errors.Is(err, ErrOwnerRequiredForAdminMapping) || !errors.Is(err, shared.ErrForbidden) {
			t.Errorf("admin: %s: err = %v, want owner required", name, err)
		}
	}
	if got := f.repo.mappings; len(got) != 1 || got["it-admins"].Role != "admin" {
		t.Errorf("mappings changed by a refused save: %+v", got)
	}
	if len(f.roles.calls) != 0 || f.roleOf(peer) != tenantdom.RoleAdmin {
		t.Errorf("a refused save re-roled someone: calls %+v, peer %s", f.roles.calls, f.roleOf(peer))
	}
	if len(f.audit.events) != 0 {
		t.Errorf("a refused save was audited as a change: %d events", len(f.audit.events))
	}

	// The admin may still manage member/viewer mappings; the unchanged admin
	// mapping keeps its owner provenance.
	if err := f.setMappings(admin, map[string]string{"IT-Admins": "admin", "Readers": "viewer"}); err != nil {
		t.Fatalf("admin edits a viewer mapping: %v", err)
	}
	if got := f.repo.mappings["it-admins"]; !got.ConfiguredByOwner || *got.ConfiguredBy != owner {
		t.Errorf("unchanged admin mapping lost its provenance: %+v", got)
	}
	if got := f.repo.mappings["readers"]; got.ConfiguredByOwner || got.ConfiguredBy == nil || *got.ConfiguredBy != admin {
		t.Errorf("viewer mapping provenance = %+v, want set by the admin", got)
	}
}

// Mapping to owner is rejected for everyone, and SCIM never re-roles the owner.
func TestSetRoleMappings_NeverOwner(t *testing.T) {
	f := newGroupFixture(t)
	owner := f.member(tenantdom.RoleOwner)
	if err := f.setMappings(owner, map[string]string{"x": "owner"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("mapping to owner: err = %v, want validation error", err)
	}
	if err := f.setMappings(owner, map[string]string{"Everyone": "viewer"}); err != nil {
		t.Fatal(err)
	}
	f.group("Everyone", owner)
	if f.roleOf(owner) != tenantdom.RoleOwner {
		t.Errorf("owner re-roled by SCIM: %s", f.roleOf(owner))
	}
	for _, c := range f.roles.calls {
		if c.role == string(tenantdom.RoleOwner) {
			t.Errorf("SCIM asked for the owner role: %+v", c)
		}
	}
}

// The mapping change is audited (actor, before/after, High), and the role
// changes it causes are made as the person who saved it.
func TestSetRoleMappings_AuditedAndRunAsActor(t *testing.T) {
	f := newGroupFixture(t)
	owner := f.member(tenantdom.RoleOwner)
	u := f.member(tenantdom.RoleMember)
	f.group("Sec-Leads", u)

	if err := f.setMappings(owner, map[string]string{"Sec-Leads": "admin"}); err != nil {
		t.Fatal(err)
	}
	if f.roleOf(u) != tenantdom.RoleAdmin {
		t.Fatalf("member in the owner-mapped group: role %s, want admin", f.roleOf(u))
	}
	if len(f.roles.calls) != 1 || f.roles.calls[0].actor == nil || *f.roles.calls[0].actor != owner {
		t.Errorf("role change calls = %+v, want one made as the owner", f.roles.calls)
	}
	if len(f.audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(f.audit.events))
	}
	e, actx := f.audit.events[0], f.audit.actxs[0]
	if e.Action != auditdom.ActionSCIMGroupMappingsUpdated || e.Severity != auditdom.SeverityHigh ||
		actx.ActorID != owner.String() || actx.TenantID != f.tenant.String() {
		t.Errorf("audit = %s/%s actor %s tenant %s", e.Action, e.Severity, actx.ActorID, actx.TenantID)
	}
	if e.Changes == nil || !strings.Contains(stringifyChanges(e.Changes), "sec-leads") {
		t.Errorf("audit changes do not name the group: %+v", e.Changes)
	}
	if e.Metadata["admin_mapping_changed"] != true {
		t.Errorf("admin_mapping_changed = %v, want true", e.Metadata["admin_mapping_changed"])
	}
}

func stringifyChanges(c *auditdom.Changes) string {
	var b strings.Builder
	for k := range c.Before {
		b.WriteString(k)
	}
	for k := range c.After {
		b.WriteString(k)
	}
	return b.String()
}

// Identity-provider pushes (no actor): admin is granted only through an
// owner-configured mapping, and taken away only once the owner configured an
// admin mapping. A hand-appointed administrator is never demoted by a push.
func TestReconcile_AdminRoleNeedsOwnerConfiguredMapping(t *testing.T) {
	t.Run("group named admin grants nothing by name", func(t *testing.T) {
		f := newGroupFixture(t)
		u := f.member(tenantdom.RoleMember)
		f.group("admin", u)
		if f.roleOf(u) != tenantdom.RoleMember || len(f.roles.calls) != 0 {
			t.Errorf("role %s calls %+v, want unchanged member", f.roleOf(u), f.roles.calls)
		}
	})

	t.Run("admin mapping not set by the owner grants nothing", func(t *testing.T) {
		f := newGroupFixture(t)
		f.repo.mappings["legacy-admins"] = scimgroup.RoleMapping{Role: "admin"} // pre-000911 row
		u := f.member(tenantdom.RoleMember)
		f.group("Legacy-Admins", u)
		if f.roleOf(u) != tenantdom.RoleMember {
			t.Errorf("role %s, want member", f.roleOf(u))
		}
	})

	t.Run("hand-appointed admin is not demoted without an owner admin mapping", func(t *testing.T) {
		f := newGroupFixture(t)
		admin := f.member(tenantdom.RoleAdmin)
		f.group("viewer", admin)
		if f.roleOf(admin) != tenantdom.RoleAdmin || len(f.roles.calls) != 0 {
			t.Errorf("role %s calls %+v, want the admin left alone", f.roleOf(admin), f.roles.calls)
		}
	})

	t.Run("owner-configured mapping grants and removes admin", func(t *testing.T) {
		f := newGroupFixture(t)
		owner := f.member(tenantdom.RoleOwner)
		if err := f.setMappings(owner, map[string]string{"IT-Admins": "admin"}); err != nil {
			t.Fatal(err)
		}
		u := f.member(tenantdom.RoleMember)
		g := f.group("IT-Admins", u)
		if f.roleOf(u) != tenantdom.RoleAdmin {
			t.Fatalf("after joining the owner-mapped group: %s, want admin", f.roleOf(u))
		}
		if _, err := f.svc.PatchMembers(context.Background(), f.tenant, g.ID(), nil, []shared.ID{u}); err != nil {
			t.Fatal(err)
		}
		if f.roleOf(u) != tenantdom.RoleMember {
			t.Errorf("after leaving it: %s, want member", f.roleOf(u))
		}
		for _, c := range f.roles.calls {
			if c.actor != nil {
				t.Errorf("an identity-provider push ran as a user: %+v", c)
			}
		}
	})
}

func TestSetRoleMappings_RequiresActor(t *testing.T) {
	f := newGroupFixture(t)
	err := f.svc.SetRoleMappings(context.Background(), f.tenant, map[string]string{"x": "viewer"}, auditapp.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("no actor: err = %v, want validation error", err)
	}
}
