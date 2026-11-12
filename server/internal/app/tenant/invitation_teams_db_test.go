package tenant_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// itGate passes or refuses re-authentication; ok can change during a test.
type itGate struct{ ok *bool }

var errITStepUp = errors.New("step-up required")

func (g itGate) RequireRecentAuth(context.Context, string) error {
	if *g.ok {
		return nil
	}
	return errITStepUp
}

// itNoDomains: no organization holds any domain (personal addresses are
// external).
type itNoDomains struct{}

func (itNoDomains) OwnerOfDomain(context.Context, string) (shared.ID, bool, error) {
	return shared.ID{}, false, nil
}

type itEnv struct {
	t      *testing.T
	db     *sql.DB
	svc    *tenantapp.TenantService
	stepUp *bool
	users  []string
	// ownsDomain: the organization holds a verified domain, so an unclaimed
	// work address becomes external.
	ownsDomain *bool
}

func newITEnv(t *testing.T) *itEnv {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	pg := &postgres.DB{DB: raw}
	log := logger.NewNop()
	ok := true
	gate := itGate{ok: &ok}
	audit := auditapp.NewAuditService(postgres.NewAuditRepository(pg), log)
	roles := accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), log)
	roles.SetStepUpGate(gate)
	groups := accesscontrol.NewGroupService(postgres.NewGroupRepository(pg), log,
		accesscontrol.WithAccessControlRepository(postgres.NewAccessControlRepository(pg)))
	groups.SetRoleBindings(postgres.NewGroupRoleBindingRepository(pg), roles)
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(pg), log, tenantapp.WithTenantAuditService(audit))
	svc.SetRoleService(roles)
	svc.SetStepUpGate(gate)
	svc.SetInvitationTeams(groups)
	owns := false
	svc.SetAddressClassifier(tenantapp.NewAddressClassifier(itNoDomains{},
		func(context.Context, shared.ID) (bool, error) { return owns, nil }))
	return &itEnv{t: t, db: raw, svc: svc, stepUp: &ok, ownsDomain: &owns}
}

func (e *itEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func (e *itEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *itEnv) org() string {
	e.t.Helper()
	id := uuid.NewString()
	e.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Invite teams IT', $2)`, id, "invteams-"+strings.ReplaceAll(id[:13], "-", ""))
	e.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM tenant_invitations WHERE tenant_id = $1`,
			`DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE tenant_id = $1)`,
			`DELETE FROM group_role_bindings WHERE tenant_id = $1`,
			`DELETE FROM groups WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE tenant_id = $1)`,
			`DELETE FROM roles WHERE tenant_id = $1`,
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
		} {
			_, _ = e.db.ExecContext(ctx, q, id)
		}
		for _, u := range e.users {
			_, _ = e.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1
				AND NOT EXISTS (SELECT 1 FROM tenant_members m WHERE m.user_id = $1)`, u)
		}
		_, _ = e.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id)
	})
	return id
}

// user creates an account; member adds it to org with a membership role.
func (e *itEnv) user(email string) string {
	id := uuid.NewString()
	e.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'IT person')`, id, email)
	e.users = append(e.users, id)
	return id
}

func (e *itEnv) member(org, role string) string {
	id := e.user("it-" + uuid.NewString()[:8] + "@it.test")
	e.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, org, role)
	return id
}

func (e *itEnv) team(org, kind string) string {
	id := uuid.NewString()
	e.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, $3, $4, $5)`,
		id, org, "Team "+id[:4], "team-"+id[:8], kind)
	return id
}

// leadRole binds a custom role with team:groups:members (privileged, above
// member) to team.
func (e *itEnv) bindLeadRole(org, team string) {
	role := uuid.NewString()
	e.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system) VALUES ($1, $2, $3, 'Team lead', false)`, role, org, "lead-"+role[:8])
	e.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'team:groups:members')`, role)
	e.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, org, team, role)
}

const itViewerRole = "00000000-0000-0000-0000-000000000004"

func (e *itEnv) invite(org, inviter, email string, teams []string, accessEnd *time.Time) (string, error) {
	inv, err := e.svc.CreateInvitation(context.Background(), org, tenantapp.CreateInvitationInput{
		Email: email, RoleIDs: []string{itViewerRole}, GroupIDs: teams, AccessExpiresAt: accessEnd,
	}, shared.MustIDFromString(inviter), auditapp.AuditContext{TenantID: org, ActorID: inviter})
	if err != nil {
		return "", err
	}
	return inv.Token(), nil
}

func (e *itEnv) accept(org, token, email string) (string, error) {
	uid := e.user(email)
	_, err := e.svc.AcceptInvitation(context.Background(), token, shared.MustIDFromString(uid), email,
		auditapp.AuditContext{TenantID: org, ActorID: uid})
	return uid, err
}

func TestInvitationTeams_AppliedAtAcceptance(t *testing.T) {
	e := newITEnv(t)
	org := e.org()
	admin := e.member(org, "admin")
	teamA, teamB := e.team(org, "team"), e.team(org, "project")
	email := "new-" + uuid.NewString()[:8] + "@it.test"
	token, err := e.invite(org, admin, email, []string{teamA, strings.ToUpper(teamB), teamA}, nil)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if n := e.count(`SELECT cardinality(group_ids) FROM tenant_invitations WHERE tenant_id = $1`, org); n != 2 {
		t.Fatalf("stored %d teams, want 2 (deduplicated)", n)
	}
	uid, err := e.accept(org, token, email)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM group_members WHERE user_id = $1 AND group_id IN ($2, $3)`, uid, teamA, teamB); n != 2 {
		t.Fatalf("joined %d teams, want 2", n)
	}
	// The acceptance audit lists the teams granted.
	if n := e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'invitation.accepted'
		AND metadata::text LIKE '%' || $2 || '%' AND metadata::text LIKE '%' || $3 || '%'`, org, teamA, teamB); n != 1 {
		t.Fatalf("acceptance audit rows listing both teams = %d, want 1", n)
	}
}

func TestInvitationTeams_Refusals(t *testing.T) {
	e := newITEnv(t)
	org, other := e.org(), e.org()
	owner, admin := e.member(org, "owner"), e.member(org, "admin")
	foreign := e.team(other, "team")
	inactive := e.team(org, "team")
	e.exec(`UPDATE groups SET is_active = false WHERE id = $1`, inactive)
	external := e.team(org, "external")
	lead := e.team(org, "team")
	e.bindLeadRole(org, lead)

	for _, tc := range []struct {
		name string
		by   string
		team string
		want error
	}{
		{"another organization's team", admin, foreign, shared.ErrNotFound},
		{"an inactive team", admin, inactive, accesscontrol.ErrInvitationTeamInactive},
		{"an external team without an end of access", admin, external, accesscontrol.ErrExpiryRequired},
		{"a team with a privileged role, by an administrator", admin, lead, accesscontrol.ErrPrivilegedTeamOwnerOnly},
	} {
		_, err := e.invite(org, tc.by, "x-"+uuid.NewString()[:8]+"@it.test", []string{tc.team}, nil)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	// The owner adds to a privileged team only after re-authenticating.
	*e.stepUp = false
	if _, err := e.invite(org, owner, "y-"+uuid.NewString()[:8]+"@it.test", []string{lead}, nil); !errors.Is(err, errITStepUp) {
		t.Fatalf("owner without step-up: %v", err)
	}
	*e.stepUp = true
	if _, err := e.invite(org, owner, "z-"+uuid.NewString()[:8]+"@it.test", []string{lead}, nil); err != nil {
		t.Fatalf("owner with step-up: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1`, org); n != 1 {
		t.Fatalf("stored invitations = %d, want 1", n)
	}
}

// TestInvitationTeams_RecheckedAtAcceptance: a team the inviter can no
// longer add the person to voids the invitation; nothing is granted.
func TestInvitationTeams_RecheckedAtAcceptance(t *testing.T) {
	e := newITEnv(t)
	org := e.org()
	admin := e.member(org, "admin")
	team := e.team(org, "team")
	email := "late-" + uuid.NewString()[:8] + "@it.test"
	token, err := e.invite(org, admin, email, []string{team}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The team gains a privileged role: only the owner may add to it now.
	e.bindLeadRole(org, team)
	uid, err := e.accept(org, token, email)
	if !errors.Is(err, tenantapp.ErrInvitationNoLongerValid) {
		t.Fatalf("accept: %v, want no longer valid", err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, org, uid); n != 0 {
		t.Fatal("membership created")
	}
	if n := e.count(`SELECT count(*) FROM group_members WHERE user_id = $1`, uid); n != 0 {
		t.Fatal("team membership created")
	}

	// A team deleted after the invitation: also void.
	team2 := e.team(org, "team")
	email2 := "gone-" + uuid.NewString()[:8] + "@it.test"
	token2, err := e.invite(org, admin, email2, []string{team2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(`DELETE FROM groups WHERE id = $1`, team2)
	if _, err := e.accept(org, token2, email2); !errors.Is(err, tenantapp.ErrInvitationNoLongerValid) {
		t.Fatalf("accept with a deleted team: %v", err)
	}
}

// TestInvitationTeams_OutsiderPrivilegeCountsTeams: a team carrying a role
// above member makes an outside invitee privileged (two-factor at sign-in,
// inviter step-up), like the role itself.
func TestInvitationTeams_OutsiderPrivilegeCountsTeams(t *testing.T) {
	e := newITEnv(t)
	org := e.org()
	owner := e.member(org, "owner")
	lead := e.team(org, "team")
	plain := e.team(org, "team")
	e.bindLeadRole(org, lead)
	end := time.Now().Add(30 * 24 * time.Hour)

	if _, err := e.invite(org, owner, "pat"+uuid.NewString()[:6]+"@gmail.com", []string{plain}, &end); err != nil {
		t.Fatal(err)
	}
	if _, err := e.invite(org, owner, "sam"+uuid.NewString()[:6]+"@gmail.com", []string{lead}, &end); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND privileged`, org); n != 1 {
		t.Fatalf("privileged invitations = %d, want 1 (the one with the lead team)", n)
	}
	// Preview says so before sending.
	p, err := e.svc.PreviewInvitationWithTeams(context.Background(), org, "kim@gmail.com",
		[]string{itViewerRole}, []string{lead}, auditapp.AuditContext{TenantID: org, ActorID: owner})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed || !p.Privileged || !p.MFARequired || !p.StepUpRequired {
		t.Fatalf("preview = %+v", p)
	}
	foreign := e.team(e.org(), "team")
	p, err = e.svc.PreviewInvitationWithTeams(context.Background(), org, "kim@gmail.com",
		[]string{itViewerRole}, []string{foreign}, auditapp.AuditContext{TenantID: org, ActorID: owner})
	if err != nil || p.Allowed || p.Reason != tenantapp.PreviewTeamNotGrantable {
		t.Fatalf("preview with another organization's team = %+v, %v", p, err)
	}
}

// TestInvitationGrants_ForTheAcceptancePage: the lookup shows the roles with
// their risk, the teams of this organization only, the outsider status and
// why two-factor will be required.
func TestInvitationGrants_ForTheAcceptancePage(t *testing.T) {
	e := newITEnv(t)
	org := e.org()
	owner := e.member(org, "owner")
	lead := e.team(org, "team")
	e.bindLeadRole(org, lead)
	end := time.Now().Add(30 * 24 * time.Hour)
	token, err := e.invite(org, owner, "ana"+uuid.NewString()[:6]+"@gmail.com", []string{lead}, &end)
	if err != nil {
		t.Fatal(err)
	}
	// A team id of another organization planted in the row is never shown.
	foreign := e.team(e.org(), "team")
	e.exec(`UPDATE tenant_invitations SET group_ids = group_ids || $2::uuid WHERE tenant_id = $1`, org, foreign)

	inv, err := e.svc.GetInvitationByToken(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	g := e.svc.InvitationGrants(context.Background(), inv)
	if len(g.Roles) != 1 || g.Roles[0].Slug != "viewer" || g.Roles[0].Summary.Risk == "" {
		t.Fatalf("roles = %+v", g.Roles)
	}
	if len(g.Teams) != 1 || g.Teams[0].ID != lead {
		t.Fatalf("teams = %+v (another organization's team must not show)", g.Teams)
	}
	if g.MemberKind != "external" || !g.MFARequired || g.MFAReason != tenantapp.MFAReasonOutsidePrivileged {
		t.Fatalf("grants = %+v", g)
	}

	// An insider with no organization policy: no two-factor notice.
	plain := e.team(org, "team")
	token2, err := e.invite(org, owner, "in-"+uuid.NewString()[:8]+"@it.test", []string{plain}, nil)
	if err != nil {
		t.Fatal(err)
	}
	inv2, _ := e.svc.GetInvitationByToken(context.Background(), token2)
	g2 := e.svc.InvitationGrants(context.Background(), inv2)
	if g2.MemberKind != "internal" || g2.MFARequired || len(g2.Teams) != 1 {
		t.Fatalf("insider grants = %+v", g2)
	}
}

// TestInvitationTeams_RecheckUsesClassificationAtAcceptance: an invitee who
// was internal when invited but is outside the organization at acceptance
// (the organization verified a domain since) never gets full data access
// through a team; the invitation is void and nothing is granted.
func TestInvitationTeams_RecheckUsesClassificationAtAcceptance(t *testing.T) {
	e := newITEnv(t)
	org := e.org()
	owner := e.member(org, "owner")
	team := e.team(org, "team")
	role := uuid.NewString()
	e.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, has_full_data_access) VALUES ($1, $2, $3, 'All data', false, true)`, role, org, "all-"+role[:8])
	e.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, org, team, role)

	email := "later-outside-" + uuid.NewString()[:8] + "@it.test"
	token, err := e.invite(org, owner, email, []string{team}, nil)
	if err != nil {
		t.Fatalf("invite an insider to a full-data team: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND invitee_kind = 'internal'`, org); n != 1 {
		t.Fatal("the invitee was not classified internal at creation")
	}
	*e.ownsDomain = true // the address is now outside the organization
	uid, err := e.accept(org, token, email)
	if !errors.Is(err, tenantapp.ErrInvitationNoLongerValid) {
		t.Fatalf("accept: %v, want no longer valid", err)
	}
	if n := e.count(`SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, org, uid); n != 0 {
		t.Fatal("membership created")
	}
	if n := e.count(`SELECT count(*) FROM group_members WHERE user_id = $1`, uid); n != 0 {
		t.Fatal("team membership created")
	}
}
