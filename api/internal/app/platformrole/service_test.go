package platformrole

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type memStore struct {
	held map[string][]platformauthz.RoleKey
}

func (m *memStore) ListAssignments(context.Context) ([]Assignment, error) { return nil, nil }
func (m *memStore) Assign(_ context.Context, id shared.ID, r platformauthz.RoleKey, _ shared.ID) error {
	m.held[id.String()] = append(m.held[id.String()], r)
	return nil
}
func (m *memStore) Revoke(_ context.Context, id shared.ID, r platformauthz.RoleKey) (bool, error) {
	out, found := []platformauthz.RoleKey{}, false
	for _, k := range m.held[id.String()] {
		if k == r {
			found = true
			continue
		}
		out = append(out, k)
	}
	m.held[id.String()] = out
	return found, nil
}

type memAdmins map[string]*admin.AdminUser

func (m memAdmins) GetByID(_ context.Context, id shared.ID) (*admin.AdminUser, error) {
	if a, ok := m[id.String()]; ok {
		return a, nil
	}
	return nil, admin.ErrAdminNotFound
}

type memAudit struct {
	admin.AuditLogRepository
	rows []*admin.AuditLog
	fail bool
}

func (a *memAudit) Create(_ context.Context, l *admin.AuditLog) error {
	if a.fail {
		return errors.New("down")
	}
	a.rows = append(a.rows, l)
	return nil
}

type memRoster struct{ n int }

func (r *memRoster) NotifyRosterChange(context.Context, *admin.AdminUser, string, string, string, string) {
	r.n++
}

func mk(t *testing.T, role admin.AdminRole, held ...platformauthz.RoleKey) *admin.AdminUser {
	t.Helper()
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), shared.NewID().String()+"@op.example", "A", role, true, nil, nil, "", 0, nil, nil, "", now, nil, now)
	if len(held) > 0 {
		a.SetPlatformAccess(held, platformauthz.Held(held))
	}
	return a
}

func TestAssignRules(t *testing.T) {
	owner := mk(t, admin.AdminRoleSuperAdmin, platformauthz.RoleOwner)
	staff := mk(t, admin.AdminRoleReadonly)
	support := mk(t, admin.AdminRoleReadonly, platformauthz.RoleViewer, platformauthz.RoleSupport)
	store, audit, roster := &memStore{held: map[string][]platformauthz.RoleKey{}}, &memAudit{}, &memRoster{}
	svc := NewService(store, memAdmins{staff.ID().String(): staff, owner.ID().String(): owner}, audit, roster, logger.NewNop())
	ctx := context.Background()
	reason := "New support engineer, ticket 42"

	for name, c := range map[string]struct {
		actor  *admin.AdminUser
		target shared.ID
		role   platformauthz.RoleKey
		reason string
		want   error
	}{
		"unknown role":     {owner, staff.ID(), "root", reason, ErrUnknownRole},
		"base role":        {owner, staff.ID(), platformauthz.RoleOwner, reason, ErrBaseRole},
		"viewer base role": {owner, staff.ID(), platformauthz.RoleViewer, reason, ErrBaseRole},
		"self":             {owner, owner.ID(), platformauthz.RoleSupport, reason, ErrSelf},
		"above own":        {support, staff.ID(), platformauthz.RoleOperator, reason, ErrAboveOwn},
		"no reason":        {owner, staff.ID(), platformauthz.RoleSupport, "short", ErrReason},
		"unknown target":   {owner, shared.NewID(), platformauthz.RoleSupport, reason, admin.ErrAdminNotFound},
	} {
		if err := svc.Assign(ctx, c.actor, c.target, c.role, c.reason, Client{}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if len(store.held) != 0 || len(audit.rows) != 0 || roster.n != 0 {
		t.Fatal("a refused change stores, audits or announces nothing")
	}

	audit.fail = true
	if err := svc.Assign(ctx, owner, staff.ID(), platformauthz.RoleSupport, reason, Client{}); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("audit down: %v", err)
	}
	if len(store.held) != 0 {
		t.Fatal("no audit row, no change")
	}
	audit.fail = false

	if err := svc.Assign(ctx, owner, staff.ID(), platformauthz.RoleSupport, reason, Client{IP: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if got := store.held[staff.ID().String()]; len(got) != 1 || got[0] != platformauthz.RoleSupport || len(audit.rows) != 1 || roster.n != 1 {
		t.Fatalf("assign: held %v, audit %d, roster %d", got, len(audit.rows), roster.n)
	}
	if audit.rows[0].Action != ActionAssigned {
		t.Fatalf("audit action %s", audit.rows[0].Action)
	}
	if err := svc.Revoke(ctx, owner, staff.ID(), platformauthz.RoleSupport, reason, Client{}); err != nil {
		t.Fatal(err)
	}
	if got := store.held[staff.ID().String()]; len(got) != 0 || roster.n != 2 {
		t.Fatalf("revoke: held %v, roster %d", got, roster.n)
	}
}

func TestOwners(t *testing.T) {
	as := []Assignment{
		{Active: true, Roles: []platformauthz.RoleKey{platformauthz.RoleOwner}},
		{Active: true, BreakGlass: true, Roles: []platformauthz.RoleKey{platformauthz.RoleOwner}},
		{Active: false, Roles: []platformauthz.RoleKey{platformauthz.RoleOwner}},
		{Active: true, Roles: []platformauthz.RoleKey{platformauthz.RoleAdmin, platformauthz.RoleSupport}},
	}
	if n := Owners(as); n != 1 {
		t.Fatalf("named owners %d, want 1 (break-glass and inactive do not count)", n)
	}
}
