package orgtrust

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type memTrusts struct{ t *orgtrust.Trust }

func (m memTrusts) Create(context.Context, *orgtrust.Trust) error { return nil }
func (m memTrusts) Update(context.Context, *orgtrust.Trust) error { return nil }
func (m memTrusts) GetForTenant(context.Context, shared.ID, shared.ID) (*orgtrust.Trust, error) {
	return m.t, nil
}
func (m memTrusts) GetPair(_ context.Context, host, home shared.ID) (*orgtrust.Trust, error) {
	if m.t == nil || m.t.HostTenantID != host || m.t.HomeTenantID != home {
		return nil, orgtrust.ErrNotFound
	}
	return m.t, nil
}
func (m memTrusts) ListForTenant(context.Context, shared.ID) ([]*orgtrust.Trust, error) {
	return nil, nil
}
func (m memTrusts) Delete(context.Context, shared.ID, shared.ID) error { return nil }

type oneMember struct{ m *tenantdom.Membership }

func (o oneMember) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	return o.m, nil
}

func externalMember(t *testing.T, host, home shared.ID, until *time.Time) *tenantdom.Membership {
	t.Helper()
	m, _ := tenantdom.NewMembership(shared.NewID(), host, tenantdom.RoleViewer, nil)
	h := home
	if err := m.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: &h, Domain: "home.example"},
		tenantdom.ExternalAccess{ExpiresAt: until}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPolicy_APIKeyAllowance(t *testing.T) {
	ctx := context.Background()
	host, home := shared.NewID(), shared.NewID()
	until := time.Now().Add(48 * time.Hour)
	ext := externalMember(t, host, home, &until)

	settings := orgtrust.DefaultSettings()
	tr, _ := orgtrust.New(host, home, settings, shared.NewID())

	// Requested (not accepted) trust: no trust in force, so keys follow the
	// member, bounded by the end of access.
	if ok, at, _ := NewPolicy(memTrusts{tr}, oneMember{ext}).APIKeyAllowance(ctx, host, ext.UserID()); !ok || at == nil || !at.Equal(until) {
		t.Fatal("without a trust in force an outside member creates keys up to the end of access")
	}
	_ = tr.Accept(shared.NewID(), false, time.Now())
	if ok, _, _ := NewPolicy(memTrusts{tr}, oneMember{ext}).APIKeyAllowance(ctx, host, ext.UserID()); ok {
		t.Fatal("an active trust that does not allow keys forbids them")
	}
	tr.Settings.AllowAPIKeys = true
	ok, at, err := NewPolicy(memTrusts{tr}, oneMember{ext}).APIKeyAllowance(ctx, host, ext.UserID())
	if err != nil || !ok || at == nil || !at.Equal(until) {
		t.Fatalf("allowed with the access end as the key limit: ok=%v until=%v err=%v", ok, at, err)
	}
	// An internal member is unaffected.
	in, _ := tenantdom.NewMembership(shared.NewID(), host, tenantdom.RoleMember, nil)
	if ok, at, _ := NewPolicy(memTrusts{nil}, oneMember{in}).APIKeyAllowance(ctx, host, in.UserID()); !ok || at != nil {
		t.Fatal("internal members create keys as before")
	}
	// An unmanaged external (no home) creates keys up to the end of access.
	m, _ := tenantdom.NewMembership(shared.NewID(), host, tenantdom.RoleViewer, nil)
	u := time.Now().Add(time.Hour)
	_ = m.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Domain: "gmail.com", Personal: true},
		tenantdom.ExternalAccess{ExpiresAt: &u}, time.Now())
	if ok, at, _ := NewPolicy(memTrusts{tr}, oneMember{m}).APIKeyAllowance(ctx, host, m.UserID()); !ok || at == nil || !at.Equal(u) {
		t.Fatal("an unmanaged external member creates keys up to the end of access")
	}
}

func TestPolicy_MaxRoleAndDefaultExpiry(t *testing.T) {
	ctx := context.Background()
	host, home := shared.NewID(), shared.NewID()
	days := 30
	s := orgtrust.DefaultSettings()
	s.MaxRole = orgtrust.MaxRoleViewer
	s.DefaultExpiryDays = &days
	tr, _ := orgtrust.New(host, home, s, shared.NewID())
	p := NewPolicy(memTrusts{tr}, oneMember{})

	// Not accepted: no ceiling (the host decides per person), no proposed expiry.
	if r, _ := p.MaxRoleFor(ctx, host, home); r != "" {
		t.Fatalf("ceiling without an active trust = %q, want none", r)
	}
	_ = tr.Accept(shared.NewID(), false, time.Now())
	if r, _ := p.MaxRoleFor(ctx, host, home); r != orgtrust.MaxRoleViewer {
		t.Fatalf("ceiling = %s, want viewer", r)
	}
	now := time.Now().UTC()
	at, _ := p.DefaultExpiryFor(ctx, host, home, now)
	if at == nil || !at.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("default expiry = %v", at)
	}
}

func TestSettingsValidate(t *testing.T) {
	bad := []orgtrust.Settings{
		{MaxRole: "admin"},
		{MaxRole: "owner"},
		{MaxRole: orgtrust.MaxRoleMember, DefaultExpiryDays: intPtr(0)},
		{MaxRole: orgtrust.MaxRoleMember, DefaultExpiryDays: intPtr(366)},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%+v must be refused", s)
		}
	}
	if _, err := orgtrust.New(shared.NewID(), shared.NewID(), orgtrust.DefaultSettings(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	same := shared.NewID()
	if _, err := orgtrust.New(same, same, orgtrust.DefaultSettings(), shared.NewID()); err == nil {
		t.Fatal("an organization cannot trust itself")
	}
}

func intPtr(v int) *int { return &v }
