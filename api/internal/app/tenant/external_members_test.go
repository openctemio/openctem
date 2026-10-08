package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeOwners struct {
	owners map[string]shared.ID
	err    error
}

func (f fakeOwners) OwnerOfDomain(_ context.Context, d string) (shared.ID, bool, error) {
	if f.err != nil {
		return shared.ID{}, false, f.err
	}
	id, ok := f.owners[d]
	return id, ok, nil
}

func ownsAny(v bool, err error) func(context.Context, shared.ID) (bool, error) {
	return func(context.Context, shared.ID) (bool, error) { return v, err }
}

func TestAddressClassifier(t *testing.T) {
	host, partner := shared.NewID(), shared.NewID()
	owners := fakeOwners{owners: map[string]shared.ID{"example.com": host, "example.com.au": partner}}
	ctx := context.Background()

	cases := []struct {
		name     string
		email    string
		ownsAny  bool
		kind     tenantdom.MemberKind
		home     *shared.ID
		personal bool
	}{
		{"own domain", "an@example.com", true, tenantdom.MemberKindInternal, nil, false},
		{"sister company", "nam@EXAMPLE.com.au", true, tenantdom.MemberKindExternal, &partner, false},
		{"personal", "j.doe@gmail.com", true, tenantdom.MemberKindExternal, nil, true},
		{"personal even with no verified domain", "j.doe@gmail.com", false, tenantdom.MemberKindExternal, nil, true},
		{"unclaimed work domain", "x@mssp.vn", true, tenantdom.MemberKindExternal, nil, false},
		{"unclaimed, host verified nothing yet", "x@mssp.vn", false, tenantdom.MemberKindInternal, nil, false},
	}
	for _, tc := range cases {
		c := NewAddressClassifier(owners, ownsAny(tc.ownsAny, nil))
		got, err := c.Classify(ctx, host, tc.email)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Kind != tc.kind || got.Personal != tc.personal {
			t.Errorf("%s: kind=%s personal=%v, want %s %v", tc.name, got.Kind, got.Personal, tc.kind, tc.personal)
		}
		if (got.HomeTenantID == nil) != (tc.home == nil) || (tc.home != nil && *got.HomeTenantID != *tc.home) {
			t.Errorf("%s: home=%v, want %v", tc.name, got.HomeTenantID, tc.home)
		}
	}
}

// Fail closed: a lookup error refuses, never guesses internal.
func TestAddressClassifier_LookupErrorsFailClosed(t *testing.T) {
	host := shared.NewID()
	boom := errors.New("db down")
	if _, err := NewAddressClassifier(fakeOwners{err: boom}, ownsAny(true, nil)).Classify(context.Background(), host, "a@x.com"); err == nil {
		t.Fatal("owner lookup error must refuse")
	}
	if _, err := NewAddressClassifier(fakeOwners{}, ownsAny(false, boom)).Classify(context.Background(), host, "a@x.com"); err == nil {
		t.Fatal("own-domains lookup error must refuse")
	}
	if _, err := NewAddressClassifier(fakeOwners{}, ownsAny(true, nil)).Classify(context.Background(), host, "not-an-email"); err == nil {
		t.Fatal("an invalid address must refuse")
	}
}

func TestSettleExternalAccess_DefaultsTheRequiredExpiry(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	got := SettleExternalAccess(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Personal: true}, tenantdom.ExternalAccess{}, now)
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(now.Add(90*24*time.Hour)) {
		t.Fatalf("default expiry = %v, want 90 days", got.ExpiresAt)
	}
	home := shared.NewID()
	got = SettleExternalAccess(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: &home}, tenantdom.ExternalAccess{}, now)
	if got.ExpiresAt != nil {
		t.Fatal("a managed external member needs no expiry")
	}
	until := now.Add(time.Hour)
	got = SettleExternalAccess(tenantdom.Classification{Kind: tenantdom.MemberKindInternal}, tenantdom.ExternalAccess{ExpiresAt: &until}, now)
	if got.ExpiresAt != nil {
		t.Fatal("an internal member gets no expiry from an invitation")
	}
}

// An address that became external after the invitation was sent still joins
// as a viewer, whatever the invitation granted.
func TestApplyInviteeClassification_ExternalBecomesViewer(t *testing.T) {
	tid, inviter := shared.NewID(), shared.NewID()
	inv, err := tenantdom.NewInvitation(tid, "x@gmail.com", tenantdom.RoleMember, inviter, []string{roledom.MemberRoleID.String()})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := tenantdom.NewMembership(shared.NewID(), tid, tenantdom.RoleMember, &inviter)
	now := time.Now().UTC()
	class := tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Personal: true, Domain: "gmail.com"}
	if err := ApplyInviteeClassification(inv, m, class, SettleExternalAccess(class, tenantdom.ExternalAccess{}, now), now); err != nil {
		t.Fatal(err)
	}
	if m.Role() != tenantdom.RoleViewer || !m.IsExternal() || m.ExpiresAt() == nil {
		t.Fatalf("role=%s external=%v expires=%v", m.Role(), m.IsExternal(), m.ExpiresAt())
	}
	if ids := inv.RoleIDs(); len(ids) != 1 || ids[0] != roledom.ViewerRoleID.String() {
		t.Fatalf("granted roles = %v, want viewer only", ids)
	}
}

func TestRequireViewerOnly(t *testing.T) {
	if err := requireViewerOnly([]string{roledom.ViewerRoleID.String()}); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]string{
		{roledom.MemberRoleID.String()},
		{roledom.ViewerRoleID.String(), roledom.MemberRoleID.String()},
		{roledom.AdminRoleID.String()},
		nil,
	} {
		if err := requireViewerOnly(ids); !errors.Is(err, ErrExternalViewerOnly) {
			t.Errorf("%v: want ErrExternalViewerOnly, got %v", ids, err)
		}
	}
}
