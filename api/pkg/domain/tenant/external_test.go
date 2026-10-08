package tenant

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func extMember(t *testing.T, role Role) *Membership {
	t.Helper()
	m, err := NewMembership(shared.NewID(), shared.NewID(), role, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExternalAccess_Validate(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	home := shared.NewID()
	unmanaged := Classification{Kind: MemberKindExternal, Domain: "gmail.com", Personal: true}
	managed := Classification{Kind: MemberKindExternal, HomeTenantID: &home, Domain: "ipas.com.vn"}
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	cases := []struct {
		name    string
		class   Classification
		access  ExternalAccess
		wantErr bool
	}{
		{"unmanaged without expiry", unmanaged, ExternalAccess{}, true},
		{"unmanaged 90 days", unmanaged, ExternalAccess{ExpiresAt: at(90 * 24 * time.Hour)}, false},
		{"unmanaged 365 days", unmanaged, ExternalAccess{ExpiresAt: at(365 * 24 * time.Hour)}, false},
		{"unmanaged 366 days", unmanaged, ExternalAccess{ExpiresAt: at(366 * 24 * time.Hour)}, true},
		{"in the past", unmanaged, ExternalAccess{ExpiresAt: at(-time.Hour)}, true},
		{"managed without expiry", managed, ExternalAccess{}, false},
		{"managed 400 days", managed, ExternalAccess{ExpiresAt: at(400 * 24 * time.Hour)}, true},
		{"reason too long", managed, ExternalAccess{Reason: strings.Repeat("x", 501)}, true},
	}
	for _, tc := range cases {
		err := tc.access.Validate(tc.class, now)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
		if err != nil && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", tc.name, err)
		}
	}
}

func TestMembership_ClassifyExternal(t *testing.T) {
	now := time.Now().UTC()
	home := shared.NewID()
	m := extMember(t, RoleViewer)
	until := now.Add(24 * time.Hour)
	if err := m.Classify(Classification{Kind: MemberKindExternal, HomeTenantID: &home, Domain: "IPAS.com.vn"},
		ExternalAccess{ExpiresAt: &until, Reason: " project "}, now); err != nil {
		t.Fatal(err)
	}
	if !m.IsExternal() || m.HomeTenantID() == nil || *m.HomeTenantID() != home || m.HomeDomain() != "ipas.com.vn" {
		t.Fatalf("external fields not recorded: kind=%s home=%v domain=%q", m.Kind(), m.HomeTenantID(), m.HomeDomain())
	}
	if m.ExpiryReason() != "project" || m.ExpiresAt() == nil {
		t.Fatalf("access not recorded: %v %q", m.ExpiresAt(), m.ExpiryReason())
	}

	// An internal classification drops any home organization.
	in := extMember(t, RoleMember)
	if err := in.Classify(Classification{Kind: MemberKindInternal, HomeTenantID: &home, Domain: "acme.com"}, ExternalAccess{}, now); err != nil {
		t.Fatal(err)
	}
	if in.IsExternal() || in.HomeTenantID() != nil {
		t.Fatal("an internal member has no home organization")
	}
}

func TestMembership_OwnerIsNeverExternal(t *testing.T) {
	m := extMember(t, RoleOwner)
	until := time.Now().Add(time.Hour)
	err := m.Classify(Classification{Kind: MemberKindExternal, Domain: "gmail.com"}, ExternalAccess{ExpiresAt: &until}, time.Now())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an owner must not become external, got %v", err)
	}
	if m.IsExternal() {
		t.Fatal("refused classification must not change the member")
	}
}

func TestMembership_SuspendExpired(t *testing.T) {
	now := time.Now().UTC()
	m := extMember(t, RoleViewer)
	until := now.Add(time.Hour)
	if err := m.Classify(Classification{Kind: MemberKindExternal, Domain: "gmail.com"}, ExternalAccess{ExpiresAt: &until}, now); err != nil {
		t.Fatal(err)
	}
	if err := m.SuspendExpired(now); err == nil {
		t.Fatal("not expired yet: must refuse")
	}
	later := now.Add(2 * time.Hour)
	if err := m.SuspendExpired(later); err != nil {
		t.Fatal(err)
	}
	if !m.IsSuspended() || m.SuspendedReason() != SuspendedReasonExpired || m.SuspendedBy() != nil {
		t.Fatalf("status=%s reason=%q by=%v", m.Status(), m.SuspendedReason(), m.SuspendedBy())
	}
	if err := m.Reactivate(); err != nil || m.SuspendedReason() != "" {
		t.Fatalf("reactivate clears the reason: %v %q", err, m.SuspendedReason())
	}
}
