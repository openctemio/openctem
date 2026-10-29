package platformauthz

import (
	"strings"
	"testing"
)

func TestCatalogKeysArePlatformAndUnique(t *testing.T) {
	seen := map[Permission]bool{}
	for _, d := range Catalog() {
		if !IsPlatformKey(string(d.Key)) {
			t.Errorf("%s: every platform permission starts with %q", d.Key, Prefix)
		}
		if seen[d.Key] {
			t.Errorf("%s listed twice", d.Key)
		}
		seen[d.Key] = true
		if strings.TrimSpace(d.Description) == "" {
			t.Errorf("%s has no description (the generated reference needs one)", d.Key)
		}
	}
}

func TestBuiltinRoles(t *testing.T) {
	all := len(Catalog())
	bases := 0
	for _, r := range BuiltinRoles() {
		if r.Base {
			bases++
		}
		set := RolePermissions(r.Key)
		for p := range set {
			if !Known(p) {
				t.Errorf("%s holds unknown %s", r.Key, p)
			}
		}
		// Every role reads the console.
		for _, d := range Catalog() {
			if d.Baseline && !set.Has(d.Key) {
				t.Errorf("%s lacks the baseline read %s", r.Key, d.Key)
			}
		}
		if r.Key != RoleOwner && len(set) == all {
			t.Errorf("%s holds the whole catalog: only the owner may", r.Key)
		}
	}
	if bases != 3 {
		t.Fatalf("want three base roles (owner, admin, viewer), got %d", bases)
	}
	if len(RolePermissions(RoleOwner)) != all {
		t.Fatal("the owner holds every permission")
	}
	if len(RolePermissions("nope")) != 0 {
		t.Fatal("an unknown role holds nothing")
	}
	// Only the owner manages administrators, roles, identity and approvals.
	for _, p := range []Permission{AdminsManage, RolesAssign, IdentityManage, ApprovalsDecide, TenantsPurge, TenantsAuditChainWrite, TenantsOwnerRecovery} {
		for _, r := range BuiltinRoles() {
			if r.Key != RoleOwner && RolePermissions(r.Key).Has(p) {
				t.Errorf("%s must be owner-only, %s holds it", p, r.Key)
			}
		}
	}
	// The viewer is exactly the baseline: the read-only tier it replaces.
	for p := range RolePermissions(RoleViewer) {
		if !Baseline(p) {
			t.Errorf("viewer holds non-baseline %s", p)
		}
	}
}

func TestTiers(t *testing.T) {
	for tier, want := range map[Tier]RoleKey{TierSuper: RoleOwner, TierOps: RoleAdmin, TierReadonly: RoleViewer, "garbage": RoleViewer} {
		if got := BaseRoleFor(tier); got != want {
			t.Errorf("BaseRoleFor(%s) = %s, want %s", tier, got, want)
		}
	}
	if TierOf(RoleOwner) != TierSuper || TierOf(RoleAdmin) != TierOps || TierOf(RoleSupport) != TierReadonly || TierOf("x") != TierReadonly {
		t.Fatal("unexpected tiers")
	}
}

func TestElevationTarget(t *testing.T) {
	cases := map[string]RoleKey{"super_admin": RoleOwner, "ops_admin": RoleAdmin, "support": RoleSupport, " operator ": RoleOperator}
	for in, want := range cases {
		if got, ok := ElevationTarget(in); !ok || got != want {
			t.Errorf("ElevationTarget(%q) = %s %v, want %s", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "readonly", "platform_viewer", "root", "platform.admins.manage"} {
		if _, ok := ElevationTarget(bad); ok {
			t.Errorf("ElevationTarget(%q) accepted", bad)
		}
	}
}

func TestCanElevateTo(t *testing.T) {
	owner := []RoleKey{RoleOwner}
	if !CanElevateTo(owner, RoleAdmin) || !CanElevateTo(owner, RoleSupport) || !CanElevateTo(owner, RoleOwner) {
		t.Fatal("an owner may act as any role")
	}
	support := []RoleKey{RoleViewer, RoleSupport}
	if !CanElevateTo(support, RoleSupport) {
		t.Fatal("support may act as support")
	}
	for _, target := range []RoleKey{RoleAdmin, RoleOwner, RoleOperator, RoleViewer, "nope"} {
		if CanElevateTo(support, target) {
			t.Errorf("support elevated to %s", target)
		}
	}
	admin := []RoleKey{RoleAdmin}
	if CanElevateTo(admin, RoleOwner) || CanElevateTo(admin, RoleOperator) {
		t.Fatal("an admin never acts above what it holds (operator manages sensors, admin does not)")
	}
	if !CanElevateTo(admin, RoleSupport) {
		t.Fatal("support's permissions are within the admin's")
	}
}

func TestActing(t *testing.T) {
	owner := []RoleKey{RoleOwner}
	if got := Acting(owner, false, ""); len(got) != len(Catalog()) {
		t.Fatal("without required elevation the owner acts with everything")
	}
	unelevated := Acting(owner, true, "")
	for p := range unelevated {
		if !Baseline(p) {
			t.Errorf("unelevated owner acts with %s", p)
		}
	}
	if unelevated.Has(AdminsRead) || unelevated.Has(UsersRead) {
		t.Fatal("people's details need an elevation")
	}
	asAdmin := Acting(owner, true, RoleAdmin)
	if !asAdmin.Has(UsersSupport) || asAdmin.Has(AdminsManage) {
		t.Fatal("an owner acting as admin gets the admin's permissions only")
	}
	// A role taken away during an elevation stops counting.
	if Acting([]RoleKey{RoleViewer}, true, RoleSupport).Has(UsersSupport) {
		t.Fatal("an elevation to a role no longer held grants nothing")
	}
	if len(Acting(nil, false, "")) != 0 || len(Acting(nil, true, RoleOwner)) != 0 {
		t.Fatal("no roles, no permissions")
	}
}

func TestSet(t *testing.T) {
	s := NewSet(ConsoleRead, "platform.nope", AuditRead)
	if len(s) != 2 || !s.Has(ConsoleRead) || s.Has("platform.nope") {
		t.Fatalf("unknown keys are dropped: %v", s)
	}
	if !NewSet(ConsoleRead).SubsetOf(s) || s.SubsetOf(NewSet(ConsoleRead)) {
		t.Fatal("subset")
	}
	var nilSet Set
	if nilSet.Has(ConsoleRead) {
		t.Fatal("a nil set holds nothing")
	}
	if got := s.Sorted(); got[0] != string(AuditRead) {
		t.Fatalf("sorted: %v", got)
	}
}
