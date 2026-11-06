package tenant

import "testing"

func TestMFAFloorAppliesTo(t *testing.T) {
	cases := []struct {
		floor      MFAFloor
		role       string
		privileged bool
		want       bool
	}{
		{MFAFloorNone, "owner", true, false},
		{MFAFloorAdmins, "owner", false, true},
		{MFAFloorAdmins, "admin", false, true},
		{MFAFloorAdmins, "member", false, false},
		{MFAFloorAdmins, "member", true, true}, // a member holding a privileged role is an administrator
		{MFAFloorEveryone, "viewer", false, true},
	}
	for _, c := range cases {
		if got := c.floor.AppliesTo(c.role, c.privileged); got != c.want {
			t.Errorf("%s %s privileged=%v: %v, want %v", c.floor, c.role, c.privileged, got, c.want)
		}
	}
}

func TestOrganizationRequirementUsesEffectivePrivilege(t *testing.T) {
	s := SecuritySettings{MFARequiredForAdmins: true}
	if !s.RequiresMFAByOrganization("member", true) {
		t.Fatal("a member with a privileged role must be covered by 2FA for admins")
	}
	if s.RequiresMFAByOrganization("member", false) {
		t.Fatal("a plain member must not be covered by 2FA for admins")
	}
	if !(SecuritySettings{MFARequired: true}).RequiresMFAByOrganization("viewer", false) {
		t.Fatal("2FA for everyone covers every member")
	}
}

func TestBelowFloorAndClamp(t *testing.T) {
	none := SecuritySettings{}
	if !none.BelowMFAFloor(MFAFloorAdmins) || !none.BelowMFAFloor(MFAFloorEveryone) || none.BelowMFAFloor(MFAFloorNone) {
		t.Fatal("empty settings are below admins and everyone, not below none")
	}
	adm := SecuritySettings{MFARequiredForAdmins: true}
	if adm.BelowMFAFloor(MFAFloorAdmins) || !adm.BelowMFAFloor(MFAFloorEveryone) {
		t.Fatal("admins-only settings meet admins, not everyone")
	}
	got := none.ClampToMFAFloor(MFAFloorEveryone)
	if !got.MFARequired || none.MFARequired {
		t.Fatal("clamp raises the copy and never the original")
	}
	if !none.ClampToMFAFloor(MFAFloorAdmins).MFARequiredForAdmins {
		t.Fatal("clamp to admins sets 2FA for admins")
	}
}

func TestParseMFAFloor(t *testing.T) {
	if f, ok := ParseMFAFloor(" Admins "); !ok || f != MFAFloorAdmins {
		t.Fatalf("got %q %v", f, ok)
	}
	if _, ok := ParseMFAFloor("most"); ok {
		t.Fatal("unknown floor accepted")
	}
	if MFAFloorNone.Rank() >= MFAFloorAdmins.Rank() || MFAFloorAdmins.Rank() >= MFAFloorEveryone.Rank() {
		t.Fatal("rank order")
	}
}
