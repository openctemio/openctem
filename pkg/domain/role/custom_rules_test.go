package role

import "testing"

func TestIsReservedSlug(t *testing.T) {
	for _, s := range []string{"owner", "admin", "member", "viewer", "Owner", " ADMIN "} {
		if !IsReservedSlug(s) {
			t.Errorf("%q should be reserved", s)
		}
	}
	for _, s := range []string{"owners", "custom-owner", "analyst", ""} {
		if IsReservedSlug(s) {
			t.Errorf("%q should not be reserved", s)
		}
	}
}

func TestValidCustomHierarchyLevel(t *testing.T) {
	for _, l := range []int{0, 1, 50, MaxCustomHierarchyLevel} {
		if !ValidCustomHierarchyLevel(l) {
			t.Errorf("level %d should be allowed", l)
		}
	}
	for _, l := range []int{-1, AdminHierarchyLevel, 100} {
		if ValidCustomHierarchyLevel(l) {
			t.Errorf("level %d should be refused", l)
		}
	}
}

func TestIsSystemRoleID(t *testing.T) {
	for _, id := range []ID{OwnerRoleID, AdminRoleID, MemberRoleID, ViewerRoleID} {
		if !IsSystemRoleID(id) {
			t.Errorf("%s should be a system role", id)
		}
	}
	if IsSystemRoleID(NewID()) {
		t.Error("a random id is not a system role")
	}
}
