package handler

import (
	"encoding/json"
	"testing"
)

// memberValues + memberRemovePathRe are where the Okta (value arrays) vs Azure
// (path filters) PATCH differences live — the fiddly, bug-prone parsing.

func TestSCIMGroup_MemberValues_OktaValueArray(t *testing.T) {
	h := &SCIMHandler{}
	raw := json.RawMessage(`[{"value":"11111111-1111-1111-1111-111111111111"},{"value":"22222222-2222-2222-2222-222222222222"}]`)
	ids := h.memberValues(raw)
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
}

func TestSCIMGroup_MemberValues_MembersObject(t *testing.T) {
	h := &SCIMHandler{}
	raw := json.RawMessage(`{"members":[{"value":"11111111-1111-1111-1111-111111111111"}]}`)
	ids := h.memberValues(raw)
	if len(ids) != 1 {
		t.Fatalf("expected 1 id from members-object form, got %d", len(ids))
	}
}

func TestSCIMGroup_MemberValues_Empty(t *testing.T) {
	h := &SCIMHandler{}
	if ids := h.memberValues(nil); len(ids) != 0 {
		t.Errorf("nil value should yield no ids, got %d", len(ids))
	}
	if ids := h.memberValues(json.RawMessage(`{}`)); len(ids) != 0 {
		t.Errorf("empty object should yield no ids, got %d", len(ids))
	}
}

func TestSCIMGroup_AzureRemovePathFilter(t *testing.T) {
	cases := map[string]string{
		`members[value eq "abc-123"]`:  "abc-123",
		`members[value eq "11111111"]`: "11111111",
		`Members[value eq "X-Y-Z"]`:    "X-Y-Z", // case-insensitive
	}
	for path, want := range cases {
		m := memberRemovePathRe.FindStringSubmatch(path)
		if m == nil {
			t.Errorf("path %q did not match the Azure remove filter", path)
			continue
		}
		if m[1] != want {
			t.Errorf("path %q extracted %q, want %q", path, m[1], want)
		}
	}
	if memberRemovePathRe.FindStringSubmatch("members") != nil {
		t.Error("plain 'members' path must not match the value-filter regex")
	}
}
