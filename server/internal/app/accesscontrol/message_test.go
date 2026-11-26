package accesscontrol

import "testing"

func TestTeamRoleMessage(t *testing.T) {
	for in, want := range map[string]string{"owner": "team.role.owner", "lead": "team.role.lead", "member": "team.role.member", "Bad Role": "team.role.other"} {
		m := teamRoleMessage(in)
		if m.Code != want {
			t.Errorf("%q -> %s, want %s", in, m.Code, want)
		}
		if err := m.Validate(); err != nil {
			t.Error(err)
		}
	}
}
