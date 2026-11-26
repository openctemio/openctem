package onboarding

import "testing"

func TestDomainNoticeMessages(t *testing.T) {
	m := domainJoinedMessage("a@corp.example", "viewer", "corp.example")
	if m.Code != "onboarding.domain_joined" || m.Params["email"] != "a@corp.example" || m.Params["role"] != "viewer" || m.Params["domain"] != "corp.example" {
		t.Errorf("joined = %+v", m)
	}
	r := domainRequestMessage("a@corp.example", "corp.example")
	if r.Code != "onboarding.join_requested" || r.Params["email"] != "a@corp.example" || r.Params["domain"] != "corp.example" {
		t.Errorf("requested = %+v", r)
	}
}
