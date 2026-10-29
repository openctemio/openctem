package handler

import (
	"encoding/json"
	"testing"
	"time"
)

// The provisioning response never carries a password of any kind: the new
// administrator chooses their own with the emailed link. The invitation link
// is the only credential-like field, and it is omitted unless the platform
// could not send mail.
func TestProvisionResponseCarriesNoPassword(t *testing.T) {
	keys := func(r AdminProvisionResponse) map[string]json.RawMessage {
		raw, _ := json.Marshal(r)
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	exp := time.Now()
	emailed := keys(AdminProvisionResponse{InvitationEmailed: true, ExpiresAt: &exp})
	for _, banned := range []string{"temporary_password", "password", "invitation_url", "token"} {
		if _, ok := emailed[banned]; ok {
			t.Fatalf("an emailed invitation must return no %q", banned)
		}
	}
	shown := keys(AdminProvisionResponse{InvitationURL: "https://app.example.test/set-password#token=x"})
	if _, ok := shown["invitation_url"]; !ok {
		t.Fatal("the link must be returned when the platform cannot send mail")
	}
	if _, ok := shown["temporary_password"]; ok {
		t.Fatal("no temporary password exists any more")
	}
}
