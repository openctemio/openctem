package handler

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// Invitation tokens are stored hashed (api#552), so the list can only ever
// return the hash: useless as a link and easy to mistake for one. The list
// carries no token for anyone; the raw token appears once, in the create
// response.
func TestInvitationListItem_HasNoToken(t *testing.T) {
	inv, err := tenant.NewInvitation(shared.NewID(), "a@example.com", tenant.RoleViewer, shared.NewID(),
		[]string{"00000000-0000-0000-0000-000000000004"})
	if err != nil {
		t.Fatalf("invitation: %v", err)
	}
	inv.SetToken("stored-hash-not-a-link")

	b, err := json.Marshal(toInvitationListItem(inv))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["token"]; ok {
		t.Fatalf("list item must not carry a token field: %s", b)
	}
	if m["id"] != inv.ID().String() || m["email"] != "a@example.com" {
		t.Fatalf("list item lost its fields: %s", b)
	}

	// The create response still returns the (raw) token to its creator.
	inv.SetToken("raw-token")
	b, _ = json.Marshal(toInvitationResponse(inv, true))
	_ = json.Unmarshal(b, &m)
	if m["token"] != "raw-token" {
		t.Fatalf("create response must carry the token: %s", b)
	}
}
