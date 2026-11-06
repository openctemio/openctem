package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The refusals of a team change reach the client with their own code, not
// the generic FORBIDDEN, and the step-up refusal keeps the shared code the
// web answers with its re-authentication dialog.
func TestGroupHandler_TeamGrantRefusalCodes(t *testing.T) {
	h := &GroupHandler{logger: logger.NewNop()}
	cases := []struct {
		err  error
		code string
	}{
		{fmt.Errorf("wrapped: %w", middleware.ErrStepUpRequired), "STEP_UP_REQUIRED"},
		{middleware.ErrStepUpUnavailable, "STEP_UP_UNAVAILABLE"},
		{accesscontrol.ErrPrivilegedTeamOwnerOnly, "TEAM_PRIVILEGED_OWNER_ONLY"},
		{accesscontrol.ErrExternalTeamFullData, "TEAM_EXTERNAL_FULL_DATA"},
		{accesscontrol.ErrSelfJoinRoleTeam, "TEAM_SELF_JOIN"},
		{accesscontrol.ErrGrantForbidden, "FORBIDDEN"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, c.err)
		var body struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusForbidden || body.Code != c.code {
			t.Errorf("%v: got %d %s, want 403 %s", c.err, rec.Code, body.Code, c.code)
		}
	}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, accesscontrol.ErrPrivilegedTeamOwnerOnly)
	if want := "Only the organization owner can change the members of a team that carries a privileged role."; !strings.Contains(rec.Body.String(), want) {
		t.Errorf("owner-only message missing: %s", rec.Body.String())
	}
}

// A full-data refusal names the outside members to a caller who may read the
// team's members, and to nobody else; the code is the same either way.
func TestGroupHandler_OutsideMembersNamedOnlyToMemberReaders(t *testing.T) {
	h := &GroupHandler{logger: logger.NewNop()}
	outsider := shared.NewID()
	refusal := fmt.Errorf("bind: %w", &accesscontrol.OutsideMembersError{
		Members: []group.OutsideMember{{UserID: outsider, Name: "Pat Contractor"}},
	})
	for _, c := range []struct {
		perms []string
		named bool
	}{
		{[]string{permission.GroupsRead.String(), permission.GroupsWrite.String()}, true},
		{[]string{permission.GroupsWrite.String(), permission.RolesAssign.String()}, false},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/groups/x/roles", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.FetchedPermissionsKey, c.perms))
		rec := httptest.NewRecorder()
		h.writeBindingError(rec, req, refusal)
		var body struct {
			Code    string `json:"code"`
			Details struct {
				Outside []OutsideMemberDetail `json:"outside_members"`
			} `json:"details"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusForbidden || body.Code != "TEAM_EXTERNAL_FULL_DATA" {
			t.Fatalf("%v: got %d %s", c.perms, rec.Code, body.Code)
		}
		got := len(body.Details.Outside) == 1 && body.Details.Outside[0].UserID == outsider.String() && body.Details.Outside[0].Name == "Pat Contractor"
		if got != c.named || (!c.named && strings.Contains(rec.Body.String(), "Pat Contractor")) {
			t.Fatalf("%v: named=%v want %v: %s", c.perms, got, c.named, rec.Body.String())
		}
	}
}
