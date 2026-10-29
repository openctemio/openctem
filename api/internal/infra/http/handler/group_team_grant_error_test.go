package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
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
