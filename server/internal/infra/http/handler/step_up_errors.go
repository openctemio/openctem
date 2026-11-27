package handler

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/server/internal/app/accesscontrol"
	authapp "github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

// writeStepUpError answers a service's step-up refusal (from
// middleware.RecentAuthGate) the way RequireRecentAuth does, so the web client
// shows its re-authentication dialog and retries. It reports whether it wrote
// one.
func writeStepUpError(w http.ResponseWriter, err error) bool {
	return middleware.WriteStepUpError(w, err, authapp.StepUpWindow)
}

// writeTeamGrantError answers the refusals of a team change that hands out
// roles (membership of a team that carries roles, a role bound to a team)
// with their own code and sentence, so the web says why instead of the
// generic permission text. It reports whether it wrote one.
func writeTeamGrantError(w http.ResponseWriter, err error) bool {
	return writeTeamGrantErrorFor(w, nil, err)
}

// OutsideMemberDetail names a team member outside the organization (or a
// service account) in a TEAM_EXTERNAL_FULL_DATA refusal.
type OutsideMemberDetail struct {
	UserID  string `json:"user_id"`
	Name    string `json:"name,omitempty"`
	Service bool   `json:"service,omitempty"`
}

// codeTeamSelfMember: a non-owner gave roles to a team they are a member of
// (presets, or turning on a team that carries roles).
const codeTeamSelfMember apierror.Code = "TEAM_SELF_MEMBER"

const teamSelfMemberMessage = "You are a member of this team, so giving it roles would raise your own access. Ask the organization owner to do it."

// writeTeamGrantErrorFor is writeTeamGrantError that, for a request whose
// caller may read the team's members, names the outside members behind a
// TEAM_EXTERNAL_FULL_DATA refusal (details.outside_members). Without the
// request or that permission the details are left out; the code and the
// sentence stay the same.
func writeTeamGrantErrorFor(w http.ResponseWriter, r *http.Request, err error) bool {
	var code apierror.Code
	switch {
	case errors.Is(err, accesscontrol.ErrPrivilegedTeamOwnerOnly):
		code = apierror.CodeTeamPrivilegedOwnerOnly
	case errors.Is(err, accesscontrol.ErrExternalTeamFullData):
		code = apierror.CodeTeamExternalFullData
	case errors.Is(err, accesscontrol.ErrSelfJoinRoleTeam):
		code = apierror.CodeTeamSelfJoin
	case errors.Is(err, accesscontrol.ErrSelfMemberRoleTeam):
		// Not in the registry yet (its console words follow in a web
		// change): sent with its own status and sentence, which the console
		// shows for a code it has no words for.
		apierror.New(http.StatusForbidden, codeTeamSelfMember, teamSelfMemberMessage).WriteJSON(w)
		return true
	default:
		return false
	}
	e := apierror.FromCode(code)
	var outside *accesscontrol.OutsideMembersError
	if r != nil && errors.As(err, &outside) && middleware.HasPermission(r.Context(), permission.GroupsRead.String()) {
		list := make([]OutsideMemberDetail, len(outside.Members))
		for i, m := range outside.Members {
			list[i] = OutsideMemberDetail{UserID: m.UserID.String(), Name: m.Name, Service: m.Service}
		}
		e = e.WithDetails(map[string]any{"outside_members": list})
	}
	e.WriteJSON(w)
	return true
}
