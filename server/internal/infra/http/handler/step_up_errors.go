package handler

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
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
