package handler

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
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
	apierror.FromCode(code).WriteJSON(w)
	return true
}
