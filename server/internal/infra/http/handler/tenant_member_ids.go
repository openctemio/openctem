package handler

import (
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxMemberUserIDs bounds the user_ids filter of the members list: one screen
// shows far fewer people than this.
const maxMemberUserIDs = 100

// parseMemberUserIDs reads the comma-separated user_ids filter of the members
// list. Every id must be a UUID (a malformed id is a 400, never passed to SQL)
// and there are at most maxMemberUserIDs. An empty value means no filter. The
// result is still intersected with the caller's tenant by the query, so an id
// of a user in another organization is simply absent from the answer.
func parseMemberUserIDs(w http.ResponseWriter, raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxMemberUserIDs {
		apierror.BadRequest("user_ids accepts at most 100 ids").WriteJSON(w)
		return nil, false
	}
	ids := make([]string, 0, len(parts))
	for _, p := range parts {
		id, err := shared.IDFromString(strings.TrimSpace(p))
		if err != nil {
			apierror.BadRequest("user_ids must be a comma-separated list of user ids").WriteJSON(w)
			return nil, false
		}
		ids = append(ids, id.String())
	}
	return ids, true
}
