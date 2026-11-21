package handler

// The reason an administrator gives for a privileged roster action (role or
// active-state change, new administrator, two-step reset, break-glass test,
// identity-provider unbind). It is kept in the action's admin audit row and in
// the four-eyes gate's row, so the record says why, not only what.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/internal/app/adminapproval"
	"github.com/openctemio/openctem/server/pkg/apierror"
)

// maxAdminActionReason bounds an action reason, the same bound as an approval
// request's reason.
//
// The reason is optional for now: the console released with this server does
// not send it yet. The redesigned console sends it with every one of these
// actions, and it becomes required once that console ships (an empty reason
// is then refused like an over-long one).
const maxAdminActionReason = adminapproval.MaxReasonLength

// maxAdminActionReasonBody bounds the JSON body that carries only a reason:
// 1000 characters of up to 4 bytes, JSON-escaped, with room to spare.
const maxAdminActionReasonBody = 16 << 10

// AdminActionReasonRequest is the optional body of a roster action that has
// no other input.
type AdminActionReasonRequest struct {
	// Reason (optional, 1 to 1000 characters after trimming) is kept in the
	// action's audit record.
	Reason string `json:"reason,omitempty"`
}

// adminActionReason trims an action reason and checks its length. An empty
// reason is allowed (see maxAdminActionReason). false: the refusal is written.
func adminActionReason(w http.ResponseWriter, raw string) (string, bool) {
	reason := strings.TrimSpace(raw)
	if utf8.RuneCountInString(reason) > maxAdminActionReason {
		apierror.BadRequest(fmt.Sprintf("the reason may be at most %d characters", maxAdminActionReason)).WriteJSON(w)
		return "", false
	}
	return reason, true
}

// readAdminActionReason reads the optional {"reason": ...} body of a roster
// action. No body is no reason. false: the refusal is written.
func readAdminActionReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", true
	}
	var req AdminActionReasonRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminActionReasonBody)).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			return "", true
		}
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return "", false
	}
	return adminActionReason(w, req.Reason)
}
