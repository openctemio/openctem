package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type scimFeatureOff struct{ err error }

func (f scimFeatureOff) Usable(context.Context, shared.ID, string) (bool, error) {
	return false, f.err
}

func patchActive(active bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": active}},
	})
	return b
}

// A leaver must lose access through SCIM even when the organization may no
// longer use SCIM (or its limits cannot be read): deactivation and deletion
// pass the feature gate; anything that grants or restores access, and every
// create or group change, stays refused.
func TestSCIM_FeatureOff_DeprovisioningStillWorks(t *testing.T) {
	for name, gate := range map[string]scimFeatureOff{
		"feature off":       {},
		"limits unreadable": {err: errors.New("db down")},
	} {
		t.Run(name, func(t *testing.T) {
			e := newSCIMTestEnv()
			e.auth = middleware.SCIMAuthWithFeature(stubSCIMAuth{tenantID: e.tenantID}, gate)

			patchID := e.seedMember(t, "patch-off@example.com")
			w := e.serve(t, e.handler.PatchUser, http.MethodPatch, "/scim/v2/Users/"+patchID.String(), patchActive(false), patchID.String(), false)
			if w.Code != http.StatusOK || !e.members.byUser[patchID].IsSuspended() {
				t.Fatalf("PATCH active:false with the feature off: %d suspended=%v", w.Code, e.members.byUser[patchID].IsSuspended())
			}

			putID := e.seedMember(t, "put-off@example.com")
			w = e.serve(t, e.handler.ReplaceUser, http.MethodPut, "/scim/v2/Users/"+putID.String(), []byte(`{"active":false}`), putID.String(), false)
			if w.Code != http.StatusOK || !e.members.byUser[putID].IsSuspended() {
				t.Fatalf("PUT active:false with the feature off: %d", w.Code)
			}

			delID := e.seedMember(t, "del-off@example.com")
			w = e.serve(t, e.handler.DeleteUser, http.MethodDelete, "/scim/v2/Users/"+delID.String(), nil, delID.String(), false)
			if w.Code != http.StatusNoContent || !e.members.byUser[delID].IsOffboarded() {
				t.Fatalf("DELETE with the feature off: %d", w.Code)
			}

			// Reactivation grants access: refused, and the member stays suspended.
			w = e.serve(t, e.handler.PatchUser, http.MethodPatch, "/scim/v2/Users/"+patchID.String(), patchActive(true), patchID.String(), false)
			if w.Code != http.StatusForbidden || !e.members.byUser[patchID].IsSuspended() {
				t.Fatalf("PATCH active:true with the feature off: %d", w.Code)
			}
			w = e.serve(t, e.handler.ReplaceUser, http.MethodPut, "/scim/v2/Users/"+putID.String(), []byte(`{}`), putID.String(), false)
			if w.Code != http.StatusForbidden || !e.members.byUser[putID].IsSuspended() {
				t.Fatalf("PUT without active (defaults to true) with the feature off: %d", w.Code)
			}

			// Creating a user stays gated.
			w = e.serve(t, e.handler.CreateUser, http.MethodPost, "/scim/v2/Users", []byte(`{"userName":"new@example.com","active":true}`), "", false)
			if w.Code == http.StatusCreated {
				t.Fatalf("create user with the feature off: %d", w.Code)
			}
		})
	}
}
