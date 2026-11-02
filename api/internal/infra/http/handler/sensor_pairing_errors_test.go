package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The user-plane refusals of a re-pair reach the console as their own codes
// (research note 352, console messaging table).
func TestSensorPairingUserErrors(t *testing.T) {
	h := &SensorPairingHandler{log: logger.NewNop()}
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{sensorpairing.ErrRepairNotAcknowledged, http.StatusConflict, "REPAIR_NOT_ACKNOWLEDGED"},
		{sensorpairing.ErrOrganizationMismatch, http.StatusConflict, "ORGANIZATION_MISMATCH"},
		{sensorpairing.ErrInvalid, http.StatusBadRequest, "BAD_REQUEST"},
		{sensorpairing.ErrNotFound, http.StatusNotFound, "NOT_FOUND"},
	} {
		w := httptest.NewRecorder()
		h.writeUserError(w, tc.err)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != tc.status || body.Code != tc.code {
			t.Errorf("%v: %d %s, want %d %s", tc.err, w.Code, body.Code, tc.status, tc.code)
		}
	}
}
