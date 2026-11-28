package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/scanpolicy"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The refusal to turn shared sensors on says what is missing: the registered
// code SHARED_SENSORS_NOT_READY with details.params.missing naming the parts
// this version does not have, also in the message.
func TestAdminSharedSensors_NotReadyNamesWhatIsMissing(t *testing.T) {
	h := &AdminScanPolicyHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.writeSharedErr(rec, scanpolicy.ErrSharedSensorsNotReady)
	var b errBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict || b.Code != "SHARED_SENSORS_NOT_READY" {
		t.Fatalf("got %d %s", rec.Code, b.Code)
	}
	missing := b.Details.Params["missing"]
	if missing == "" {
		t.Fatalf("no details.params.missing: %s", rec.Body.String())
	}
	for _, part := range scanpolicy.SharedSensorsMissing() {
		if !strings.Contains(missing, part) || !strings.Contains(b.Message, part) {
			t.Errorf("%q not named (params %q, message %q)", part, missing, b.Message)
		}
	}
}
