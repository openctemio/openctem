package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// A trigger whose context sets a platform-owned key is refused with 400
// before the service runs (the handler has no service here: reaching it
// would panic).
func TestTriggerScan_RefusesPlatformContextKeys(t *testing.T) {
	h := NewScanHandler(nil, nil, nil, nil, logger.NewNop())
	for _, body := range []string{
		`{"context":{"uncovered_targets":5}}`,
		`{"context":{"rule_sources":"x"}}`,
		`{"context":{"reason":"ok","sensor_routing":{}}}`,
		`{"context":{"reason":7}}`,
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/scans/x/trigger", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.TriggerScan(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: want 400, got %d", body, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "TRIGGER_CONTEXT_REFUSED") {
			t.Fatalf("body %s: want the refusal code, got %s", body, rec.Body.String())
		}
	}
}
