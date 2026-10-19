package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// A scan profile is only the quality gate: tools, intensity, timeout and
// concurrency were stored and never applied at dispatch. A request that sets
// one is refused instead of silently doing nothing, and responses no longer
// carry them.
func TestScanProfileRefusesRemovedFields(t *testing.T) {
	tenantID, userID := shared.NewID(), shared.NewID().String()
	repo := &auditProfileRepo{byID: map[shared.ID]*scanprofile.ScanProfile{}}
	h := NewScanProfileHandler(scan.NewScanProfileService(repo, logger.NewNop()), validator.New(), logger.NewNop())

	for name, body := range map[string]string{
		"tools config": `{"name":"p","tools_config":{"nuclei":{"enabled":true}}}`,
		"intensity":    `{"name":"p","intensity":"low"}`,
		"concurrency":  `{"name":"p","max_concurrent_scans":3}`,
		"timeout":      `{"name":"p","timeout_seconds":600}`,
	} {
		t.Run("create "+name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles", []byte(body), tenantID.String(), userID, ""))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "quality gate") {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if len(repo.byID) != 0 {
				t.Fatal("a profile was stored")
			}
		})
	}

	w := httptest.NewRecorder()
	h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles",
		[]byte(`{"name":"p","intensity":null,"quality_gate":{"enabled":true,"fail_on_critical":true,"max_critical":-1,"max_high":-1,"max_medium":-1,"max_total":-1}}`), tenantID.String(), userID, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d: %s", w.Code, w.Body.String())
	}
	for _, key := range []string{"tools_config", "intensity", "max_concurrent_scans", "timeout_seconds", "template_mode"} {
		if strings.Contains(w.Body.String(), key) {
			t.Fatalf("response still carries %s: %s", key, w.Body.String())
		}
	}
	if !strings.Contains(w.Body.String(), `"fail_on_critical":true`) {
		t.Fatalf("quality gate lost: %s", w.Body.String())
	}
	var id string
	for k := range repo.byID {
		id = k.String()
	}
	w = httptest.NewRecorder()
	h.Update(w, auditedRequest(http.MethodPut, "/api/v1/scan-profiles/"+id,
		[]byte(`{"name":"p","intensity":"high"}`), tenantID.String(), userID, id))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("update: status %d: %s", w.Code, w.Body.String())
	}
}

// Rows written before the removal still hold the keys in tools_config;
// they are dropped on read and not written back.
func TestStoredTemplateFieldsAreDropped(t *testing.T) {
	var cfg map[string]scanprofile.ToolConfig
	if err := json.Unmarshal([]byte(`{"nuclei":{"enabled":true,"template_mode":"custom","custom_template_ids":["x"]}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "template") || !cfg["nuclei"].Enabled {
		t.Fatalf("round trip: %s", out)
	}
}
