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

// A scan profile never selected templates: dispatch takes custom templates
// from the scan. The profile's template_mode and custom_template_ids were
// stored and ignored; a request that sets them is now refused instead of
// silently doing nothing, and responses no longer carry them.
func TestScanProfileRefusesRemovedTemplateFields(t *testing.T) {
	tenantID, userID := shared.NewID(), shared.NewID().String()
	repo := &auditProfileRepo{byID: map[shared.ID]*scanprofile.ScanProfile{}}
	h := NewScanProfileHandler(scan.NewScanProfileService(repo, logger.NewNop()), validator.New(), logger.NewNop())

	for name, body := range map[string]string{
		"template mode":       `{"name":"p","tools_config":{"nuclei":{"enabled":true,"template_mode":"custom"}}}`,
		"custom template ids": `{"name":"p","tools_config":{"nuclei":{"enabled":true,"custom_template_ids":["00000000-0000-0000-0000-000000000001"]}}}`,
	} {
		t.Run("create "+name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles", []byte(body), tenantID.String(), userID, ""))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "template_mode") {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if len(repo.byID) != 0 {
				t.Fatal("a profile was stored")
			}
		})
	}

	w := httptest.NewRecorder()
	h.Create(w, auditedRequest(http.MethodPost, "/api/v1/scan-profiles",
		[]byte(`{"name":"p","tools_config":{"nuclei":{"enabled":true,"severity":"high"}}}`), tenantID.String(), userID, ""))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "template_mode") || strings.Contains(w.Body.String(), "custom_template_ids") {
		t.Fatalf("response still carries removed fields: %s", w.Body.String())
	}
	var id string
	for k := range repo.byID {
		id = k.String()
	}
	w = httptest.NewRecorder()
	h.Update(w, auditedRequest(http.MethodPut, "/api/v1/scan-profiles/"+id,
		[]byte(`{"name":"p","tools_config":{"nuclei":{"enabled":true,"template_mode":"both"}}}`), tenantID.String(), userID, id))
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
