package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func postRunResults(t *testing.T, h *CIRunnerHandler, run *cirun.Run, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/"+run.ID.String()+"/results", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), ciRunContextKey{}, run))
	w := httptest.NewRecorder()
	h.UploadResults(w, r)
	return w
}

func exportRun() *cirun.Run {
	return &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID(),
		Repository: "github.com/acme/api", Branch: "main", CommitSHA: strings.Repeat("a", 40)}
}

// A DefectDojo export names hosts and domains: none of them is the run's
// repository, so every finding is dropped and counted, nothing ingested.
const ddExport = `{"findings": [
 {"title": "SQLi", "severity": "High", "description": "d", "endpoints": [{"host": "shop.example.com", "protocol": "https"}]},
 {"title": "In code", "severity": "Medium", "description": "d", "file_path": "src/app.py", "line": 3}
]}`

func TestCIExport_FindingsOffTheRepositoryAreDropped(t *testing.T) {
	svc := &fakeCIService{}
	h := NewCIRunnerHandler(svc, logger.NewNop())
	run := exportRun()
	w := postRunResults(t, h, run, []byte(ddExport))
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp CIExportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if svc.ctisPath != 0 || len(resp.Files) != 1 || resp.Files[0].Format != "defectdojo" {
		t.Fatalf("response %+v, ctis path %d", resp, svc.ctisPath)
	}
	if resp.FindingsDroppedOutOfScope == 0 {
		t.Fatal("findings on hosts were not dropped")
	}
	for _, rep := range svc.imported {
		if len(rep.Assets) != 1 || rep.Assets[0].Value != run.Repository {
			t.Fatalf("assets %+v", rep.Assets)
		}
		if rep.Metadata.Branch == nil || rep.Metadata.Branch.CommitSHA != run.CommitSHA || rep.Metadata.Branch.Name != "main" {
			t.Fatalf("branch not from the run: %+v", rep.Metadata.Branch)
		}
	}
}

// A CTIS report keeps the CTIS path, even though a detector sees its
// top-level "findings".
func TestCIExport_CTISStaysOnTheCTISPath(t *testing.T) {
	svc := &fakeCIService{}
	h := NewCIRunnerHandler(svc, logger.NewNop())
	body := `{"version":"1.4","metadata":{"timestamp":"2026-10-05T00:00:00Z"},"assets":[{"id":"r","type":"repository","value":"github.com/acme/api"}],"findings":[]}`
	w := postRunResults(t, h, exportRun(), []byte(body))
	if w.Code != http.StatusCreated || svc.ctisPath != 1 || len(svc.imported) != 0 {
		t.Fatalf("status %d ctis %d imported %d", w.Code, svc.ctisPath, len(svc.imported))
	}
}

func TestCIExport_HostileInputRefused(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	f, _ := zw.Create("../../etc/x.json")
	_, _ = f.Write([]byte(ddExport))
	_ = zw.Close()
	cases := map[string][]byte{
		"xxe":           []byte(`<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY x SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&x;</NessusClientData_v2>`),
		"deep":          []byte(`{"findings": ` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}`),
		"zip traversal": zbuf.Bytes(),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			svc := &fakeCIService{}
			w := postRunResults(t, NewCIRunnerHandler(svc, logger.NewNop()), exportRun(), body)
			if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if len(svc.imported) != 0 || svc.ctisPath != 0 || strings.Contains(w.Body.String(), "root:") {
				t.Fatal("a refused upload was ingested or echoed")
			}
		})
	}
}
