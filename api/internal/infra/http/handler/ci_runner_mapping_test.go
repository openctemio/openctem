package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appimportmapping "github.com/openctemio/openctem/api/internal/app/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/importmapping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// recordingResolver knows one mapping (when set) and records the
// organization it was asked in.
type recordingResolver struct {
	tenants []shared.ID
	known   *appimportmapping.Resolved
}

func (r *recordingResolver) Resolve(_ context.Context, tenantID shared.ID, _ importmapping.FormatRef) (*appimportmapping.Resolved, error) {
	r.tenants = append(r.tenants, tenantID)
	if r.known == nil {
		return nil, importmapping.ErrUnknownMapping
	}
	return r.known, nil
}

// format=mapping:<name> on a CI upload is resolved in the run's own
// organization (from its token) at accept; an unknown mapping is a 400, the
// resolved version is pinned on the queued upload, and any other format is
// refused.
func TestCIUpload_MappingFormat(t *testing.T) {
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID()}
	send := func(h *CIRunnerHandler, format string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/x/results?format="+format, strings.NewReader("title\nx\n"))
		req = req.WithContext(context.WithValue(req.Context(), ciRunContextKey{}, run))
		rec := httptest.NewRecorder()
		h.UploadResults(rec, req)
		return rec
	}
	svc := &fakeCIService{run: run}
	res := &recordingResolver{}
	h := NewCIRunnerHandler(svc, logger.NewNop())
	h.SetMappingResolver(res)
	if rec := send(h, "mapping:legacy-vm"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), string(CodeUnknownMapping)) {
		t.Fatalf("unknown mapping: %d %s", rec.Code, rec.Body)
	}
	if len(res.tenants) != 1 || res.tenants[0] != run.TenantID {
		t.Fatalf("resolved in %v, want the run's organization %s", res.tenants, run.TenantID)
	}
	for _, f := range []string{"nessus", "mapping:Bad", "mapping:a@0"} {
		if rec := send(h, f); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", f, rec.Code)
		}
	}
	if len(svc.accepted) != 0 {
		t.Fatalf("a refused format stored %d uploads", len(svc.accepted))
	}
	// Without the mapping service the format is refused, never ignored.
	if rec := send(NewCIRunnerHandler(svc, logger.NewNop()), "mapping:legacy-vm"); rec.Code != http.StatusBadRequest {
		t.Fatalf("no resolver: %d", rec.Code)
	}

	// A known mapping: the exact version resolved now is pinned.
	mid := shared.NewID()
	res.known = &appimportmapping.Resolved{
		Mapping: &importmapping.Mapping{ID: mid, Name: "legacy-vm"},
		Version: &importmapping.Version{Version: 3},
	}
	rec := send(h, "mapping:legacy-vm")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("known mapping: %d %s", rec.Code, rec.Body)
	}
	if len(svc.pins) != 1 || svc.pins[0] == nil || svc.pins[0].ID != mid.String() || svc.pins[0].Format != "mapping:legacy-vm@3" {
		t.Fatalf("pin = %+v", svc.pins)
	}
}
