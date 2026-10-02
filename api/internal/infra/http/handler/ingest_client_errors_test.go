package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/pkg/logger"
)

// A payload the sensor got wrong is the sensor's error, not the server's. These
// answered 500 — reproduced live against develop (2026-10-01) — which (a) logs
// an ERROR for every bad push and (b) tells the sensor SDK to retry a request
// that can never succeed: its retry queue keeps re-sending it.

func newClientErrorIngestHandler() *IngestHandler {
	svc := ingest.NewService(nil, nil, nil, nil, nil, nil, nil, nil, logger.NewNop())
	return NewIngestHandler(svc, nil, logger.NewNop())
}

func TestIngestSARIF_MalformedIsBadRequest(t *testing.T) {
	for name, body := range map[string]string{
		"runs is a string": `{"version":"2.1.0","runs":"x"}`,
		"top-level array":  `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := reqWithSensor(t, body)
			w := httptest.NewRecorder()
			newClientErrorIngestHandler().IngestSARIF(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestIngestCTIS_OversizedReportIs413(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":"1.0","metadata":{"id":"too-big"},"findings":[`)
	for i := 0; i <= ingest.MaxFindingsPerReport; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"vulnerability","title":"f%d","severity":"low"}`, i)
	}
	b.WriteString(`]}`)

	r, _ := reqWithSensor(t, b.String())
	w := httptest.NewRecorder()
	newClientErrorIngestHandler().IngestCTIS(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%.200s", w.Code, w.Body.String())
	}
}
