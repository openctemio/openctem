package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A sensor controls the payload, and parser errors quote it. The client
// message must not carry raw line breaks, and must stay bounded.
func TestWriteIngestError_SanitizesSensorControlledText(t *testing.T) {
	h := &IngestHandler{logger: logger.NewNop()}
	forged := "bad field\r\nlevel=ERROR msg=\"forged\" " + strings.Repeat("x", 2000)
	err := fmt.Errorf("%w: %s", shared.ErrValidation, forged)

	rec := httptest.NewRecorder()
	h.writeIngestError(rec, "SARIF ingestion failed", err, "scanner_type", "semgrep\nlevel=ERROR")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `\r\n`) || strings.Contains(body, `\n`+"level=ERROR") {
		t.Errorf("response echoes raw line breaks from the sensor payload: %s", body)
	}
	if len(body) > 600 {
		t.Errorf("response length %d, want the echoed error capped", len(body))
	}
}

func TestWriteIngestError_PayloadTooLargeIs413(t *testing.T) {
	h := &IngestHandler{logger: logger.NewNop()}
	err := shared.NewDomainError(ingest.CodePayloadTooLarge, "too many findings", shared.ErrValidation)

	rec := httptest.NewRecorder()
	h.writeIngestError(rec, "CTIS ingestion failed", err)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}
