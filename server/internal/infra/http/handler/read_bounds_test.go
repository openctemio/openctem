package handler

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func boundsIDs(n int) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = `"` + shared.NewID().String() + `"`
	}
	return "[" + strings.Join(ids, ",") + "]"
}

// The asset-group bulk routes refuse more than 1000 group ids before they
// reach the service (nil here: reaching it would panic).
func TestAssetGroupBulk_RefusesMoreThanCap(t *testing.T) {
	h := NewAssetGroupHandler(nil, validator.New(), logger.NewNop())
	tenant := shared.NewID()
	cases := map[string]struct {
		call func(http.ResponseWriter, *http.Request)
		body func(n int) string
	}{
		"update": {h.BulkUpdate, func(n int) string {
			return `{"group_ids":` + boundsIDs(n) + `,"update":{"environment":"production"}}`
		}},
		"delete": {h.BulkDelete, func(n int) string { return `{"group_ids":` + boundsIDs(n) + `}` }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			req := requestWithTenant(http.MethodPost, "/x", c.body(1001), tenant)
			rec := httptest.NewRecorder()
			c.call(rec, req)
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("1001 ids: status %d, want a validation refusal; body %s", rec.Code, rec.Body)
			}
		})
	}
}

func csvUpload(t *testing.T, rows int) *http.Request {
	t.Helper()
	var csvBuf bytes.Buffer
	w := csv.NewWriter(&csvBuf)
	for i := 0; i < rows; i++ {
		_ = w.Write([]string{"identifier", fmt.Sprint(i)})
	}
	w.Flush()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "c.csv")
	_, _ = fw.Write(csvBuf.Bytes())
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/credentials/import/csv", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
}

// A credential CSV above the row cap is a 400 before the service runs.
func TestCredentialImportCSV_RefusesMoreThanRowCap(t *testing.T) {
	h := NewCredentialImportHandler(nil, validator.New(), logger.NewNop())
	rec := httptest.NewRecorder()
	h.ImportCSV(rec, csvUpload(t, maxCredentialCSVRows+1))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too many rows") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestReadCSVRecords_Boundary(t *testing.T) {
	in := "a,b\n1,2\n3,4\n"
	recs, err := readCSVRecords(csv.NewReader(strings.NewReader(in)), 3)
	if err != nil || len(recs) != 3 {
		t.Fatalf("at the cap: %d records, err %v", len(recs), err)
	}
	if _, err := readCSVRecords(csv.NewReader(strings.NewReader(in)), 2); err == nil {
		t.Fatal("over the cap must fail")
	}
}
