package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCapabilities struct {
	passiveOnly map[shared.ID]bool
	err         error
	asked       []shared.ID
}

func (f *fakeCapabilities) ActiveScanningAllowed(_ context.Context, t shared.ID) (bool, error) {
	f.asked = append(f.asked, t)
	if f.err != nil {
		return false, f.err
	}
	return !f.passiveOnly[t], nil
}

func getCapabilities(t *testing.T, f *fakeCapabilities, req *http.Request) (*httptest.ResponseRecorder, ScanCapabilitiesResponse) {
	t.Helper()
	h := NewScanHandler(nil, nil, nil, nil, logger.NewNop())
	h.capabilities = f
	rec := httptest.NewRecorder()
	h.GetCapabilities(rec, req)
	var body ScanCapabilitiesResponse
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
	}
	return rec, body
}

// SECURITY: the answer is about the organization of the credential, and only
// it: a passive-only organization reads false while another reads true in
// the same run, and the reader is asked about the credential's tenant.
func TestGetCapabilities_PerOrganization(t *testing.T) {
	passive, other := shared.NewID(), shared.NewID()
	f := &fakeCapabilities{passiveOnly: map[shared.ID]bool{passive: true}}

	rec, body := getCapabilities(t, f, reqWithTenant("/api/v1/scans/capabilities", passive))
	if rec.Code != http.StatusOK || body.ActiveScanning {
		t.Fatalf("passive-only organization: %d %+v", rec.Code, body)
	}
	rec, body = getCapabilities(t, f, reqWithTenant("/api/v1/scans/capabilities", other))
	if rec.Code != http.StatusOK || !body.ActiveScanning {
		t.Fatalf("other organization: %d %+v", rec.Code, body)
	}
	if len(f.asked) != 2 || f.asked[0] != passive || f.asked[1] != other {
		t.Fatalf("asked about %v", f.asked)
	}
}

// SECURITY: a query parameter naming another organization is ignored; the
// tenant comes from the credential only.
func TestGetCapabilities_IgnoresTenantInRequest(t *testing.T) {
	mine, theirs := shared.NewID(), shared.NewID()
	f := &fakeCapabilities{passiveOnly: map[shared.ID]bool{theirs: true}}
	req := reqWithTenant("/api/v1/scans/capabilities?tenant_id="+theirs.String(), mine)
	rec, body := getCapabilities(t, f, req)
	if rec.Code != http.StatusOK || !body.ActiveScanning || f.asked[0] != mine {
		t.Fatalf("read another organization: %d %+v asked %v", rec.Code, body, f.asked)
	}
}

func TestGetCapabilities_NoTenantIsUnauthorized(t *testing.T) {
	f := &fakeCapabilities{}
	rec, _ := getCapabilities(t, f, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/capabilities", nil))
	if rec.Code != http.StatusUnauthorized || len(f.asked) != 0 {
		t.Fatalf("status %d, asked %v", rec.Code, f.asked)
	}
}

// A failed lookup is an error, never "active scanning allowed", and its
// cause is not in the response.
func TestGetCapabilities_LookupErrorIsNotAllowed(t *testing.T) {
	f := &fakeCapabilities{err: errors.New("db password=secret")}
	rec, _ := getCapabilities(t, f, reqWithTenant("/api/v1/scans/capabilities", shared.NewID()))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Body.String(); strings.Contains(got, "secret") {
		t.Fatalf("error cause leaked: %s", got)
	}
}
