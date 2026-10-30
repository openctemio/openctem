package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An approval request carries the scan definition it covers, scanner_config
// included, and the before/after of each changed field. A caller who may read
// approvals but not edit scans sees the credential-looking values masked, as
// on the scan read; editors, owners and admins see them in clear.

func TestApprovalResponse_MasksConfigSecretsForReaders(t *testing.T) {
	tenant := shared.NewID()
	before := redactTestConfig()
	before["password"] = "old-" + redactTestPassword
	q := &scangov.Request{
		ID: shared.NewID(), TenantID: tenant, ScanID: shared.NewID(),
		// Not pending: the response is built without the approver lookup.
		Status:     scangov.StatusApproved,
		Definition: scangov.Definition{ScanType: "single", ScannerName: "nuclei", ScannerConfig: redactTestConfig()},
		Changes: []scangov.Change{
			{Field: "scanner_config", Before: before, After: redactTestConfig()},
			{Field: "intensity", Before: "passive", After: "active"},
		},
	}
	h := &ScanApprovalHandler{}

	for _, c := range redactCallers {
		t.Run(c.name, func(t *testing.T) {
			r := withCaller(httptest.NewRequest(http.MethodGet, "/api/v1/scan-approvals", nil), tenant, c, nil)
			raw, err := json.Marshal(h.requestResponse(r, q))
			if err != nil {
				t.Fatal(err)
			}
			body := string(raw)
			for _, secret := range []string{redactTestPassword, redactTestBearer} {
				if got := strings.Contains(body, secret); got != c.reveal {
					t.Fatalf("response contains %q = %v, want %v: %s", secret, got, c.reveal, body)
				}
			}
			// Non-secret values and plain fields stay readable for everyone.
			for _, plain := range []string{"plain-header", `"after":"active"`, `"scanner_name":"nuclei"`} {
				if !strings.Contains(body, plain) {
					t.Fatalf("response lost %s: %s", plain, body)
				}
			}
		})
	}
	// The stored request is never modified by a masked read.
	if q.Definition.ScannerConfig["password"] != redactTestPassword {
		t.Fatal("the stored definition was masked in place")
	}
}
