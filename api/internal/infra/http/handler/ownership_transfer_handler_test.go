package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestOwnershipTransferErrorCodes(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{tenant.ErrOwnershipTransferNotOwner, "OWNERSHIP_NOT_OWNER", http.StatusForbidden},
		{tenant.ErrOwnershipTargetNoMFA, "OWNERSHIP_TARGET_NEEDS_MFA", http.StatusBadRequest},
		{tenant.ErrOwnershipTargetManaged, "OWNERSHIP_TARGET_MANAGED", http.StatusBadRequest},
		{tenant.ErrOwnershipTargetNeedsInternal, "OWNERSHIP_TARGET_NEEDS_CONFIRMATION", http.StatusBadRequest},
		{fmt.Errorf("wrapped: %w", tenant.ErrOwnershipTransferPending), "OWNERSHIP_TRANSFER_PENDING", http.StatusConflict},
		{tenant.ErrOwnershipTransferExpired, "OWNERSHIP_TRANSFER_EXPIRED", http.StatusGone},
		{tenant.ErrOwnershipTransferNotFound, "OWNERSHIP_TRANSFER_NOT_FOUND", http.StatusNotFound},
	} {
		code, status, ok := ownershipTransferErrorCode(tc.err)
		if !ok || code != tc.code || status != tc.status {
			t.Errorf("%v: got %s %d %v", tc.err, code, status, ok)
		}
	}
	rec := httptest.NewRecorder()
	(&TenantHandler{}).writeOwnershipError(rec, tenant.ErrOwnershipTargetNoMFA)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"the new owner must turn on two-factor authentication first"`) {
		t.Fatalf("body = %d %s", rec.Code, rec.Body.String())
	}
}
