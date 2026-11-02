package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Stand-ins the metadata never calls.
type (
	metaRepo  struct{ mcpoauth.Repository }
	metaMembs struct{ mcpoauthapp.MembershipChecker }
	metaPerms struct{ mcpoauthapp.HolderPermissions }
)

// The authorization server metadata advertises the device authorization
// endpoint and grant (RFC 8628 §4) next to the browser flow.
func TestServerMetadataAdvertisesDeviceGrant(t *testing.T) {
	e, err := mcpoauth.NewEndpoints("https://openctem.example")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := mcpoauthapp.NewService(mcpoauthapp.Config{
		Repository: metaRepo{}, Members: metaMembs{}, Permissions: metaPerms{}, Endpoints: e, Logger: logger.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := NewMCPOAuthHandler(svc, logger.NewNop())
	rec := httptest.NewRecorder()
	h.ServerMetadata(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	var doc authorizationServerMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.DeviceAuthorizationEndpoint != "https://openctem.example/oauth/device_authorization" ||
		!slices.Contains(doc.GrantTypesSupported, mcpoauth.DeviceGrantType) ||
		!slices.Contains(doc.GrantTypesSupported, "authorization_code") {
		t.Fatalf("metadata %+v", doc)
	}
}

// Terminal sign-in refusals map to stable statuses with fixed text.
func TestConsentErrorDeviceFlow(t *testing.T) {
	h := &MCPOAuthHandler{log: logger.NewNop()}
	for err, want := range map[error]int{
		mcpoauthapp.ErrUserCodeInvalid:    http.StatusNotFound,
		mcpoauthapp.ErrDeviceFlowDisabled: http.StatusForbidden,
		mcpoauthapp.ErrDeviceFullData:     http.StatusForbidden,
	} {
		rec := httptest.NewRecorder()
		h.consentError(rec, err)
		if rec.Code != want || strings.Contains(rec.Body.String(), "%!") {
			t.Errorf("%v: %d %s", err, rec.Code, rec.Body.String())
		}
	}
}
