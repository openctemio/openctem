package unit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Handler tests for RFC-003 Phase 1a asset-source settings endpoints.
// Uses the same mock tenant repo + helpers that the risk scoring
// handler tests rely on (see settings_handler_scoring_test.go).

func newSourceID(t *testing.T) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(uuid.New().String())
	require.NoError(t, err)
	return id
}

// =============================================================================
// GET /settings/asset-source
// =============================================================================

func TestAssetSourceHandler_Get_DefaultIsDisabled(t *testing.T) {
	// Fresh tenant with default settings — feature is not enabled,
	// and the endpoint returns a zero-value payload without error.
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/asset-source", nil)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.GetAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp tenant.AssetSourceSettings
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.False(t, resp.IsEnabled())
	assert.Empty(t, resp.Priority)
	assert.Empty(t, resp.TrustLevels)
	assert.False(t, resp.TrackFieldAttribution)
}

func TestAssetSourceHandler_Get_NoTenantContext_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/asset-source", nil)
	rr := httptest.NewRecorder()

	h.GetAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// =============================================================================
// PUT /settings/asset-source
// =============================================================================

func TestAssetSourceHandler_Put_HappyPath(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	sourceID := newSourceID(t)
	payload := tenant.AssetSourceSettings{
		Priority:              []shared.ID{sourceID},
		TrustLevels:           map[string]tenant.TrustLevel{sourceID.String(): tenant.TrustLevelPrimary},
		TrackFieldAttribution: true,
	}

	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader(marshalJSON(t, payload)),
	)
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "response body: %s", rr.Body.String())

	var resp tenant.AssetSourceSettings
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.IsEnabled())
	require.Len(t, resp.Priority, 1)
	assert.Equal(t, sourceID, resp.Priority[0])
	assert.Equal(t, tenant.TrustLevelPrimary, resp.TrustLevels[sourceID.String()])
	assert.True(t, resp.TrackFieldAttribution)
}

func TestAssetSourceHandler_Put_RoundTripThroughGet(t *testing.T) {
	// Verifies the PUT persisted through to subsequent GETs.
	// Catches serialization or map-key drift regressions.
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	sourceID := newSourceID(t)
	payload := tenant.AssetSourceSettings{
		Priority: []shared.ID{sourceID},
	}

	putReq := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader(marshalJSON(t, payload)),
	)
	putReq = withTeamContext(putReq, tenantID)
	h.UpdateAssetSourceSettings(httptest.NewRecorder(), putReq)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/asset-source", nil)
	getReq = withTeamContext(getReq, tenantID)
	getRR := httptest.NewRecorder()
	h.GetAssetSourceSettings(getRR, getReq)

	assert.Equal(t, http.StatusOK, getRR.Code)

	var resp tenant.AssetSourceSettings
	require.NoError(t, json.Unmarshal(getRR.Body.Bytes(), &resp))
	require.Len(t, resp.Priority, 1)
	assert.Equal(t, sourceID, resp.Priority[0])
}

func TestAssetSourceHandler_Put_RejectsUnknownFields(t *testing.T) {
	// Typos like "trust_level" (singular) must be rejected so the
	// admin sees a 400 instead of silently having their request
	// no-op.
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	body := []byte(`{"priority":[],"trust_level":{}}`) // note: singular key
	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader(body),
	)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code, "body: %s", rr.Body.String())
}

func TestAssetSourceHandler_Put_RejectsDuplicatePriority(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	dup := newSourceID(t)
	payload := tenant.AssetSourceSettings{Priority: []shared.ID{dup, dup}}

	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader(marshalJSON(t, payload)),
	)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	// Response must NOT echo the duplicate UUID.
	assert.NotContains(t, rr.Body.String(), dup.String())
}

func TestAssetSourceHandler_Put_RejectsOversizePriority(t *testing.T) {
	// Size-bound guard. We submit one beyond the limit and expect
	// 400. Builds the payload as raw JSON to avoid O(n) allocation
	// of shared.ID values.
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	var buf strings.Builder
	buf.WriteString(`{"priority":[`)
	for i := 0; i <= tenant.MaxAssetSourcePriorityLen; i++ {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(`"`)
		buf.WriteString(uuid.New().String())
		buf.WriteString(`"`)
	}
	buf.WriteString(`]}`)

	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader([]byte(buf.String())),
	)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAssetSourceHandler_Put_NoTenantContext_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	payload := tenant.AssetSourceSettings{}
	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader(marshalJSON(t, payload)),
	)
	rr := httptest.NewRecorder()

	h.UpdateAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAssetSourceHandler_Put_InvalidJSONBody_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader([]byte(`{not json`)),
	)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateAssetSourceSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAssetSourceHandler_Put_EmptyBodyDisablesFeature(t *testing.T) {
	// Operators clear priority to return to last-write-wins. The
	// endpoint must accept an empty/zero-value payload and persist
	// it — this is the documented rollback path.
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// First set some priority.
	seed := tenant.AssetSourceSettings{Priority: []shared.ID{newSourceID(t)}}
	putReq := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader(marshalJSON(t, seed)),
	)
	putReq = withTeamContext(putReq, tenantID)
	h.UpdateAssetSourceSettings(httptest.NewRecorder(), putReq)

	// Now PUT an empty payload.
	clearReq := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tenants/test-org/settings/asset-source",
		bytes.NewReader([]byte(`{}`)),
	)
	clearReq = withTeamContext(clearReq, tenantID)
	clearRR := httptest.NewRecorder()
	h.UpdateAssetSourceSettings(clearRR, clearReq)
	require.Equal(t, http.StatusOK, clearRR.Code)

	// Confirm via GET.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/asset-source", nil)
	getReq = withTeamContext(getReq, tenantID)
	getRR := httptest.NewRecorder()
	h.GetAssetSourceSettings(getRR, getReq)

	var resp tenant.AssetSourceSettings
	require.NoError(t, json.Unmarshal(getRR.Body.Bytes(), &resp))
	assert.False(t, resp.IsEnabled(), "cleared settings should disable the feature")
}
