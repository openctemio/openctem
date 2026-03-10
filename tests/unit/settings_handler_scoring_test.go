package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers for risk scoring handler tests
// =============================================================================

// withTeamContext sets the team ID in context the same way middleware.TenantContext does.
func withTeamContext(req *http.Request, tenantID shared.ID) *http.Request {
	ctx := context.WithValue(req.Context(), middleware.TeamIDKey, tenantID)
	return req.WithContext(ctx)
}

// newTenantHandlerForScoring creates a TenantHandler wired with a mock tenant repo
// containing a tenant with default (legacy) settings.
func newTenantHandlerForScoring(repo *mockTenantRepo) *handler.TenantHandler {
	log := logger.NewNop()
	v := validator.New()
	svc := app.NewTenantService(repo, log)
	return handler.NewTenantHandler(svc, v, log)
}

// createTenantWithSettings creates a tenant with default settings and stores it in the mock repo.
func createTenantWithSettings(repo *mockTenantRepo) (*tenant.Tenant, shared.ID) {
	t, err := tenant.NewTenant("Test Org", "test-org", "user-1")
	if err != nil {
		panic(fmt.Sprintf("failed to create tenant: %v", err))
	}
	// Apply default settings (includes legacy risk scoring)
	defaults := tenant.DefaultSettings()
	_ = t.UpdateSettings(defaults)
	repo.tenants[t.ID().String()] = t
	return t, t.ID()
}

// validLegacySettings returns a valid RiskScoringSettings using the legacy preset.
func validLegacySettings() tenant.RiskScoringSettings {
	return tenant.LegacyRiskScoringSettings()
}

// invalidWeightsSettings returns a RiskScoringSettings with weights that don't sum to 100.
func invalidWeightsSettings() tenant.RiskScoringSettings {
	s := validLegacySettings()
	s.Weights.Exposure = 50
	s.Weights.Criticality = 50
	s.Weights.Findings = 50 // sum = 150
	s.Weights.CTEM = 0
	return s
}

// marshalJSON is a helper to marshal to JSON bytes.
func marshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// =============================================================================
// Mock AssetService wrapper for handler tests
// =============================================================================

// scoringHandlerMockAssetRepo extends MockAssetRepository for handler tests.
type scoringHandlerMockAssetRepo struct {
	MockAssetRepository
}

func (m *scoringHandlerMockAssetRepo) BatchUpdateRiskScores(_ context.Context, _ shared.ID, _ []*asset.Asset) error {
	return nil
}

// =============================================================================
// Tests: GET /settings/risk-scoring
// =============================================================================

func TestRiskScoringHandler_Get_ReturnsCurrentConfig(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring", nil)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.GetRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp tenant.RiskScoringSettings
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err, "response should be valid JSON")

	// Legacy preset should be returned
	assert.Equal(t, "legacy", resp.Preset)
	assert.Equal(t, 100, resp.Weights.Exposure+resp.Weights.Criticality+resp.Weights.Findings+resp.Weights.CTEM)
}

func TestRiskScoringHandler_Get_NoTenantContext_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring", nil)
	// No team context set
	rr := httptest.NewRecorder()

	h.GetRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRiskScoringHandler_Get_TenantNotFound_Returns404(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	// Use a random tenant ID that doesn't exist in repo
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring", nil)
	req = withTeamContext(req, shared.NewID())
	rr := httptest.NewRecorder()

	h.GetRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// =============================================================================
// Tests: PATCH /settings/risk-scoring
// =============================================================================

func TestRiskScoringHandler_Update_ValidConfig(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// Use default preset instead of legacy
	newSettings := tenant.DefaultRiskScoringPreset()
	body := marshalJSON(t, newSettings)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/test-org/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp tenant.RiskScoringSettings
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, newSettings.Preset, resp.Preset)
	assert.Equal(t, newSettings.Weights.Exposure, resp.Weights.Exposure)

	// Verify repo was updated
	assert.Equal(t, 1, repo.updateCalls)
}

func TestRiskScoringHandler_Update_InvalidWeights_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	invalid := invalidWeightsSettings()
	body := marshalJSON(t, invalid)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/test-org/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, 0, repo.updateCalls, "repo should not be called for invalid input")
}

func TestRiskScoringHandler_Update_InvalidJSON_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/test-org/settings/risk-scoring", bytes.NewReader([]byte(`{invalid json`)))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRiskScoringHandler_Update_NoTenantContext_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	body := marshalJSON(t, validLegacySettings())
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/test-org/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRiskScoringHandler_Update_PersistsNewPreset(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// Update to banking preset
	bankingSettings := tenant.AllRiskScoringPresets["banking"]
	body := marshalJSON(t, bankingSettings)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/test-org/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Verify by reading back
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring", nil)
	getReq = withTeamContext(getReq, tenantID)
	getRR := httptest.NewRecorder()

	h.GetRiskScoringSettings(getRR, getReq)
	require.Equal(t, http.StatusOK, getRR.Code)

	var readBack tenant.RiskScoringSettings
	err := json.Unmarshal(getRR.Body.Bytes(), &readBack)
	require.NoError(t, err)
	assert.Equal(t, "banking", readBack.Preset)
}

// =============================================================================
// Tests: POST /settings/risk-scoring/preview
// =============================================================================

func TestRiskScoringHandler_Preview_NoAssetService_Returns500(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)
	// Deliberately NOT setting asset service

	body := marshalJSON(t, validLegacySettings())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-org/settings/risk-scoring/preview", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.PreviewRiskScoringChanges(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRiskScoringHandler_Preview_InvalidConfig_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// Set up a minimal asset service so we get past the nil check
	assetRepo := &scoringHandlerMockAssetRepo{
		MockAssetRepository: MockAssetRepository{assets: make(map[string]*asset.Asset)},
	}
	assetSvc := app.NewAssetService(assetRepo, logger.NewNop())
	h.SetAssetService(assetSvc)

	invalid := invalidWeightsSettings()
	body := marshalJSON(t, invalid)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-org/settings/risk-scoring/preview", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.PreviewRiskScoringChanges(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// =============================================================================
// Tests: POST /settings/risk-scoring/recalculate
// =============================================================================

func TestRiskScoringHandler_Recalculate_NoAssetService_Returns500(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)
	// Deliberately NOT setting asset service

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-org/settings/risk-scoring/recalculate", nil)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.RecalculateRiskScores(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRiskScoringHandler_Recalculate_NoTenantContext_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-org/settings/risk-scoring/recalculate", nil)
	rr := httptest.NewRecorder()

	h.RecalculateRiskScores(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// =============================================================================
// Tests: GET /settings/risk-scoring/presets
// =============================================================================

func TestRiskScoringHandler_GetPresets_ReturnsAllPresets(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring/presets", nil)
	rr := httptest.NewRecorder()

	h.GetRiskScoringPresets(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var presets []struct {
		Name   string                     `json:"name"`
		Config tenant.RiskScoringSettings `json:"config"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &presets)
	require.NoError(t, err, "response should be valid JSON array")

	// Should contain all known presets
	expectedPresets := tenant.AllRiskScoringPresets
	assert.Len(t, presets, len(expectedPresets))

	presetNames := make(map[string]bool, len(presets))
	for _, p := range presets {
		presetNames[p.Name] = true
	}

	for name := range expectedPresets {
		assert.True(t, presetNames[name], "expected preset %q in response", name)
	}
}

func TestRiskScoringHandler_GetPresets_EachPresetIsValid(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring/presets", nil)
	rr := httptest.NewRecorder()

	h.GetRiskScoringPresets(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var presets []struct {
		Name   string                     `json:"name"`
		Config tenant.RiskScoringSettings `json:"config"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &presets)
	require.NoError(t, err)

	for _, p := range presets {
		err := p.Config.Validate()
		assert.NoError(t, err, "preset %q should be valid", p.Name)
	}
}

func TestRiskScoringHandler_GetPresets_ContainsLegacyAndDefault(t *testing.T) {
	repo := newMockTenantRepo()
	h := newTenantHandlerForScoring(repo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-org/settings/risk-scoring/presets", nil)
	rr := httptest.NewRecorder()

	h.GetRiskScoringPresets(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var presets []struct {
		Name   string                     `json:"name"`
		Config tenant.RiskScoringSettings `json:"config"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &presets)
	require.NoError(t, err)

	names := make(map[string]bool, len(presets))
	for _, p := range presets {
		names[p.Name] = true
	}

	assert.True(t, names["legacy"], "should contain legacy preset")
	assert.True(t, names["default"], "should contain default preset")
	assert.True(t, names["banking"], "should contain banking preset")
	assert.True(t, names["healthcare"], "should contain healthcare preset")
	assert.True(t, names["ecommerce"], "should contain ecommerce preset")
	assert.True(t, names["government"], "should contain government preset")
}

// =============================================================================
// Tests: Update → Read roundtrip
// =============================================================================

func TestRiskScoringHandler_UpdateAndRead_AllPresets(t *testing.T) {
	for presetName, presetConfig := range tenant.AllRiskScoringPresets {
		t.Run(presetName, func(t *testing.T) {
			repo := newMockTenantRepo()
			_, tenantID := createTenantWithSettings(repo)
			h := newTenantHandlerForScoring(repo)

			// Update to this preset
			body := marshalJSON(t, presetConfig)
			patchReq := httptest.NewRequest(http.MethodPatch, "/settings/risk-scoring", bytes.NewReader(body))
			patchReq.Header.Set("Content-Type", "application/json")
			patchReq = withTeamContext(patchReq, tenantID)
			patchRR := httptest.NewRecorder()

			h.UpdateRiskScoringSettings(patchRR, patchReq)
			require.Equal(t, http.StatusOK, patchRR.Code, "updating to %s preset should succeed", presetName)

			// Read back
			getReq := httptest.NewRequest(http.MethodGet, "/settings/risk-scoring", nil)
			getReq = withTeamContext(getReq, tenantID)
			getRR := httptest.NewRecorder()

			h.GetRiskScoringSettings(getRR, getReq)
			require.Equal(t, http.StatusOK, getRR.Code)

			var readBack tenant.RiskScoringSettings
			err := json.Unmarshal(getRR.Body.Bytes(), &readBack)
			require.NoError(t, err)

			assert.Equal(t, presetConfig.Preset, readBack.Preset)
			assert.Equal(t, presetConfig.Weights, readBack.Weights)
		})
	}
}

// =============================================================================
// Tests: Validation edge cases
// =============================================================================

func TestRiskScoringHandler_Update_ZeroWeightComponentsAllowed(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// All weight in exposure, zero for others
	s := validLegacySettings()
	s.Preset = "custom"
	s.Weights.Exposure = 100
	s.Weights.Criticality = 0
	s.Weights.Findings = 0
	s.Weights.CTEM = 0
	s.CTEMPoints.Enabled = false
	body := marshalJSON(t, s)

	req := httptest.NewRequest(http.MethodPatch, "/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRiskScoringHandler_Update_ServiceError_Returns500(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// Force repo update to fail
	repo.updateErr = fmt.Errorf("database connection lost")

	body := marshalJSON(t, validLegacySettings())
	req := httptest.NewRequest(http.MethodPatch, "/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestRiskScoringHandler_Update_InvalidRiskLevelOrder_Returns400(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// Risk levels not properly ordered (critical < high)
	s := validLegacySettings()
	s.RiskLevels.CriticalMin = 50
	s.RiskLevels.HighMin = 70 // higher than critical = invalid
	body := marshalJSON(t, s)

	req := httptest.NewRequest(http.MethodPatch, "/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// =============================================================================
// Tests: Timing / concurrent safety (lightweight)
// =============================================================================

func TestRiskScoringHandler_Get_ReturnsFreshDataAfterUpdate(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	// First read — should be legacy
	getReq := httptest.NewRequest(http.MethodGet, "/settings/risk-scoring", nil)
	getReq = withTeamContext(getReq, tenantID)
	getRR := httptest.NewRecorder()
	h.GetRiskScoringSettings(getRR, getReq)
	require.Equal(t, http.StatusOK, getRR.Code)

	var initial tenant.RiskScoringSettings
	_ = json.Unmarshal(getRR.Body.Bytes(), &initial)
	assert.Equal(t, "legacy", initial.Preset)

	// Update to healthcare
	healthcare := tenant.AllRiskScoringPresets["healthcare"]
	body := marshalJSON(t, healthcare)
	patchReq := httptest.NewRequest(http.MethodPatch, "/settings/risk-scoring", bytes.NewReader(body))
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq = withTeamContext(patchReq, tenantID)
	patchRR := httptest.NewRecorder()
	h.UpdateRiskScoringSettings(patchRR, patchReq)
	require.Equal(t, http.StatusOK, patchRR.Code)

	// Second read — should be healthcare now
	getReq2 := httptest.NewRequest(http.MethodGet, "/settings/risk-scoring", nil)
	getReq2 = withTeamContext(getReq2, tenantID)
	getRR2 := httptest.NewRecorder()
	h.GetRiskScoringSettings(getRR2, getReq2)
	require.Equal(t, http.StatusOK, getRR2.Code)

	var updated tenant.RiskScoringSettings
	_ = json.Unmarshal(getRR2.Body.Bytes(), &updated)
	assert.Equal(t, "healthcare", updated.Preset)
}

// Verify that TeamIDKey is the correct context key type.
func TestRiskScoringHandler_TeamIDKey_IsLoggerContextKey(t *testing.T) {
	assert.Equal(t, logger.ContextKey("team_id"), middleware.TeamIDKey)
}
