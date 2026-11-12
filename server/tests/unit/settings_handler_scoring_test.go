package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"

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
	svc := tenantapp.NewTenantService(repo, log)
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

	// The default likelihood-impact preset should be returned
	assert.Equal(t, "default", resp.Preset)
	assert.Equal(t, tenant.ScoreCompositionLikelihoodImpact, resp.ScoreCompositionMode)
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

	var rawResp struct {
		Config    tenant.RiskScoringSettings `json:"config"`
		Recompute string                     `json:"recompute"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &rawResp)
	require.NoError(t, err)

	assert.Equal(t, newSettings.Preset, rawResp.Config.Preset)
	assert.Equal(t, newSettings.Weights.Exposure, rawResp.Config.Weights.Exposure)
	// The recompute runs in the background (the settings trigger queued it).
	assert.Equal(t, "queued", rawResp.Recompute)

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
	assetSvc := assetapp.NewAssetService(assetRepo, logger.NewNop())
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

	// First read — the default preset
	getReq := httptest.NewRequest(http.MethodGet, "/settings/risk-scoring", nil)
	getReq = withTeamContext(getReq, tenantID)
	getRR := httptest.NewRecorder()
	h.GetRiskScoringSettings(getRR, getReq)
	require.Equal(t, http.StatusOK, getRR.Code)

	var initial tenant.RiskScoringSettings
	_ = json.Unmarshal(getRR.Body.Bytes(), &initial)
	assert.Equal(t, "default", initial.Preset)

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

// =============================================================================
// Tests: Preview with wired AssetService
// =============================================================================

func newHandlerWithAssetService(tenantRepo *mockTenantRepo, assetRepo *scoringHandlerMockAssetRepo) *handler.TenantHandler {
	h := newTenantHandlerForScoring(tenantRepo)
	assetSvc := assetapp.NewAssetService(assetRepo, logger.NewNop())
	// Wire a scoring config provider so preview can compute new scores
	legacyCfg := asset.LegacyRiskScoringConfig()
	assetSvc.SetScoringConfigProvider(&mockScoringConfigProvider{config: &legacyCfg})
	assetSvc.SetRiskQueue(&countingRiskQueue{n: int64(len(assetRepo.assets))}, nil)
	h.SetAssetService(assetSvc)
	return h
}

// countingRiskQueue answers EnqueueTenant with a fixed count.
type countingRiskQueue struct {
	asset.RiskQueueRepository
	n int64
}

func (q *countingRiskQueue) EnqueueTenant(context.Context, shared.ID) (int64, error) { return q.n, nil }

func TestRiskScoringHandler_Preview_ReturnsDeltas(t *testing.T) {
	tenantRepo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(tenantRepo)

	assetRepo := &scoringHandlerMockAssetRepo{
		MockAssetRepository: MockAssetRepository{assets: make(map[string]*asset.Asset)},
	}

	// Add some assets
	legacyCfg := asset.LegacyRiskScoringConfig()
	for i := range 3 {
		a, _ := asset.NewAssetWithSubType(fmt.Sprintf("asset-%d", i), asset.AssetTypeApplication, "website", asset.CriticalityCritical)
		_ = a.UpdateExposure(asset.ExposurePublic)
		a.UpdateFindingCount(i * 2)
		a.SetTenantID(tenantID)
		a.CalculateRiskScoreWithConfig(&legacyCfg)
		assetRepo.assets[a.ID().String()] = a
	}

	h := newHandlerWithAssetService(tenantRepo, assetRepo)

	// Preview with a different config
	previewCfg := tenant.DefaultRiskScoringPreset()
	body := marshalJSON(t, previewCfg)

	req := httptest.NewRequest(http.MethodPost, "/settings/risk-scoring/preview", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.PreviewRiskScoringChanges(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		Assets          assetapp.RiskImpact `json:"assets"`
		AffectsPriority bool                `json:"affects_priority"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 3, resp.Assets.TotalAssets, "every asset is scored, not a sample")
	assert.False(t, resp.AffectsPriority, "the ownership floor did not change")
	assert.Equal(t, resp.Assets.Changed, resp.Assets.Raised+resp.Assets.Lowered)
	for _, item := range resp.Assets.TopChanges {
		assert.NotEmpty(t, item.AssetID)
		assert.NotEmpty(t, item.AssetName)
		assert.NotEqual(t, item.CurrentScore, item.NewScore, "only changed assets are listed")
		assert.NotEmpty(t, item.NewLevel)
	}
}

// =============================================================================
// Tests: Recalculate with wired AssetService
// =============================================================================

func TestRiskScoringHandler_Recalculate_QueuesEveryAsset(t *testing.T) {
	tenantRepo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(tenantRepo)

	assetRepo := &scoringHandlerMockAssetRepo{
		MockAssetRepository: MockAssetRepository{assets: make(map[string]*asset.Asset)},
	}

	// Add assets
	for i := range 5 {
		a, _ := asset.NewAssetWithSubType(fmt.Sprintf("recalc-asset-%d", i), asset.AssetTypeApplication, "website", asset.CriticalityHigh)
		_ = a.UpdateExposure(asset.ExposurePublic)
		a.UpdateFindingCount(i)
		a.SetTenantID(tenantID)
		assetRepo.assets[a.ID().String()] = a
	}

	h := newHandlerWithAssetService(tenantRepo, assetRepo)

	req := httptest.NewRequest(http.MethodPost, "/settings/risk-scoring/recalculate", nil)
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.RecalculateRiskScores(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp struct {
		AssetsQueued int `json:"assets_queued"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, 5, resp.AssetsQueued)
}

// =============================================================================
// Tests: Update invalidates cache
// =============================================================================

func TestRiskScoringHandler_Update_InvalidatesScoringCache(t *testing.T) {
	tenantRepo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(tenantRepo)

	assetRepo := &scoringHandlerMockAssetRepo{
		MockAssetRepository: MockAssetRepository{assets: make(map[string]*asset.Asset)},
	}

	h := newHandlerWithAssetService(tenantRepo, assetRepo)

	// Update scoring settings
	newSettings := tenant.DefaultRiskScoringPreset()
	body := marshalJSON(t, newSettings)

	req := httptest.NewRequest(http.MethodPatch, "/settings/risk-scoring", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.UpdateRiskScoringSettings(rr, req)

	// Should succeed — the cache invalidation happens internally
	assert.Equal(t, http.StatusOK, rr.Code)

	// Verify that a subsequent preview uses the new settings
	// (cache was invalidated, so provider will be called again)
	previewBody := marshalJSON(t, newSettings)
	previewReq := httptest.NewRequest(http.MethodPost, "/settings/risk-scoring/preview", bytes.NewReader(previewBody))
	previewReq.Header.Set("Content-Type", "application/json")
	previewReq = withTeamContext(previewReq, tenantID)
	previewRR := httptest.NewRecorder()

	h.PreviewRiskScoringChanges(previewRR, previewReq)
	assert.Equal(t, http.StatusOK, previewRR.Code)
}

// The preview is a whole-organization dry run: six per minute per tenant,
// then 429 with Retry-After; another tenant has its own budget.
func TestRiskScoringHandler_Preview_RateLimitedPerTenant(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantA := createTenantWithSettings(repo)
	h := newTenantHandlerForScoring(repo)

	call := func(tid shared.ID) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/test-org/settings/risk-scoring/preview",
			bytes.NewReader(marshalJSON(t, validLegacySettings())))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.PreviewRiskScoringChanges(rr, withTeamContext(req, tid))
		return rr
	}
	for i := range 6 {
		rr := call(tenantA)
		require.NotEqual(t, http.StatusTooManyRequests, rr.Code, "call %d was limited", i+1)
	}
	rr := call(tenantA)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("Retry-After"))

	// Another tenant is not affected by tenant A's use.
	tenantB := shared.NewID()
	assert.NotEqual(t, http.StatusTooManyRequests, call(tenantB).Code)
}

// =============================================================================
// Tests: a PATCH merges into the stored settings and refuses unsafe maps
// =============================================================================

func patchRiskScoring(t *testing.T, h *handler.TenantHandler, tenantID shared.ID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/test-org/settings/risk-scoring", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()
	h.UpdateRiskScoringSettings(rr, req)
	return rr
}

func storedRiskScoring(t *testing.T, repo *mockTenantRepo, tenantID shared.ID) tenant.RiskScoringSettings {
	t.Helper()
	return repo.tenants[tenantID.String()].TypedSettings().RiskScoring
}

// Omitting a block keeps the stored block. A body with only the finding
// impact used to decode exposure_scores and criticality_scores to zero, so
// every asset then scored 0.
func TestRiskScoringHandler_Update_OmittedBlocksKeepStoredValues(t *testing.T) {
	for name, body := range map[string]string{
		"only the ownership floor":   `{"floor_unowned_at_p2":true}`,
		"only the risk levels":       `{"risk_levels":{"critical_min":90,"high_min":70,"medium_min":50,"low_min":30}}`,
		"one field of one block":     `{"exposure_scores":{"isolated":20}}`,
		"empty body (nothing to do)": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			repo := newMockTenantRepo()
			_, tenantID := createTenantWithSettings(repo)
			h := newTenantHandlerForScoring(repo)
			before := storedRiskScoring(t, repo, tenantID)

			rr := patchRiskScoring(t, h, tenantID, body)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			after := storedRiskScoring(t, repo, tenantID)
			assert.Equal(t, before.Weights, after.Weights)
			assert.Equal(t, before.CriticalityScores, after.CriticalityScores)
			assert.Equal(t, before.ExposureMultipliers, after.ExposureMultipliers)
			assert.Equal(t, before.FindingImpact, after.FindingImpact)
			assert.NotZero(t, after.ExposureScores.Public, "an omitted exposure block must not be zeroed")
			assert.NotZero(t, after.CriticalityScores.Critical)
			if name == "one field of one block" {
				want := before.ExposureScores
				want.Isolated = 20
				assert.Equal(t, want, after.ExposureScores, "only the named field changes")
			}
		})
	}
}

func TestRiskScoringHandler_Update_UnsafeMapsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"all-zero exposure scores":     `{"exposure_scores":{"public":0,"restricted":0,"private":0,"isolated":0,"unknown":0}}`,
		"inverted exposure scores":     `{"exposure_scores":{"public":20,"restricted":50,"private":70,"isolated":90,"unknown":50}}`,
		"exposure score below minimum": `{"exposure_scores":{"isolated":5}}`,
		"all-zero criticality scores":  `{"criticality_scores":{"critical":0,"high":0,"medium":0,"low":0,"none":0}}`,
		"inverted criticality scores":  `{"criticality_scores":{"critical":10,"high":40,"medium":60,"low":80,"none":0}}`,
		"criticality score below min":  `{"criticality_scores":{"low":3}}`,
		"unordered risk levels":        `{"risk_levels":{"critical_min":30,"high_min":60,"medium_min":40,"low_min":20}}`,
		"weights that do not sum":      `{"weights":{"exposure":10,"criticality":10,"findings":10,"ctem":10}}`,
		"negative score":               `{"exposure_scores":{"public":-5}}`,
		"wrong type":                   `{"exposure_scores":"high"}`,
		"unknown composition mode":     `{"score_composition_mode":"bogus"}`,
	} {
		t.Run(name, func(t *testing.T) {
			repo := newMockTenantRepo()
			_, tenantID := createTenantWithSettings(repo)
			h := newTenantHandlerForScoring(repo)
			before := storedRiskScoring(t, repo, tenantID)

			rr := patchRiskScoring(t, h, tenantID, body)
			assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, 0, repo.updateCalls, "nothing is saved")
			assert.Equal(t, before, storedRiskScoring(t, repo, tenantID))
		})
	}
}

// Every shipped preset, and the defaults, pass the stricter save rules, so
// applying a preset keeps working.
func TestRiskScoringSettings_PresetsPassValidateForSave(t *testing.T) {
	for name, p := range tenant.AllRiskScoringPresets {
		p := p
		assert.NoError(t, p.ValidateForSave(), name)
	}
	d := tenant.DefaultSettings().RiskScoring
	assert.NoError(t, d.ValidateForSave(), "defaults")
}

// Saving another section of the settings never trips over a stored risk map
// that predates the save rules (Validate stays the lenient check).
func TestRiskScoringSettings_StoredLegacyValuesDoNotBlockOtherSaves(t *testing.T) {
	zeroed := tenant.DefaultSettings()
	zeroed.RiskScoring.ExposureScores = tenant.ExposureScoreConfig{}
	assert.NoError(t, zeroed.RiskScoring.Validate())
	assert.Error(t, zeroed.RiskScoring.ValidateForSave())
}

// The preview reads the body like the save: omitted blocks keep the stored value.
func TestRiskScoringHandler_Preview_OmittedBlocksKeepStoredValues(t *testing.T) {
	repo := newMockTenantRepo()
	_, tenantID := createTenantWithSettings(repo)
	assetRepo := &scoringHandlerMockAssetRepo{MockAssetRepository: MockAssetRepository{assets: make(map[string]*asset.Asset)}}
	h := newHandlerWithAssetService(repo, assetRepo)

	req := httptest.NewRequest(http.MethodPost, "/settings/risk-scoring/preview", bytes.NewReader([]byte(`{"floor_unowned_at_p2":false}`)))
	req = withTeamContext(req, tenantID)
	rr := httptest.NewRecorder()
	h.PreviewRiskScoringChanges(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	bad := httptest.NewRequest(http.MethodPost, "/settings/risk-scoring/preview",
		bytes.NewReader([]byte(`{"exposure_scores":{"public":0,"restricted":0,"private":0,"isolated":0,"unknown":0}}`)))
	bad = withTeamContext(bad, tenantID)
	rr = httptest.NewRecorder()
	h.PreviewRiskScoringChanges(rr, bad)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
