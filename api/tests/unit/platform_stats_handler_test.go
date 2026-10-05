package unit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock: Sensor Repository for PlatformStats tests
// =============================================================================

// mockSensorRepository implements sensor.Repository for platform stats handler tests.
type mockSensorRepository struct {
	statsResult *sensor.PlatformSensorStatsResult
	statsErr    error
}

func (m *mockSensorRepository) Create(_ context.Context, _ *sensor.Sensor) error {
	return nil
}
func (m *mockSensorRepository) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockSensorRepository) GetByID(_ context.Context, _ shared.ID) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) GetByAPIKeyHash(_ context.Context, _ string) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) List(_ context.Context, _ sensor.Filter, _ pagination.Pagination) (pagination.Result[*sensor.Sensor], error) {
	return pagination.Result[*sensor.Sensor]{}, nil
}
func (m *mockSensorRepository) Update(_ context.Context, _ *sensor.Sensor) error {
	return nil
}
func (m *mockSensorRepository) RetireInlineKey(_ context.Context, _ shared.ID, _ []string, _ time.Time) (bool, error) {
	return false, nil
}
func (m *mockSensorRepository) UpdateHeartbeat(_ context.Context, _ shared.ID, _ sensor.HeartbeatUpdate) (bool, error) {
	return true, nil
}
func (m *mockSensorRepository) UpdateAPIKey(_ context.Context, _ shared.ID, _, _ string, _ *time.Time, _ bool) (bool, error) {
	return true, nil
}
func (m *mockSensorRepository) Delete(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockSensorRepository) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockSensorRepository) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}
func (m *mockSensorRepository) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *mockSensorRepository) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) ClaimJob(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockSensorRepository) ReleaseJob(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockSensorRepository) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockSensorRepository) MarkStaleSensorsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockSensorRepository) GetSensorsOfflineSince(_ context.Context, _ time.Time) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *mockSensorRepository) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *mockSensorRepository) HasSensorForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockSensorRepository) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *mockSensorRepository) HasSensorForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockSensorRepository) GetPlatformSensorStats(_ context.Context, _ shared.ID) (*sensor.PlatformSensorStatsResult, error) {
	if m.statsErr != nil {
		return nil, m.statsErr
	}
	return m.statsResult, nil
}

func (m *mockSensorRepository) GetTenantSensorStats(_ context.Context, _ shared.ID) (*sensor.TenantSensorStats, error) {
	return &sensor.TenantSensorStats{
		ByStatus: make(map[string]int),
		ByHealth: make(map[string]int),
		ByType:   make(map[string]int),
		ByMode:   make(map[string]int),
	}, nil
}

// =============================================================================
// Helper: create handler with mock repository
// =============================================================================

func newPlatformStatsHandler(repo *mockSensorRepository) *handler.PlatformStatsHandler {
	log := logger.NewNop()
	svc := sensorapp.NewSensorService(repo, nil, log)
	return handler.NewPlatformStatsHandler(svc, log)
}

// withPlatformTenantContext adds a tenant_id to the request context, matching
// how the real middleware sets the key. Uses logger.ContextKey("tenant_id")
// which is the same key that middleware.GetTenantIDFromContext reads.
func withPlatformTenantContext(req *http.Request, tenantID shared.ID) *http.Request {
	ctx := context.WithValue(req.Context(), logger.ContextKey("tenant_id"), tenantID.String())
	return req.WithContext(ctx)
}

// =============================================================================
// Tests: PlatformStatsHandler.GetStats
// =============================================================================

func TestPlatformStatsHandler_GetStats_Success(t *testing.T) {
	repo := &mockSensorRepository{
		statsResult: &sensor.PlatformSensorStatsResult{
			TotalSensors:      5,
			OnlineSensors:     3,
			TotalCapacity:     25,
			CurrentActiveJobs: 8,
			CurrentQueuedJobs: 2,
			TierBreakdown: map[string]sensor.TierBreakdown{
				"shared": {
					TotalSensors:  3,
					OnlineSensors: 2,
					TotalCapacity: 15,
					CurrentLoad:   5,
				},
				"dedicated": {
					TotalSensors:  2,
					OnlineSensors: 1,
					TotalCapacity: 10,
					CurrentLoad:   3,
				},
			},
		},
	}
	h := newPlatformStatsHandler(repo)
	tenantID := shared.NewID()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-stats", nil)
	req = withPlatformTenantContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.GetStats(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp handler.PlatformStatsResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err, "response should be valid JSON")

	assert.True(t, resp.Enabled, "enabled should be true when sensors exist")
	assert.Equal(t, "dedicated", resp.MaxTier)
	assert.Contains(t, resp.AccessibleTiers, "shared")
	assert.Contains(t, resp.AccessibleTiers, "dedicated")
	assert.Equal(t, 25, resp.MaxConcurrent)
	assert.Equal(t, 75, resp.MaxQueued, "max_queued should be 3x capacity")
	assert.Equal(t, 8, resp.CurrentActive)
	assert.Equal(t, 2, resp.CurrentQueued)
	assert.Equal(t, 17, resp.AvailableSlots, "available = capacity - active = 25 - 8")

	// Verify tier stats
	require.Contains(t, resp.TierStats, "shared")
	sharedTier := resp.TierStats["shared"]
	assert.Equal(t, 3, sharedTier.TotalSensors)
	assert.Equal(t, 2, sharedTier.OnlineSensors)
	assert.Equal(t, 1, sharedTier.OfflineSensors, "offline = total - online = 3 - 2")
	assert.Equal(t, 15, sharedTier.TotalCapacity)
	assert.Equal(t, 5, sharedTier.CurrentLoad)
	assert.Equal(t, 10, sharedTier.AvailableSlots, "available = capacity - load = 15 - 5")

	require.Contains(t, resp.TierStats, "dedicated")
	dedicatedTier := resp.TierStats["dedicated"]
	assert.Equal(t, 2, dedicatedTier.TotalSensors)
	assert.Equal(t, 1, dedicatedTier.OnlineSensors)
	assert.Equal(t, 1, dedicatedTier.OfflineSensors)
	assert.Equal(t, 10, dedicatedTier.TotalCapacity)
	assert.Equal(t, 3, dedicatedTier.CurrentLoad)
	assert.Equal(t, 7, dedicatedTier.AvailableSlots)
}

func TestPlatformStatsHandler_GetStats_NoTenantInContext(t *testing.T) {
	repo := &mockSensorRepository{}
	h := newPlatformStatsHandler(repo)

	// No tenant context set on the request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-stats", nil)
	rr := httptest.NewRecorder()

	h.GetStats(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "should return 401 when no tenant in context")

	var resp map[string]any
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "tenant context required")
}

func TestPlatformStatsHandler_GetStats_ServiceError(t *testing.T) {
	repo := &mockSensorRepository{
		statsErr: errors.New("database connection lost"),
	}
	h := newPlatformStatsHandler(repo)
	tenantID := shared.NewID()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-stats", nil)
	req = withPlatformTenantContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.GetStats(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code, "should return 500 on service error")
}

func TestPlatformStatsHandler_GetStats_NoPlatformSensors(t *testing.T) {
	// When no platform sensors exist, the service returns Enabled=false
	repo := &mockSensorRepository{
		statsResult: &sensor.PlatformSensorStatsResult{
			TotalSensors:  0,
			TierBreakdown: make(map[string]sensor.TierBreakdown),
		},
	}
	h := newPlatformStatsHandler(repo)
	tenantID := shared.NewID()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-stats", nil)
	req = withPlatformTenantContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.GetStats(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "should return 200 even with no sensors")

	var resp handler.PlatformStatsResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Enabled, "enabled should be false when no sensors")
	assert.Equal(t, "shared", resp.MaxTier, "default tier should be shared")
	assert.Equal(t, []string{"shared"}, resp.AccessibleTiers)
	assert.Equal(t, 0, resp.MaxConcurrent)
	assert.Equal(t, 0, resp.MaxQueued)
	assert.Equal(t, 0, resp.CurrentActive)
	assert.Equal(t, 0, resp.CurrentQueued)
	assert.Equal(t, 0, resp.AvailableSlots)
	assert.Empty(t, resp.TierStats, "tier_stats should be empty with no sensors")
}

func (m *mockSensorRepository) KnownCapabilityNames(_ context.Context, _ *shared.ID, _, _ []string) (map[string]bool, map[string]bool, error) {
	return map[string]bool{}, map[string]bool{}, nil
}
