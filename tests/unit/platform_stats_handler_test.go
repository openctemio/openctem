package unit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock: Agent Repository for PlatformStats tests
// =============================================================================

// mockAgentRepository implements agent.Repository for platform stats handler tests.
type mockAgentRepository struct {
	statsResult *agent.PlatformAgentStatsResult
	statsErr    error
}

func (m *mockAgentRepository) Create(_ context.Context, _ *agent.Agent) error {
	return nil
}
func (m *mockAgentRepository) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAgentRepository) GetByID(_ context.Context, _ shared.ID) (*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) GetByAPIKeyHash(_ context.Context, _ string) (*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) List(_ context.Context, _ agent.Filter, _ pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	return pagination.Result[*agent.Agent]{}, nil
}
func (m *mockAgentRepository) Update(_ context.Context, _ *agent.Agent) error {
	return nil
}
func (m *mockAgentRepository) Delete(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAgentRepository) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAgentRepository) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}
func (m *mockAgentRepository) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *mockAgentRepository) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) ClaimJob(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAgentRepository) ReleaseJob(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAgentRepository) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAgentRepository) MarkStaleAgentsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAgentRepository) GetAgentsOfflineSince(_ context.Context, _ time.Time) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *mockAgentRepository) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *mockAgentRepository) HasAgentForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockAgentRepository) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *mockAgentRepository) HasAgentForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockAgentRepository) GetPlatformAgentStats(_ context.Context, _ shared.ID) (*agent.PlatformAgentStatsResult, error) {
	if m.statsErr != nil {
		return nil, m.statsErr
	}
	return m.statsResult, nil
}

// =============================================================================
// Helper: create handler with mock repository
// =============================================================================

func newPlatformStatsHandler(repo *mockAgentRepository) *handler.PlatformStatsHandler {
	log := logger.NewNop()
	svc := app.NewAgentService(repo, nil, log)
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
	repo := &mockAgentRepository{
		statsResult: &agent.PlatformAgentStatsResult{
			TotalAgents:       5,
			OnlineAgents:      3,
			TotalCapacity:     25,
			CurrentActiveJobs: 8,
			CurrentQueuedJobs: 2,
			TierBreakdown: map[string]agent.TierBreakdown{
				"shared": {
					TotalAgents:   3,
					OnlineAgents:  2,
					TotalCapacity: 15,
					CurrentLoad:   5,
				},
				"dedicated": {
					TotalAgents:   2,
					OnlineAgents:  1,
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

	assert.True(t, resp.Enabled, "enabled should be true when agents exist")
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
	assert.Equal(t, 3, sharedTier.TotalAgents)
	assert.Equal(t, 2, sharedTier.OnlineAgents)
	assert.Equal(t, 1, sharedTier.OfflineAgents, "offline = total - online = 3 - 2")
	assert.Equal(t, 15, sharedTier.TotalCapacity)
	assert.Equal(t, 5, sharedTier.CurrentLoad)
	assert.Equal(t, 10, sharedTier.AvailableSlots, "available = capacity - load = 15 - 5")

	require.Contains(t, resp.TierStats, "dedicated")
	dedicatedTier := resp.TierStats["dedicated"]
	assert.Equal(t, 2, dedicatedTier.TotalAgents)
	assert.Equal(t, 1, dedicatedTier.OnlineAgents)
	assert.Equal(t, 1, dedicatedTier.OfflineAgents)
	assert.Equal(t, 10, dedicatedTier.TotalCapacity)
	assert.Equal(t, 3, dedicatedTier.CurrentLoad)
	assert.Equal(t, 7, dedicatedTier.AvailableSlots)
}

func TestPlatformStatsHandler_GetStats_NoTenantInContext(t *testing.T) {
	repo := &mockAgentRepository{}
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
	repo := &mockAgentRepository{
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

func TestPlatformStatsHandler_GetStats_NoPlatformAgents(t *testing.T) {
	// When no platform agents exist, the service returns Enabled=false
	repo := &mockAgentRepository{
		statsResult: &agent.PlatformAgentStatsResult{
			TotalAgents:   0,
			TierBreakdown: make(map[string]agent.TierBreakdown),
		},
	}
	h := newPlatformStatsHandler(repo)
	tenantID := shared.NewID()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform-stats", nil)
	req = withPlatformTenantContext(req, tenantID)
	rr := httptest.NewRecorder()

	h.GetStats(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "should return 200 even with no agents")

	var resp handler.PlatformStatsResponse
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.False(t, resp.Enabled, "enabled should be false when no agents")
	assert.Equal(t, "shared", resp.MaxTier, "default tier should be shared")
	assert.Equal(t, []string{"shared"}, resp.AccessibleTiers)
	assert.Equal(t, 0, resp.MaxConcurrent)
	assert.Equal(t, 0, resp.MaxQueued)
	assert.Equal(t, 0, resp.CurrentActive)
	assert.Equal(t, 0, resp.CurrentQueued)
	assert.Equal(t, 0, resp.AvailableSlots)
	assert.Empty(t, resp.TierStats, "tier_stats should be empty with no agents")
}
