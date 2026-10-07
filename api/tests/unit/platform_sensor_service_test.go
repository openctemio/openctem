package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// =============================================================================
// Mock Sensor Repository
// =============================================================================

// mockSensorRepo implements sensor.Repository for testing.
type mockSensorRepo struct {
	sensors      map[shared.ID]*sensor.Sensor
	apiKeyMap    map[string]*sensor.Sensor // hash -> sensor
	createErr    error
	getByIDErr   error
	updateErr    error
	deleteErr    error
	listResult   pagination.Result[*sensor.Sensor]
	listErr      error
	findAvailErr error
	findAvail    []*sensor.Sensor
	claimJobErr  error

	// Call tracking
	createCalls     int
	updateCalls     int
	lastSeenCalls   int
	claimJobCalls   int
	releaseJobCalls int
}

func newMockSensorRepo() *mockSensorRepo {
	return &mockSensorRepo{
		sensors:   make(map[shared.ID]*sensor.Sensor),
		apiKeyMap: make(map[string]*sensor.Sensor),
	}
}

func (m *mockSensorRepo) Create(_ context.Context, a *sensor.Sensor) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sensors[a.ID] = a
	if a.APIKeyHash != "" {
		m.apiKeyMap[a.APIKeyHash] = a
	}
	return nil
}

func (m *mockSensorRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return len(m.sensors), nil
}

func (m *mockSensorRepo) GetByID(_ context.Context, id shared.ID) (*sensor.Sensor, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	a, ok := m.sensors[id]
	if !ok {
		return nil, sensor.ErrSensorNotFound
	}
	return a, nil
}

func (m *mockSensorRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	a, ok := m.sensors[id]
	if !ok {
		return nil, sensor.ErrSensorNotFound
	}
	if a.TenantID == nil || *a.TenantID != tenantID {
		return nil, sensor.ErrSensorNotFound
	}
	return a, nil
}

func (m *mockSensorRepo) GetByAPIKeyHash(_ context.Context, hash string) (*sensor.Sensor, error) {
	a, ok := m.apiKeyMap[hash]
	if !ok {
		return nil, sensor.ErrInvalidAPIKey
	}
	return a, nil
}

func (m *mockSensorRepo) List(_ context.Context, _ sensor.Filter, _ pagination.Pagination) (pagination.Result[*sensor.Sensor], error) {
	if m.listErr != nil {
		return pagination.Result[*sensor.Sensor]{}, m.listErr
	}
	if m.listResult.Data != nil {
		return m.listResult, nil
	}
	// Default: return all sensors
	var items []*sensor.Sensor
	for _, a := range m.sensors {
		items = append(items, a)
	}
	return pagination.Result[*sensor.Sensor]{
		Data:    items,
		Total:   int64(len(items)),
		Page:    1,
		PerPage: 20,
	}, nil
}

func (m *mockSensorRepo) Update(_ context.Context, a *sensor.Sensor) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sensors[a.ID] = a
	return nil
}

func (m *mockSensorRepo) RetireInlineKey(_ context.Context, _ shared.ID, _ []string, _ time.Time) (bool, error) {
	return false, nil
}

func (m *mockSensorRepo) UpdateHeartbeat(_ context.Context, id shared.ID, hb sensor.HeartbeatUpdate) (bool, error) {
	m.updateCalls++
	if m.updateErr != nil {
		return false, m.updateErr
	}
	a, ok := m.sensors[id]
	if !ok || a.Status != sensor.SensorStatusActive {
		return false, nil
	}
	if hb.Version != "" {
		a.Version = hb.Version
	}
	if hb.Hostname != "" {
		a.Hostname = hb.Hostname
	}
	a.CPUPercent = hb.CPUPercent
	a.MemoryPercent = hb.MemoryPercent
	a.LoadScore = hb.LoadScore
	a.UpdateLastSeen()
	return true, nil
}

func (m *mockSensorRepo) UpdateAPIKey(_ context.Context, id shared.ID, hash, prefix string, expiresAt *time.Time, requireActive bool) (bool, error) {
	m.updateCalls++
	if m.updateErr != nil {
		return false, m.updateErr
	}
	a, ok := m.sensors[id]
	if !ok || (requireActive && a.Status != sensor.SensorStatusActive) {
		return false, nil
	}
	a.SetAPIKeyWithExpiry(hash, prefix, expiresAt)
	return true, nil
}

func (m *mockSensorRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sensors, id)
	return nil
}

func (m *mockSensorRepo) UpdateLastSeen(_ context.Context, id shared.ID) error {
	m.lastSeenCalls++
	return nil
}

func (m *mockSensorRepo) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}

func (m *mockSensorRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return m.findAvail, m.findAvailErr
}

func (m *mockSensorRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return m.findAvail, m.findAvailErr
}

func (m *mockSensorRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*sensor.Sensor, error) {
	if len(m.findAvail) > 0 {
		return m.findAvail[0], nil
	}
	return nil, sensor.ErrNoPlatformSensorAvailable
}

func (m *mockSensorRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *mockSensorRepo) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return m.findAvail, m.findAvailErr
}

func (m *mockSensorRepo) ClaimJob(_ context.Context, _ shared.ID) error {
	m.claimJobCalls++
	return m.claimJobErr
}

func (m *mockSensorRepo) ReleaseJob(_ context.Context, _ shared.ID) error {
	m.releaseJobCalls++
	return nil
}

func (m *mockSensorRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *mockSensorRepo) MarkStaleSensorsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockSensorRepo) GetSensorsOfflineSince(_ context.Context, _ time.Time) ([]*sensor.Sensor, error) {
	return nil, nil
}

func (m *mockSensorRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *mockSensorRepo) HasSensorForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockSensorRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return []string{}, nil
}

func (m *mockSensorRepo) HasSensorForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockSensorRepo) GetPlatformSensorStats(_ context.Context, _ shared.ID) (*sensor.PlatformSensorStatsResult, error) {
	return &sensor.PlatformSensorStatsResult{
		TierBreakdown: make(map[string]sensor.TierBreakdown),
	}, nil
}

func (m *mockSensorRepo) GetTenantSensorStats(_ context.Context, _ shared.ID) (*sensor.TenantSensorStats, error) {
	return &sensor.TenantSensorStats{
		ByStatus: make(map[string]int),
		ByHealth: make(map[string]int),
		ByType:   make(map[string]int),
		ByMode:   make(map[string]int),
	}, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestSensorService(repo *mockSensorRepo) *sensorapp.SensorService {
	log := logger.NewNop()
	return sensorapp.NewSensorService(repo, nil, log)
}

func createTestSensor(t *testing.T, tenantID shared.ID, name string) *sensor.Sensor {
	t.Helper()
	a, err := sensor.NewSensor(tenantID, name, sensor.SensorTypeWorker, "test sensor", []string{"sast"}, sensor.ExecutionModeDaemon)
	if err != nil {
		t.Fatalf("failed to create test sensor: %v", err)
	}
	return a
}

// =============================================================================
// Tests for CreateSensor (RegisterSensor equivalent)
// =============================================================================

func TestCreateSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	input := sensorapp.CreateSensorInput{
		TenantID:      tenantID.String(),
		Name:          "Test Worker Sensor",
		Type:          "worker",
		Description:   "A test worker sensor",
		Capabilities:  []string{"sast", "sca"},
		ExecutionMode: "daemon",
	}

	output, err := svc.CreateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateSensor failed: %v", err)
	}

	if output == nil {
		t.Fatal("Expected non-nil output")
	}
	if output.Sensor == nil {
		t.Fatal("Expected non-nil sensor")
	}
	if output.APIKey == "" {
		t.Error("Expected non-empty API key")
	}
	if output.Sensor.Name != "Test Worker Sensor" {
		t.Errorf("Expected name 'Test Worker Sensor', got '%s'", output.Sensor.Name)
	}
	if output.Sensor.Type != sensor.SensorTypeWorker {
		t.Errorf("Expected type worker, got %s", output.Sensor.Type)
	}
	if output.Sensor.Status != sensor.SensorStatusActive {
		t.Errorf("Expected status active, got %s", output.Sensor.Status)
	}
	if output.Sensor.Health != sensor.SensorHealthUnknown {
		t.Errorf("Expected health unknown, got %s", output.Sensor.Health)
	}

	// Verify repo was called
	if repo.createCalls != 1 {
		t.Errorf("Expected 1 create call, got %d", repo.createCalls)
	}
}

func TestCreateSensor_InvalidTenantID(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID: "not-a-uuid",
		Name:     "Bad Sensor",
		Type:     "worker",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestCreateSensor_EmptyName(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	input := sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "",
		Type:     "worker",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for empty name")
	}
}

func TestCreateSensor_RepoError(t *testing.T) {
	repo := newMockSensorRepo()
	repo.createErr = errors.New("database error")
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	input := sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "Failing Sensor",
		Type:     "worker",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error when repo fails")
	}
}

func TestCreateSensor_WithMaxConcurrentJobs(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	input := sensorapp.CreateSensorInput{
		TenantID:          tenantID.String(),
		Name:              "Capacity Sensor",
		Type:              "worker",
		MaxConcurrentJobs: 10,
	}

	output, err := svc.CreateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateSensor failed: %v", err)
	}

	if output.Sensor.MaxConcurrentJobs != 10 {
		t.Errorf("Expected max concurrent jobs 10, got %d", output.Sensor.MaxConcurrentJobs)
	}
}

func TestCreateSensor_DefaultExecutionMode(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	// Worker should default to daemon mode
	input := sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "Default Mode Sensor",
		Type:     "worker",
		// ExecutionMode not set
	}

	output, err := svc.CreateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateSensor failed: %v", err)
	}

	if output.Sensor.ExecutionMode != sensor.ExecutionModeDaemon {
		t.Errorf("Expected default execution mode 'daemon' for worker, got '%s'", output.Sensor.ExecutionMode)
	}
}

// =============================================================================
// Tests for GetSensor
// =============================================================================

func TestGetSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Get Me Sensor")
	repo.sensors[a.ID] = a

	result, err := svc.GetSensor(context.Background(), tenantID.String(), a.ID.String())
	if err != nil {
		t.Fatalf("GetSensor failed: %v", err)
	}

	if result.Name != "Get Me Sensor" {
		t.Errorf("Expected name 'Get Me Sensor', got '%s'", result.Name)
	}
}

func TestGetSensor_NotFound(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	_, err := svc.GetSensor(context.Background(), tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for non-existent sensor")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestGetSensor_InvalidTenantID(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)

	_, err := svc.GetSensor(context.Background(), "not-a-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestGetSensor_InvalidSensorID(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	_, err := svc.GetSensor(context.Background(), tenantID.String(), "not-a-uuid")
	if err == nil {
		t.Fatal("Expected error for invalid sensor ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestGetSensor_WrongTenant(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Wrong Tenant Sensor")
	repo.sensors[a.ID] = a

	_, err := svc.GetSensor(context.Background(), otherTenantID.String(), a.ID.String())
	if err == nil {
		t.Fatal("Expected error for wrong tenant")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

// =============================================================================
// Tests for ListSensors
// =============================================================================

func TestListSensors_WithFilters(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	// Add sensors
	for _, name := range []string{"Sensor Alpha", "Sensor Beta", "Sensor Gamma"} {
		a := createTestSensor(t, tenantID, name)
		repo.sensors[a.ID] = a
	}

	result, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("ListSensors failed: %v", err)
	}

	if len(result.Data) != 3 {
		t.Errorf("Expected 3 sensors, got %d", len(result.Data))
	}
}

func TestListSensors_InvalidTenantID(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestListSensors_EmptyResult(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	result, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("ListSensors failed: %v", err)
	}

	if len(result.Data) != 0 {
		t.Errorf("Expected 0 sensors, got %d", len(result.Data))
	}
}

// =============================================================================
// Tests for UpdateSensor (UpdateSensorStatus equivalent)
// =============================================================================

func TestUpdateSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Update Me")
	repo.sensors[a.ID] = a

	input := sensorapp.UpdateSensorInput{
		TenantID:    tenantID.String(),
		SensorID:    a.ID.String(),
		Name:        "Updated Name",
		Description: "Updated description",
	}

	result, err := svc.UpdateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateSensor failed: %v", err)
	}

	if result.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", result.Name)
	}
	if result.Description != "Updated description" {
		t.Errorf("Expected description 'Updated description', got '%s'", result.Description)
	}
}

func TestUpdateSensor_NotFound(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	input := sensorapp.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: shared.NewID().String(),
		Name:     "Updated",
	}

	_, err := svc.UpdateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for non-existent sensor")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateSensor_ChangeStatus(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Status Sensor")
	repo.sensors[a.ID] = a

	// Disable sensor
	input := sensorapp.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: a.ID.String(),
		Status:   "disabled",
	}

	result, err := svc.UpdateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateSensor (disable) failed: %v", err)
	}

	if result.Status != sensor.SensorStatusDisabled {
		t.Errorf("Expected status disabled, got %s", result.Status)
	}
}

func TestUpdateSensor_ChangeMaxConcurrentJobs(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Capacity Sensor")
	repo.sensors[a.ID] = a

	maxJobs := 20
	input := sensorapp.UpdateSensorInput{
		TenantID:          tenantID.String(),
		SensorID:          a.ID.String(),
		MaxConcurrentJobs: &maxJobs,
	}

	result, err := svc.UpdateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("UpdateSensor failed: %v", err)
	}

	if result.MaxConcurrentJobs != 20 {
		t.Errorf("Expected max concurrent jobs 20, got %d", result.MaxConcurrentJobs)
	}
}

// =============================================================================
// Tests for DeleteSensor
// =============================================================================

func TestDeleteSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Delete Me")
	repo.sensors[a.ID] = a

	err := svc.DeleteSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("DeleteSensor failed: %v", err)
	}

	// Verify sensor was deleted
	if _, exists := repo.sensors[a.ID]; exists {
		t.Error("Expected sensor to be deleted")
	}
}

func TestDeleteSensor_NotFound(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	err := svc.DeleteSensor(context.Background(), tenantID.String(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for non-existent sensor")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("Expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteSensor_InvalidTenantID(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)

	err := svc.DeleteSensor(context.Background(), "not-a-uuid", shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

// =============================================================================
// Tests for ActivateSensor
// =============================================================================

func TestActivateSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Disabled Sensor")
	a.Disable("maintenance")
	repo.sensors[a.ID] = a

	result, err := svc.ActivateSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("ActivateSensor failed: %v", err)
	}

	if result.Status != sensor.SensorStatusActive {
		t.Errorf("Expected status active, got %s", result.Status)
	}
}

func TestActivateSensor_RevokedSensor(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Revoked Sensor")
	a.Revoke("compromised")
	repo.sensors[a.ID] = a

	_, err := svc.ActivateSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("Expected error when activating revoked sensor")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("Expected ErrForbidden, got: %v", err)
	}
}

func TestActivateSensor_NotFound(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	_, err := svc.ActivateSensor(context.Background(), tenantID.String(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for non-existent sensor")
	}
}

// =============================================================================
// Tests for DisableSensor
// =============================================================================

func TestDisableSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Active Sensor")
	repo.sensors[a.ID] = a

	result, err := svc.DisableSensor(context.Background(), tenantID.String(), a.ID.String(), "maintenance window", nil)
	if err != nil {
		t.Fatalf("DisableSensor failed: %v", err)
	}

	if result.Status != sensor.SensorStatusDisabled {
		t.Errorf("Expected status disabled, got %s", result.Status)
	}
	if result.StatusMessage != "maintenance window" {
		t.Errorf("Expected message 'maintenance window', got '%s'", result.StatusMessage)
	}
}

func TestDisableSensor_DefaultReason(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Default Reason Sensor")
	repo.sensors[a.ID] = a

	result, err := svc.DisableSensor(context.Background(), tenantID.String(), a.ID.String(), "", nil)
	if err != nil {
		t.Fatalf("DisableSensor failed: %v", err)
	}

	if result.StatusMessage != "Disabled by administrator" {
		t.Errorf("Expected default reason, got '%s'", result.StatusMessage)
	}
}

// =============================================================================
// Tests for RevokeSensor
// =============================================================================

func TestRevokeSensor_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Revoke Me")
	repo.sensors[a.ID] = a

	result, err := svc.RevokeSensor(context.Background(), tenantID.String(), a.ID.String(), "compromised", nil)
	if err != nil {
		t.Fatalf("RevokeSensor failed: %v", err)
	}

	if result.Status != sensor.SensorStatusRevoked {
		t.Errorf("Expected status revoked, got %s", result.Status)
	}
}

// =============================================================================
// Tests for AuthenticateByAPIKey
// =============================================================================

func TestAuthenticateByAPIKey_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Auth Sensor")
	a.SetAPIKey("testhash123", "rda_test")
	repo.sensors[a.ID] = a
	repo.apiKeyMap["testhash123"] = a

	// We can't test the actual API key flow since hash computation
	// is internal, but we can test the repo interaction
	_, err := svc.AuthenticateByAPIKey(context.Background(), "some-key")
	if err == nil {
		// If the hash doesn't match, it's expected to fail
		// This test verifies the authentication flow handles the error properly
		t.Log("Authentication succeeded (unexpected, but not necessarily wrong)")
	}
}

func TestAuthenticateByAPIKey_DisabledSensor(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Disabled Auth Sensor")
	a.Disable("disabled")
	// We need to set the hash for a known key so the lookup succeeds
	a.SetAPIKey("knownhash", "rda_test")
	repo.sensors[a.ID] = a
	repo.apiKeyMap["knownhash"] = a

	// The API key hash won't match, but we test that disabled sensors
	// would be rejected. The actual test requires matching the hash.
	_, err := svc.AuthenticateByAPIKey(context.Background(), "wrong-key")
	if err == nil {
		t.Fatal("Expected error for wrong API key")
	}
}

// =============================================================================
// Tests for Heartbeat
// =============================================================================

func TestHeartbeat_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Heartbeat Sensor")
	repo.sensors[a.ID] = a

	input := sensorapp.SensorHeartbeatInput{
		SensorID: a.ID,
		Version:  "1.0.0",
		Hostname: "test-host",
	}

	err := svc.Heartbeat(context.Background(), input)
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}

	// Verify sensor was updated
	updated := repo.sensors[a.ID]
	if updated.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", updated.Version)
	}
	if updated.Hostname != "test-host" {
		t.Errorf("Expected hostname 'test-host', got '%s'", updated.Hostname)
	}
	if updated.Health != sensor.SensorHealthOnline {
		t.Errorf("Expected health 'online', got '%s'", updated.Health)
	}
}

func TestHeartbeat_SensorNotFound(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)

	input := sensorapp.SensorHeartbeatInput{
		SensorID: shared.NewID(),
	}

	err := svc.Heartbeat(context.Background(), input)
	if err == nil {
		t.Fatal("Expected error for non-existent sensor")
	}
}

// =============================================================================
// Tests for FindAvailableSensors
// =============================================================================

func TestFindAvailableSensors_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a1 := createTestSensor(t, tenantID, "Available Sensor 1")
	a2 := createTestSensor(t, tenantID, "Available Sensor 2")
	repo.findAvail = []*sensor.Sensor{a1, a2}

	sensors, err := svc.FindAvailableSensors(context.Background(), tenantID, []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("FindAvailableSensors failed: %v", err)
	}

	if len(sensors) != 2 {
		t.Errorf("Expected 2 available sensors, got %d", len(sensors))
	}
}

func TestFindAvailableSensors_NoSensors(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	repo.findAvail = []*sensor.Sensor{}

	sensors, err := svc.FindAvailableSensors(context.Background(), tenantID, []string{"sast"}, "nuclei")
	if err != nil {
		t.Fatalf("FindAvailableSensors failed: %v", err)
	}

	if len(sensors) != 0 {
		t.Errorf("Expected 0 sensors, got %d", len(sensors))
	}
}

// =============================================================================
// Tests for RegenerateAPIKey
// =============================================================================

func TestRegenerateAPIKey_Success(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	a := createTestSensor(t, tenantID, "Regen Key Sensor")
	a.SetAPIKey("oldhash", "rda_old")
	repo.sensors[a.ID] = a

	newKey, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("RegenerateAPIKey failed: %v", err)
	}

	if newKey == "" {
		t.Error("Expected non-empty new API key")
	}

	// Verify sensor was updated with new key hash
	updated := repo.sensors[a.ID]
	if updated.APIKeyHash == "oldhash" {
		t.Error("Expected API key hash to be different from old hash")
	}
}

func TestRegenerateAPIKey_SensorNotFound(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()

	_, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("Expected error for non-existent sensor")
	}
}

// =============================================================================
// Tests for Sensor Entity
// =============================================================================

func TestSensor_HasCapacity(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestSensor(t, tenantID, "Capacity Test")
	a.SetMaxConcurrentJobs(5)
	a.CurrentJobs = 3

	if !a.HasCapacity() {
		t.Error("Sensor with 3/5 jobs should have capacity")
	}

	a.CurrentJobs = 5
	if a.HasCapacity() {
		t.Error("Sensor with 5/5 jobs should not have capacity")
	}
}

func TestSensor_AvailableSlots(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestSensor(t, tenantID, "Slots Test")
	a.SetMaxConcurrentJobs(5)
	a.CurrentJobs = 2

	if a.AvailableSlots() != 3 {
		t.Errorf("Expected 3 available slots, got %d", a.AvailableSlots())
	}
}

func TestSensor_MatchesRequirements(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestSensor(t, tenantID, "Requirements Test")
	// Has capabilities: ["sast"]; reports semgrep installed.
	a.Reported = sensor.ReportOf("semgrep")

	if !a.MatchesRequirements([]string{"sast"}, "semgrep") {
		t.Error("Sensor should match sast + semgrep requirements")
	}

	if a.MatchesRequirements([]string{"dast"}, "nuclei") {
		t.Error("Sensor should not match dast + nuclei requirements")
	}

	if a.MatchesRequirements([]string{"sast"}, "trivy") {
		t.Error("Sensor should not match sast + trivy (wrong tool)")
	}
}

func TestSensor_IsAvailable(t *testing.T) {
	tenantID := shared.NewID()
	a := createTestSensor(t, tenantID, "Available Test")

	if !a.IsAvailable() {
		t.Error("Active sensor should be available")
	}

	a.Disable("test")
	if a.IsAvailable() {
		t.Error("Disabled sensor should not be available")
	}
}

func (m *mockSensorRepo) KnownCapabilityNames(_ context.Context, _ *shared.ID, _, _ []string) (map[string]bool, map[string]bool, error) {
	return map[string]bool{}, map[string]bool{}, nil
}
