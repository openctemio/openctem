package unit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

// ============================================================================
// Mock Repository
// ============================================================================

// sensorSvcMockRepo implements sensor.Repository for testing.
type sensorSvcMockRepo struct {
	mu      sync.Mutex
	sensors map[string]*sensor.Sensor // keyed by sensor ID string

	// Error injection
	createErr                   error
	getByIDErr                  error
	getByTenantAndIDErr         error
	getByAPIKeyHashErr          error
	listErr                     error
	updateErr                   error
	deleteErr                   error
	updateLastSeenErr           error
	incrementStatsErr           error
	findAvailableErr            error
	findAvailableWithCapErr     error
	claimJobErr                 error
	releaseJobErr               error
	getAvailableCapabilitiesErr error
	hasSensorForCapabilityErr   error
	getPlatformSensorStatsErr   error

	// Capability catalog (KnownCapabilityNames) and the last heartbeat write.
	knownTools    map[string]bool
	knownCaps     map[string]bool
	knownErr      error
	lastHeartbeat sensor.HeartbeatUpdate

	// Return overrides
	availableSensors    []*sensor.Sensor
	availableCapSensors []*sensor.Sensor
	capabilities        []string
	hasCapability       bool
	platformStats       *sensor.PlatformSensorStatsResult
	staleOfflineIDs     []shared.ID // returned by MarkStaleSensorsOffline
	// livenessNow is the database time ListLivenessCandidates reports; zero
	// is time.Now().
	livenessNow time.Time

	// Call tracking
	createCalls           int
	getByIDCalls          int
	getByTenantAndIDCalls int
	getByAPIKeyHashCalls  int
	listCalls             int
	updateCalls           int
	retireInlineKeyCalls  int
	updateHeartbeatCalls  int
	updateAPIKeyCalls     int
	deleteCalls           int
	updateLastSeenCalls   int
	incrementStatsCalls   int
	findAvailableCalls    int
	findAvailableCapCalls int
	claimJobCalls         int
	releaseJobCalls       int
	getAvailCapCalls      int
	hasSensorCapCalls     int
	getPlatformStatsCalls int

	// Last args
	lastFilter     sensor.Filter
	lastPagination pagination.Pagination
	lastAPIKeyHash string
	lastStatsArgs  struct {
		findings, scans, errors int64
	}
}

func newSensorSvcMockRepo() *sensorSvcMockRepo {
	return &sensorSvcMockRepo{
		sensors: make(map[string]*sensor.Sensor),
	}
}

func (m *sensorSvcMockRepo) Create(_ context.Context, a *sensor.Sensor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sensors[a.ID.String()] = a
	return nil
}

func (m *sensorSvcMockRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, a := range m.sensors {
		count++
		_ = a
	}
	return count, nil
}

func (m *sensorSvcMockRepo) GetByID(_ context.Context, id shared.ID) (*sensor.Sensor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	a, ok := m.sensors[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *sensorSvcMockRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByTenantAndIDCalls++
	if m.getByTenantAndIDErr != nil {
		return nil, m.getByTenantAndIDErr
	}
	a, ok := m.sensors[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	// IDOR check
	if a.TenantID == nil || *a.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return a, nil
}

func (m *sensorSvcMockRepo) GetByAPIKeyHash(_ context.Context, hash string) (*sensor.Sensor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByAPIKeyHashCalls++
	m.lastAPIKeyHash = hash
	if m.getByAPIKeyHashErr != nil {
		return nil, m.getByAPIKeyHashErr
	}
	for _, a := range m.sensors {
		if a.APIKeyHash == hash {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *sensorSvcMockRepo) List(_ context.Context, filter sensor.Filter, page pagination.Pagination) (pagination.Result[*sensor.Sensor], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	m.lastFilter = filter
	m.lastPagination = page
	if m.listErr != nil {
		return pagination.Result[*sensor.Sensor]{}, m.listErr
	}
	var results []*sensor.Sensor
	for _, a := range m.sensors {
		if filter.TenantID != nil && (a.TenantID == nil || *a.TenantID != *filter.TenantID) {
			continue
		}
		results = append(results, a)
	}
	total := int64(len(results))
	return pagination.Result[*sensor.Sensor]{
		Data:       results,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *sensorSvcMockRepo) Update(_ context.Context, a *sensor.Sensor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sensors[a.ID.String()] = a
	return nil
}

func (m *sensorSvcMockRepo) RetireInlineKey(_ context.Context, id shared.ID, keyHashes []string, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retireInlineKeyCalls++
	if m.updateErr != nil {
		return false, m.updateErr
	}
	a, ok := m.sensors[id.String()]
	// Hash guard + never extend, as the SQL.
	if !ok || !slices.Contains(keyHashes, a.APIKeyHash) || (a.InlineKeyExpiresAt != nil && !a.InlineKeyExpiresAt.After(at)) {
		return false, nil
	}
	t := at
	a.InlineKeyExpiresAt = &t
	return true, nil
}

func (m *sensorSvcMockRepo) UpdateHeartbeat(_ context.Context, id shared.ID, hb sensor.HeartbeatUpdate) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateHeartbeatCalls++
	m.lastHeartbeat = hb
	if m.updateErr != nil {
		return false, m.updateErr
	}
	a, ok := m.sensors[id.String()]
	if !ok || a.Status != sensor.SensorStatusActive { // status='active' guard
		return false, nil
	}
	if hb.TenantID != nil && (a.TenantID == nil || *a.TenantID != *hb.TenantID) {
		return false, nil // tenant guard
	}
	if hb.Version != "" {
		a.Version = hb.Version
	}
	if hb.Hostname != "" {
		a.Hostname = hb.Hostname
	}
	if hb.Region != "" {
		a.Region = hb.Region
	}
	a.CPUPercent = hb.CPUPercent
	a.MemoryPercent = hb.MemoryPercent
	a.DiskReadMBPS = hb.DiskReadMBPS
	a.DiskWriteMBPS = hb.DiskWriteMBPS
	a.NetworkRxMBPS = hb.NetworkRxMBPS
	a.NetworkTxMBPS = hb.NetworkTxMBPS
	a.LoadScore = hb.LoadScore
	if hb.IPAddress != nil {
		a.IPAddress = hb.IPAddress
	}
	now := time.Now()
	a.MetricsUpdatedAt = &now
	a.LastSeenAt = &now
	a.Health = sensor.SensorHealthOnline
	return true, nil
}

func (m *sensorSvcMockRepo) UpdateAPIKey(_ context.Context, id shared.ID, hash, prefix string, expiresAt *time.Time, requireActive bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateAPIKeyCalls++
	if m.updateErr != nil {
		return false, m.updateErr
	}
	a, ok := m.sensors[id.String()]
	if !ok || (requireActive && a.Status != sensor.SensorStatusActive) {
		return false, nil
	}
	a.SetAPIKeyWithExpiry(hash, prefix, expiresAt)
	return true, nil
}

func (m *sensorSvcMockRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sensors, id.String())
	return nil
}

func (m *sensorSvcMockRepo) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateLastSeenCalls++
	return m.updateLastSeenErr
}

func (m *sensorSvcMockRepo) IncrementStats(_ context.Context, _ shared.ID, findings, scans, errs int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incrementStatsCalls++
	m.lastStatsArgs.findings = findings
	m.lastStatsArgs.scans = scans
	m.lastStatsArgs.errors = errs
	return m.incrementStatsErr
}

func (m *sensorSvcMockRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return nil, nil
}

func (m *sensorSvcMockRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findAvailableCalls++
	if m.findAvailableErr != nil {
		return nil, m.findAvailableErr
	}
	return m.availableSensors, nil
}

func (m *sensorSvcMockRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*sensor.Sensor, error) {
	return nil, nil
}

func (m *sensorSvcMockRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}

func (m *sensorSvcMockRepo) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findAvailableCapCalls++
	if m.findAvailableWithCapErr != nil {
		return nil, m.findAvailableWithCapErr
	}
	return m.availableCapSensors, nil
}

func (m *sensorSvcMockRepo) ClaimJob(_ context.Context, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimJobCalls++
	return m.claimJobErr
}

func (m *sensorSvcMockRepo) ReleaseJob(_ context.Context, _ shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseJobCalls++
	return m.releaseJobErr
}

func (m *sensorSvcMockRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *sensorSvcMockRepo) MarkStaleSensorsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.staleOfflineIDs, nil
}

// ListLivenessCandidates implements sensor.LivenessRepository over the
// seeded sensors.
func (m *sensorSvcMockRepo) ListLivenessCandidates(_ context.Context) (time.Time, []sensor.LivenessCandidate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.livenessNow
	if now.IsZero() {
		now = time.Now()
	}
	var out []sensor.LivenessCandidate
	for _, a := range m.sensors {
		if a.Health.IsLive() {
			out = append(out, sensor.LivenessCandidate{ID: a.ID, Health: a.Health, Deadline: a.HeartbeatDeadline()})
		}
	}
	return now, out, nil
}

// ApplyLiveness implements sensor.LivenessRepository with the same guard as
// the postgres one: still live, not already there, last seen unchanged.
func (m *sensorSvcMockRepo) ApplyLiveness(_ context.Context, h sensor.SensorHealth, cands []sensor.LivenessCandidate) ([]shared.ID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var moved []shared.ID
	for _, c := range cands {
		a, ok := m.sensors[c.ID.String()]
		if !ok || !a.Health.IsLive() || a.Health == h {
			continue
		}
		if (a.LastSeenAt == nil) != (c.Deadline.LastSeenAt == nil) ||
			(a.LastSeenAt != nil && !a.LastSeenAt.Equal(*c.Deadline.LastSeenAt)) {
			continue
		}
		a.Health = h
		if h == sensor.SensorHealthOffline {
			now := time.Now()
			a.LastOfflineAt = &now
		}
		moved = append(moved, a.ID)
	}
	return moved, nil
}

// silence makes a seeded sensor online but last seen ago, with no stored
// deadline (due = last seen + 60s).
func (m *sensorSvcMockRepo) silence(a *sensor.Sensor, ago time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := time.Now().Add(-ago)
	a.Health, a.LastSeenAt, a.HeartbeatDueAt, a.HeartbeatInterval = sensor.SensorHealthOnline, &seen, nil, 0
}

func (m *sensorSvcMockRepo) GetSensorsOfflineSince(_ context.Context, _ time.Time) ([]*sensor.Sensor, error) {
	return nil, nil
}

func (m *sensorSvcMockRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *sensorSvcMockRepo) HasSensorForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *sensorSvcMockRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getAvailCapCalls++
	if m.getAvailableCapabilitiesErr != nil {
		return nil, m.getAvailableCapabilitiesErr
	}
	return m.capabilities, nil
}

func (m *sensorSvcMockRepo) HasSensorForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasSensorCapCalls++
	if m.hasSensorForCapabilityErr != nil {
		return false, m.hasSensorForCapabilityErr
	}
	return m.hasCapability, nil
}

func (m *sensorSvcMockRepo) GetPlatformSensorStats(_ context.Context, _ shared.ID) (*sensor.PlatformSensorStatsResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getPlatformStatsCalls++
	if m.getPlatformSensorStatsErr != nil {
		return nil, m.getPlatformSensorStatsErr
	}
	if m.platformStats != nil {
		return m.platformStats, nil
	}
	return &sensor.PlatformSensorStatsResult{
		TierBreakdown: make(map[string]sensor.TierBreakdown),
	}, nil
}

func (m *sensorSvcMockRepo) GetTenantSensorStats(_ context.Context, _ shared.ID) (*sensor.TenantSensorStats, error) {
	return &sensor.TenantSensorStats{
		ByStatus: make(map[string]int),
		ByHealth: make(map[string]int),
		ByType:   make(map[string]int),
		ByMode:   make(map[string]int),
	}, nil
}

// seedSensor creates and stores a sensor in the mock repo.
func (m *sensorSvcMockRepo) seedSensor(tenantID shared.ID, name string, sensorType sensor.SensorType) *sensor.Sensor {
	a, _ := sensor.NewSensor(tenantID, name, sensorType, "test sensor", []string{"sast"}, sensor.ExecutionModeStandalone)
	m.sensors[a.ID.String()] = a
	return a
}

// ============================================================================
// Helper functions
// ============================================================================

func newSensorSvcTestService(repo *sensorSvcMockRepo) *sensorapp.SensorService {
	log := logger.NewNop()
	return sensorapp.NewSensorService(repo, nil, log)
}

func sensorSvcValidTenantID() string {
	return shared.NewID().String()
}

// ============================================================================
// Tests: CreateSensor
// ============================================================================

func TestSensorService_CreateSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID:     sensorSvcValidTenantID(),
		Name:         "test-runner",
		Type:         "worker",
		Description:  "A test runner sensor",
		Capabilities: []string{"sast", "sca"},
	}

	out, err := svc.CreateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if out.Sensor == nil {
		t.Fatal("expected sensor to be non-nil")
	}

	if out.Sensor.Name != "test-runner" {
		t.Errorf("expected name 'test-runner', got %q", out.Sensor.Name)
	}

	if out.Sensor.Type != sensor.SensorTypeWorker {
		t.Errorf("expected type worker, got %q", out.Sensor.Type)
	}

	if out.Sensor.Status != sensor.SensorStatusActive {
		t.Errorf("expected status 'active', got %q", out.Sensor.Status)
	}

	if out.Sensor.Health != sensor.SensorHealthUnknown {
		t.Errorf("expected health 'unknown', got %q", out.Sensor.Health)
	}

	// New keys are octs_ keys with a valid checksum, never legacy rda_.
	if p, ok := sensorkey.Valid(out.APIKey); !ok || p != sensorkey.PrefixSensorKey {
		t.Errorf("expected a valid octs_ API key, got %q", out.APIKey)
	}

	// API key length: "octs_" + 43 base62 chars + 6 checksum chars = 54
	if len(out.APIKey) != 54 {
		t.Errorf("expected API key length 54, got %d", len(out.APIKey))
	}
	if out.Sensor.IsLegacyKey() {
		t.Error("a newly created sensor must not be on a legacy key")
	}

	if out.Sensor.APIKeyHash == "" {
		t.Error("expected API key hash to be set")
	}

	if out.Sensor.InlineKeyPrefix == "" {
		t.Error("expected API key prefix to be set")
	}

	if repo.createCalls != 1 {
		t.Errorf("expected 1 Create call, got %d", repo.createCalls)
	}
}

// The runner type (a sensor key used from CI) is gone: CI pipelines use OIDC
// (RFC-051). Creating one is a validation error.
func TestSensorService_CreateSensor_RunnerTypeRefused(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	_, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: sensorSvcValidTenantID(), Name: "ci", Type: "runner",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("creating a runner sensor: err = %v, want a validation error", err)
	}
	if sensor.SensorType("runner").IsValid() {
		t.Fatal("runner is still a valid sensor type")
	}
}

func TestSensorService_CreateSensor_DefaultExecutionMode(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	tests := []struct {
		sensorType   string
		expectedMode sensor.ExecutionMode
	}{
		{"worker", sensor.ExecutionModeDaemon},
		{"collector", sensor.ExecutionModeDaemon},
		{"sensor", sensor.ExecutionModeDaemon},
	}

	for _, tc := range tests {
		t.Run(tc.sensorType, func(t *testing.T) {
			input := sensorapp.CreateSensorInput{
				TenantID: sensorSvcValidTenantID(),
				Name:     "test-" + tc.sensorType,
				Type:     tc.sensorType,
			}
			out, err := svc.CreateSensor(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if out.Sensor.ExecutionMode != tc.expectedMode {
				t.Errorf("expected execution mode %q for type %q, got %q", tc.expectedMode, tc.sensorType, out.Sensor.ExecutionMode)
			}
		})
	}
}

func TestSensorService_CreateSensor_MaxConcurrentJobs(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID:          sensorSvcValidTenantID(),
		Name:              "worker-1",
		Type:              "worker",
		MaxConcurrentJobs: 10,
	}

	out, err := svc.CreateSensor(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if out.Sensor.MaxConcurrentJobs != 10 {
		t.Errorf("expected max concurrent jobs 10, got %d", out.Sensor.MaxConcurrentJobs)
	}
}

func TestSensorService_CreateSensor_InvalidTenantID(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID: "not-a-uuid",
		Name:     "test-sensor",
		Type:     "worker",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_CreateSensor_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.createErr = errors.New("db connection failed")
	svc := newSensorSvcTestService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID: sensorSvcValidTenantID(),
		Name:     "test-sensor",
		Type:     "worker",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repo.Create fails")
	}
}

func TestSensorService_CreateSensor_EmptyName(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID: sensorSvcValidTenantID(),
		Name:     "",
		Type:     "worker",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_CreateSensor_InvalidType(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	input := sensorapp.CreateSensorInput{
		TenantID: sensorSvcValidTenantID(),
		Name:     "test-sensor",
		Type:     "invalid-type",
	}

	_, err := svc.CreateSensor(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid sensor type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// ============================================================================
// Tests: GetSensor
// ============================================================================

func TestSensorService_GetSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "my-runner", sensor.SensorTypeWorker)

	got, err := svc.GetSensor(context.Background(), tenantID.String(), a.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("expected sensor ID %s, got %s", a.ID, got.ID)
	}
}

func TestSensorService_GetSensor_InvalidTenantID(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.GetSensor(context.Background(), "bad-id", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_GetSensor_InvalidSensorID(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.GetSensor(context.Background(), sensorSvcValidTenantID(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid sensor ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_GetSensor_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.GetSensor(context.Background(), sensorSvcValidTenantID(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSensorService_GetSensor_IDORPrevention(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	a := repo.seedSensor(tenantA, "sensor-a", sensor.SensorTypeWorker)

	// Try to access tenant A's sensor using tenant B's ID
	_, err := svc.GetSensor(context.Background(), tenantB.String(), a.ID.String())
	if err == nil {
		t.Fatal("expected error when accessing another tenant's sensor (IDOR)")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for IDOR prevention, got %v", err)
	}
}

// ============================================================================
// Tests: ListSensors
// ============================================================================

func TestSensorService_ListSensors_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	repo.seedSensor(tenantID, "runner-1", sensor.SensorTypeWorker)
	repo.seedSensor(tenantID, "worker-1", sensor.SensorTypeWorker)

	result, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 sensors, got %d", result.Total)
	}
}

func TestSensorService_ListSensors_WithTypeFilter(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	repo.seedSensor(tenantID, "runner-1", sensor.SensorTypeWorker)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: tenantID.String(),
		Type:     "worker",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.Type == nil || *repo.lastFilter.Type != sensor.SensorTypeWorker {
		t.Error("expected type filter to be set to runner")
	}
}

func TestSensorService_ListSensors_WithStatusFilter(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: sensorSvcValidTenantID(),
		Status:   "active",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.Status == nil || *repo.lastFilter.Status != sensor.SensorStatusActive {
		t.Error("expected status filter to be set to active")
	}
}

func TestSensorService_ListSensors_WithHealthFilter(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: sensorSvcValidTenantID(),
		Health:   "online",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.Health == nil || *repo.lastFilter.Health != sensor.SensorHealthOnline {
		t.Error("expected health filter to be set to online")
	}
}

func TestSensorService_ListSensors_WithExecutionModeFilter(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID:      sensorSvcValidTenantID(),
		ExecutionMode: "daemon",
		Page:          1,
		PerPage:       10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.lastFilter.ExecutionMode == nil || *repo.lastFilter.ExecutionMode != sensor.ExecutionModeDaemon {
		t.Error("expected execution mode filter to be set to daemon")
	}
}

func TestSensorService_ListSensors_InvalidTenantID(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_ListSensors_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.listErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	_, err := svc.ListSensors(context.Background(), sensorapp.ListSensorsInput{
		TenantID: sensorSvcValidTenantID(),
		Page:     1,
		PerPage:  10,
	})
	if err == nil {
		t.Fatal("expected error when repo.List fails")
	}
}

// ============================================================================
// Tests: UpdateSensor
// ============================================================================

func TestSensorService_UpdateSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "old-name", sensor.SensorTypeWorker)

	updated, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID:    tenantID.String(),
		SensorID:    a.ID.String(),
		Name:        "new-name",
		Description: "updated description",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "new-name" {
		t.Errorf("expected name 'new-name', got %q", updated.Name)
	}
	if updated.Description != "updated description" {
		t.Errorf("expected description 'updated description', got %q", updated.Description)
	}
}

func TestSensorService_UpdateSensor_Capabilities(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	updated, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID:     tenantID.String(),
		SensorID:     a.ID.String(),
		Capabilities: []string{"dast", "api"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(updated.Capabilities) != 2 || updated.Capabilities[0] != "dast" {
		t.Errorf("expected capabilities [dast, api], got %v", updated.Capabilities)
	}
}

func TestSensorService_UpdateSensor_Status(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	updated, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: a.ID.String(),
		Status:   "disabled",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Status != sensor.SensorStatusDisabled {
		t.Errorf("expected status 'disabled', got %q", updated.Status)
	}
}

func TestSensorService_UpdateSensor_MaxConcurrentJobs(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	maxJobs := 20
	updated, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID:          tenantID.String(),
		SensorID:          a.ID.String(),
		MaxConcurrentJobs: &maxJobs,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.MaxConcurrentJobs != 20 {
		t.Errorf("expected max concurrent jobs 20, got %d", updated.MaxConcurrentJobs)
	}
}

func TestSensorService_UpdateSensor_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID: sensorSvcValidTenantID(),
		SensorID: shared.NewID().String(),
		Name:     "new-name",
	})
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_UpdateSensor_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.updateErr = errors.New("update failed")

	_, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: a.ID.String(),
		Name:     "new-name",
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

func TestSensorService_UpdateSensor_NoChanges(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	// Update with same name and empty fields
	updated, err := svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: a.ID.String(),
		Name:     "sensor-1", // same name
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "sensor-1" {
		t.Errorf("expected name unchanged")
	}
}

// ============================================================================
// Tests: UpdateHeartbeat
// ============================================================================

func TestSensorService_UpdateHeartbeat_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Version:       "1.2.0",
		Hostname:      "worker-node-1",
		CPUPercent:    45.5,
		MemoryPercent: 62.3,
		CurrentJobs:   3,
		Region:        "us-east-1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := repo.sensors[a.ID.String()]
	if updated.Version != "1.2.0" {
		t.Errorf("expected version '1.2.0', got %q", updated.Version)
	}
	if updated.Hostname != "worker-node-1" {
		t.Errorf("expected hostname 'worker-node-1', got %q", updated.Hostname)
	}
	if updated.Health != sensor.SensorHealthOnline {
		t.Errorf("expected health 'online' after heartbeat, got %q", updated.Health)
	}
	if updated.LastSeenAt == nil {
		t.Error("expected LastSeenAt to be set after heartbeat")
	}
}

func TestSensorService_UpdateHeartbeat_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	err := svc.UpdateHeartbeat(context.Background(), shared.NewID(), sensorapp.SensorHeartbeatData{})
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_UpdateHeartbeat_UpdateError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.updateErr = errors.New("update failed")

	err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{
		Version: "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: DeleteSensor
// ============================================================================

func TestSensorService_DeleteSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-to-delete", sensor.SensorTypeWorker)

	err := svc.DeleteSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 Delete call, got %d", repo.deleteCalls)
	}

	// Sensor should be gone
	if _, exists := repo.sensors[a.ID.String()]; exists {
		t.Error("expected sensor to be removed from repo")
	}
}

func TestSensorService_DeleteSensor_InvalidTenantID(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	err := svc.DeleteSensor(context.Background(), "bad-id", shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_DeleteSensor_InvalidSensorID(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	err := svc.DeleteSensor(context.Background(), sensorSvcValidTenantID(), "bad-id", nil)
	if err == nil {
		t.Fatal("expected error for invalid sensor ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestSensorService_DeleteSensor_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	err := svc.DeleteSensor(context.Background(), sensorSvcValidTenantID(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_DeleteSensor_IDORPrevention(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	a := repo.seedSensor(tenantA, "sensor-a", sensor.SensorTypeWorker)

	err := svc.DeleteSensor(context.Background(), tenantB.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when deleting another tenant's sensor (IDOR)")
	}
}

func TestSensorService_DeleteSensor_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.deleteErr = errors.New("delete failed")

	err := svc.DeleteSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when repo.Delete fails")
	}
}

// ============================================================================
// Tests: RegenerateAPIKey
// ============================================================================

func TestSensorService_RegenerateAPIKey_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	oldHash := a.APIKeyHash

	newKey, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if _, ok := sensorkey.Valid(newKey); !ok || !strings.HasPrefix(newKey, "octs_") {
		t.Errorf("expected regenerated key to be a valid octs_ key, got %q", newKey)
	}

	updated := repo.sensors[a.ID.String()]
	if updated.APIKeyHash == oldHash {
		t.Error("expected API key hash to change after regeneration")
	}
}

func TestSensorService_RegenerateAPIKey_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.RegenerateAPIKey(context.Background(), sensorSvcValidTenantID(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_RegenerateAPIKey_UpdateError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.updateErr = errors.New("update failed")

	_, err := svc.RegenerateAPIKey(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: RenewAPIKey (self-service credential rotation)
// ============================================================================

func TestSensorService_RenewAPIKey_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	oldHash := a.APIKeyHash

	newKey, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, ok := sensorkey.Valid(newKey); !ok || !strings.HasPrefix(newKey, "octs_") {
		t.Errorf("expected renewed key to be a valid octs_ key, got %q", newKey)
	}
	if repo.sensors[a.ID.String()].APIKeyHash == oldHash {
		t.Error("expected API key hash to change after renewal")
	}
}

// Renewal works for a platform (nil-tenant) sensor — the self-renew path must not
// be tenant-scoped, unlike the admin RegenerateAPIKey.
func TestSensorService_RenewAPIKey_PlatformSensor(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	a := repo.seedSensor(shared.NewID(), "platform-1", sensor.SensorTypeWorker)
	a.TenantID = nil
	a.IsPlatformSensor = true

	newKey, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a})
	if err != nil {
		t.Fatalf("expected no error for platform sensor renewal, got %v", err)
	}
	if _, ok := sensorkey.Valid(newKey); !ok || !strings.HasPrefix(newKey, "octs_") {
		t.Errorf("expected renewed key to be a valid octs_ key, got %q", newKey)
	}
}

func TestSensorService_RenewAPIKey_NilSensor(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{})
	if err == nil {
		t.Fatal("expected error for nil sensor")
	}
	if !errors.Is(err, shared.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

// A revoked/disabled sensor cannot renew, even if it still holds a working key
// (defends the auth→renew TOCTOU window: status is re-read from the repo).
func TestSensorService_RenewAPIKey_RevokedSensor(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "revoked-1", sensor.SensorTypeWorker)
	a.Revoke("compromised")
	repo.sensors[a.ID.String()] = a

	_, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a})
	if err == nil {
		t.Fatal("expected error for revoked sensor")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// End-to-end: after renewal the old key stops authenticating and the new key works.
func TestSensorService_RenewAPIKey_OldKeyStopsWorking(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "renew-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}
	oldKey := out.APIKey

	newKey, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: out.Sensor})
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if newKey == oldKey {
		t.Fatal("expected renewed key to differ from the old key")
	}

	if _, err := svc.AuthenticateByAPIKey(context.Background(), oldKey); err == nil {
		t.Error("expected the old key to stop authenticating after renewal")
	}
	if _, err := svc.AuthenticateByAPIKey(context.Background(), newKey); err != nil {
		t.Errorf("expected the new key to authenticate, got %v", err)
	}
}

func TestSensorService_RenewAPIKey_UpdateError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.updateErr = errors.New("update failed")

	_, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

func TestSensor_IsKeyExpired(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)
	cases := []struct {
		name    string
		expires *time.Time
		want    bool
	}{
		{"nil never expires", nil, false},
		{"future not expired", &future, false},
		{"past expired", &past, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &sensor.Sensor{InlineKeyExpiresAt: tc.expires}
			if got := a.IsKeyExpired(); got != tc.want {
				t.Errorf("IsKeyExpired() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Default service (no key TTL configured): a renewed key never expires — the
// returned expiry and the stored KeyExpiresAt are both nil (today's behavior).
func TestSensorService_RenewAPIKey_NoTTL_NeverExpires(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	_, expiresAt, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a})
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if expiresAt != nil {
		t.Errorf("expected nil expiry with no TTL configured, got %v", expiresAt)
	}
	if repo.sensors[a.ID.String()].InlineKeyExpiresAt != nil {
		t.Error("expected stored KeyExpiresAt to be nil with no TTL")
	}
}

// With a key TTL configured, a renewed key carries a fresh future expiry, both
// returned to the caller and persisted on the sensor.
func TestSensorService_RenewAPIKey_WithTTL_SetsExpiry(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	svc.SetKeyTTL(1 * time.Hour)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	before := time.Now()
	_, expiresAt, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: a})
	if err != nil {
		t.Fatalf("renew failed: %v", err)
	}
	if expiresAt == nil {
		t.Fatal("expected a non-nil expiry when TTL is configured")
	}
	if !expiresAt.After(before.Add(59 * time.Minute)) {
		t.Errorf("expected expiry ~1h out, got %v (before=%v)", expiresAt, before)
	}
	stored := repo.sensors[a.ID.String()].InlineKeyExpiresAt
	if stored == nil || !stored.Equal(*expiresAt) {
		t.Errorf("expected persisted KeyExpiresAt %v to match returned %v", stored, expiresAt)
	}
}

// An expired key is rejected at authentication even though the sensor is active.
func TestSensorService_AuthenticateByAPIKey_ExpiredKey(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "expired-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}

	past := time.Now().Add(-1 * time.Hour)
	out.Sensor.InlineKeyExpiresAt = &past
	repo.sensors[out.Sensor.ID.String()] = out.Sensor

	_, err = svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err == nil {
		t.Fatal("expected error for expired key")
	}
	if !errors.Is(err, shared.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for expired key, got %v", err)
	}
}

// A key with a future expiry (or NULL, the back-compat default) still authenticates.
func TestSensorService_AuthenticateByAPIKey_UnexpiredKey(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "unexpired-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}

	future := time.Now().Add(1 * time.Hour)
	out.Sensor.InlineKeyExpiresAt = &future
	repo.sensors[out.Sensor.ID.String()] = out.Sensor

	if _, err := svc.AuthenticateByAPIKey(context.Background(), out.APIKey); err != nil {
		t.Errorf("expected a future-expiry key to authenticate, got %v", err)
	}
}

// ============================================================================
// Tests: AuthenticateByAPIKey
// ============================================================================

func TestSensorService_AuthenticateByAPIKey_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	// Create a sensor via service to get a valid API key
	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "auth-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}

	// Authenticate with the key
	authenticated, err := svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if authenticated.ID != out.Sensor.ID {
		t.Errorf("expected sensor ID %s, got %s", out.Sensor.ID, authenticated.ID)
	}
}

func TestSensorService_AuthenticateByAPIKey_InvalidKey(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.AuthenticateByAPIKey(context.Background(), "rda_invalid_key_here")
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}
	if !errors.Is(err, shared.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestSensorService_AuthenticateByAPIKey_DisabledSensor(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "disabled-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}

	// Disable the sensor
	out.Sensor.Disable("test disable")
	repo.sensors[out.Sensor.ID.String()] = out.Sensor

	_, err = svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err == nil {
		t.Fatal("expected error for disabled sensor")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestSensorService_AuthenticateByAPIKey_RevokedSensor(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "revoked-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}

	// Revoke the sensor
	out.Sensor.Revoke("compromised")
	repo.sensors[out.Sensor.ID.String()] = out.Sensor

	_, err = svc.AuthenticateByAPIKey(context.Background(), out.APIKey)
	if err == nil {
		t.Fatal("expected error for revoked sensor")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected error message to mention 'revoked', got %q", err.Error())
	}
}

// ============================================================================
// Tests: ActivateSensor
// ============================================================================

func TestSensorService_ActivateSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.Disable("maintenance")

	activated, err := svc.ActivateSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if activated.Status != sensor.SensorStatusActive {
		t.Errorf("expected status 'active', got %q", activated.Status)
	}
}

func TestSensorService_ActivateSensor_RevokedCannotReactivate(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.Revoke("compromised")

	_, err := svc.ActivateSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when activating revoked sensor")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected error message to mention 'revoked', got %q", err.Error())
	}
}

func TestSensorService_ActivateSensor_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.ActivateSensor(context.Background(), sensorSvcValidTenantID(), shared.NewID().String(), nil)
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_ActivateSensor_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	a.Disable("test")
	repo.updateErr = errors.New("update failed")

	_, err := svc.ActivateSensor(context.Background(), tenantID.String(), a.ID.String(), nil)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: DisableSensor
// ============================================================================

func TestSensorService_DisableSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	disabled, err := svc.DisableSensor(context.Background(), tenantID.String(), a.ID.String(), "maintenance window", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if disabled.Status != sensor.SensorStatusDisabled {
		t.Errorf("expected status 'disabled', got %q", disabled.Status)
	}
	if disabled.StatusMessage != "maintenance window" {
		t.Errorf("expected status message 'maintenance window', got %q", disabled.StatusMessage)
	}
}

func TestSensorService_DisableSensor_DefaultReason(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	disabled, err := svc.DisableSensor(context.Background(), tenantID.String(), a.ID.String(), "", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if disabled.StatusMessage != "Disabled by administrator" {
		t.Errorf("expected default reason 'Disabled by administrator', got %q", disabled.StatusMessage)
	}
}

func TestSensorService_DisableSensor_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.DisableSensor(context.Background(), sensorSvcValidTenantID(), shared.NewID().String(), "test", nil)
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

// ============================================================================
// Tests: RevokeSensor
// ============================================================================

func TestSensorService_RevokeSensor_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	revoked, err := svc.RevokeSensor(context.Background(), tenantID.String(), a.ID.String(), "compromised key", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if revoked.Status != sensor.SensorStatusRevoked {
		t.Errorf("expected status 'revoked', got %q", revoked.Status)
	}
	if revoked.StatusMessage != "compromised key" {
		t.Errorf("expected status message 'compromised key', got %q", revoked.StatusMessage)
	}
}

func TestSensorService_RevokeSensor_DefaultReason(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	revoked, err := svc.RevokeSensor(context.Background(), tenantID.String(), a.ID.String(), "", nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if revoked.StatusMessage != "Revoked by administrator" {
		t.Errorf("expected default reason 'Revoked by administrator', got %q", revoked.StatusMessage)
	}
}

func TestSensorService_RevokeSensor_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	_, err := svc.RevokeSensor(context.Background(), sensorSvcValidTenantID(), shared.NewID().String(), "test", nil)
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_RevokeSensor_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.updateErr = errors.New("update failed")

	_, err := svc.RevokeSensor(context.Background(), tenantID.String(), a.ID.String(), "test", nil)
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: Heartbeat
// ============================================================================

func TestSensorService_Heartbeat_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	err := svc.Heartbeat(context.Background(), sensorapp.SensorHeartbeatInput{
		SensorID:  a.ID,
		Status:    "online",
		Message:   "all good",
		Version:   "2.0.0",
		Hostname:  "node-42",
		IPAddress: "192.168.1.100",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := repo.sensors[a.ID.String()]
	if updated.Health != sensor.SensorHealthOnline {
		t.Errorf("expected health 'online', got %q", updated.Health)
	}
	if updated.Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got %q", updated.Version)
	}
	if updated.Hostname != "node-42" {
		t.Errorf("expected hostname 'node-42', got %q", updated.Hostname)
	}
	if updated.IPAddress.String() != "192.168.1.100" {
		t.Errorf("expected IP '192.168.1.100', got %q", updated.IPAddress)
	}
	if updated.StatusMessage != "all good" {
		t.Errorf("expected status message 'all good', got %q", updated.StatusMessage)
	}
	if updated.LastSeenAt == nil {
		t.Error("expected LastSeenAt to be set")
	}
}

func TestSensorService_Heartbeat_MinimalInput(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	err := svc.Heartbeat(context.Background(), sensorapp.SensorHeartbeatInput{
		SensorID: a.ID,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := repo.sensors[a.ID.String()]
	if updated.Health != sensor.SensorHealthOnline {
		t.Errorf("expected health 'online' after heartbeat, got %q", updated.Health)
	}
}

func TestSensorService_Heartbeat_NotFound(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	err := svc.Heartbeat(context.Background(), sensorapp.SensorHeartbeatInput{
		SensorID: shared.NewID(),
	})
	if err == nil {
		t.Fatal("expected error for non-existent sensor")
	}
}

func TestSensorService_Heartbeat_UpdateError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.updateErr = errors.New("update failed")

	err := svc.Heartbeat(context.Background(), sensorapp.SensorHeartbeatInput{
		SensorID: a.ID,
		Version:  "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when repo.Update fails")
	}
}

// ============================================================================
// Tests: FindAvailableSensors
// ============================================================================

func TestSensorService_FindAvailableSensors_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.availableSensors = []*sensor.Sensor{a}

	sensors, err := svc.FindAvailableSensors(context.Background(), tenantID, []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sensors) != 1 {
		t.Errorf("expected 1 available sensor, got %d", len(sensors))
	}
}

func TestSensorService_FindAvailableSensors_Empty(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	repo.availableSensors = []*sensor.Sensor{}

	sensors, err := svc.FindAvailableSensors(context.Background(), shared.NewID(), []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sensors) != 0 {
		t.Errorf("expected 0 available sensors, got %d", len(sensors))
	}
}

func TestSensorService_FindAvailableSensors_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.findAvailableErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	_, err := svc.FindAvailableSensors(context.Background(), shared.NewID(), []string{"sast"}, "semgrep")
	if err == nil {
		t.Fatal("expected error when repo.FindAvailable fails")
	}
}

// ============================================================================
// Tests: FindAvailableWithCapacity
// ============================================================================

func TestSensorService_FindAvailableWithCapacity_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)
	repo.availableCapSensors = []*sensor.Sensor{a}

	sensors, err := svc.FindAvailableWithCapacity(context.Background(), tenantID, []string{"sast"}, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sensors) != 1 {
		t.Errorf("expected 1 sensor with capacity, got %d", len(sensors))
	}
}

func TestSensorService_FindAvailableWithCapacity_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.findAvailableWithCapErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	_, err := svc.FindAvailableWithCapacity(context.Background(), shared.NewID(), []string{"sast"}, "semgrep")
	if err == nil {
		t.Fatal("expected error when repo.FindAvailableWithCapacity fails")
	}
}

// ============================================================================
// Tests: IncrementStats
// ============================================================================

func TestSensorService_IncrementStats_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	err := svc.IncrementStats(context.Background(), shared.NewID(), 10, 5, 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.incrementStatsCalls != 1 {
		t.Errorf("expected 1 IncrementStats call, got %d", repo.incrementStatsCalls)
	}
	if repo.lastStatsArgs.findings != 10 {
		t.Errorf("expected findings=10, got %d", repo.lastStatsArgs.findings)
	}
	if repo.lastStatsArgs.scans != 5 {
		t.Errorf("expected scans=5, got %d", repo.lastStatsArgs.scans)
	}
	if repo.lastStatsArgs.errors != 2 {
		t.Errorf("expected errors=2, got %d", repo.lastStatsArgs.errors)
	}
}

func TestSensorService_IncrementStats_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.incrementStatsErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	err := svc.IncrementStats(context.Background(), shared.NewID(), 1, 1, 0)
	if err == nil {
		t.Fatal("expected error when repo.IncrementStats fails")
	}
}

// ============================================================================
// Tests: GetAvailableCapabilitiesForTenant
// ============================================================================

func TestSensorService_GetAvailableCapabilitiesForTenant_Success(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.capabilities = []string{"sast", "sca", "dast"}
	svc := newSensorSvcTestService(repo)

	out, err := svc.GetAvailableCapabilitiesForTenant(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(out.Capabilities) != 3 {
		t.Errorf("expected 3 capabilities, got %d", len(out.Capabilities))
	}
	if out.TotalSensors != 3 {
		t.Errorf("expected TotalSensors=3 (len of capabilities), got %d", out.TotalSensors)
	}
}

func TestSensorService_GetAvailableCapabilitiesForTenant_Empty(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.capabilities = nil // nil from repo
	svc := newSensorSvcTestService(repo)

	out, err := svc.GetAvailableCapabilitiesForTenant(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Should return empty array, not nil
	if out.Capabilities == nil {
		t.Error("expected non-nil capabilities slice (empty array)")
	}
	if len(out.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(out.Capabilities))
	}
}

func TestSensorService_GetAvailableCapabilitiesForTenant_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.getAvailableCapabilitiesErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	_, err := svc.GetAvailableCapabilitiesForTenant(context.Background(), shared.NewID())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: HasCapability
// ============================================================================

func TestSensorService_HasCapability_True(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.hasCapability = true
	svc := newSensorSvcTestService(repo)

	has, err := svc.HasCapability(context.Background(), shared.NewID(), "sast")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected HasCapability to return true")
	}
}

func TestSensorService_HasCapability_False(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.hasCapability = false
	svc := newSensorSvcTestService(repo)

	has, err := svc.HasCapability(context.Background(), shared.NewID(), "sast")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected HasCapability to return false")
	}
}

func TestSensorService_HasCapability_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.hasSensorForCapabilityErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	_, err := svc.HasCapability(context.Background(), shared.NewID(), "sast")
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: GetPlatformStats
// ============================================================================

func TestSensorService_GetPlatformStats_NoPlatformSensors(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.platformStats = &sensor.PlatformSensorStatsResult{
		TotalSensors:  0,
		TierBreakdown: make(map[string]sensor.TierBreakdown),
	}
	svc := newSensorSvcTestService(repo)

	out, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out.Enabled {
		t.Error("expected Enabled=false when no platform sensors")
	}
	if out.MaxTier != "shared" {
		t.Errorf("expected MaxTier='shared', got %q", out.MaxTier)
	}
	if len(out.AccessibleTiers) != 1 || out.AccessibleTiers[0] != "shared" {
		t.Errorf("expected AccessibleTiers=[shared], got %v", out.AccessibleTiers)
	}
}

func TestSensorService_GetPlatformStats_WithSensors(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.platformStats = &sensor.PlatformSensorStatsResult{
		TotalSensors:      5,
		OnlineSensors:     3,
		TotalCapacity:     25,
		CurrentActiveJobs: 10,
		CurrentQueuedJobs: 2,
		TierBreakdown: map[string]sensor.TierBreakdown{
			"shared": {
				TotalSensors:  3,
				OnlineSensors: 2,
				TotalCapacity: 15,
				CurrentLoad:   6,
			},
			"dedicated": {
				TotalSensors:  2,
				OnlineSensors: 1,
				TotalCapacity: 10,
				CurrentLoad:   4,
			},
		},
	}
	svc := newSensorSvcTestService(repo)

	out, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !out.Enabled {
		t.Error("expected Enabled=true when platform sensors exist")
	}
	if out.MaxTier != "dedicated" {
		t.Errorf("expected MaxTier='dedicated', got %q", out.MaxTier)
	}
	if out.MaxConcurrent != 25 {
		t.Errorf("expected MaxConcurrent=25, got %d", out.MaxConcurrent)
	}
	if out.MaxQueued != 75 {
		t.Errorf("expected MaxQueued=75 (3x capacity), got %d", out.MaxQueued)
	}
	if out.CurrentActive != 10 {
		t.Errorf("expected CurrentActive=10, got %d", out.CurrentActive)
	}
	if out.CurrentQueued != 2 {
		t.Errorf("expected CurrentQueued=2, got %d", out.CurrentQueued)
	}
	if out.AvailableSlots != 15 {
		t.Errorf("expected AvailableSlots=15, got %d", out.AvailableSlots)
	}

	// Check tier stats
	sharedTier, ok := out.TierStats["shared"]
	if !ok {
		t.Fatal("expected 'shared' tier in TierStats")
	}
	if sharedTier.TotalSensors != 3 {
		t.Errorf("expected shared TotalSensors=3, got %d", sharedTier.TotalSensors)
	}
	if sharedTier.OnlineSensors != 2 {
		t.Errorf("expected shared OnlineSensors=2, got %d", sharedTier.OnlineSensors)
	}
	if sharedTier.OfflineSensors != 1 {
		t.Errorf("expected shared OfflineSensors=1, got %d", sharedTier.OfflineSensors)
	}
	if sharedTier.AvailableSlots != 9 {
		t.Errorf("expected shared AvailableSlots=9, got %d", sharedTier.AvailableSlots)
	}
}

func TestSensorService_GetPlatformStats_WithPremiumTier(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.platformStats = &sensor.PlatformSensorStatsResult{
		TotalSensors:  2,
		TotalCapacity: 10,
		TierBreakdown: map[string]sensor.TierBreakdown{
			"shared":  {TotalSensors: 1, TotalCapacity: 5},
			"premium": {TotalSensors: 1, TotalCapacity: 5},
		},
	}
	svc := newSensorSvcTestService(repo)

	out, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if out.MaxTier != "premium" {
		t.Errorf("expected MaxTier='premium', got %q", out.MaxTier)
	}
	// Should have shared + premium
	foundShared := false
	foundPremium := false
	for _, tier := range out.AccessibleTiers {
		if tier == "shared" {
			foundShared = true
		}
		if tier == "premium" {
			foundPremium = true
		}
	}
	if !foundShared || !foundPremium {
		t.Errorf("expected AccessibleTiers to contain shared and premium, got %v", out.AccessibleTiers)
	}
}

func TestSensorService_GetPlatformStats_RepoError(t *testing.T) {
	repo := newSensorSvcMockRepo()
	repo.getPlatformSensorStatsErr = errors.New("db error")
	svc := newSensorSvcTestService(repo)

	_, err := svc.GetPlatformStats(context.Background(), shared.NewID())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
}

// ============================================================================
// Tests: API Key Format
// ============================================================================

func TestSensorService_APIKeyFormat(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: sensorSvcValidTenantID(),
		Name:     "format-test",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}

	// Verify prefix format: "octs_" + first 5 random chars (10 characters,
	// fits the VARCHAR(12) column; the SDK's 8-character log hint is a prefix
	// of it).
	expectedPrefix := out.APIKey[:10]
	if out.Sensor.InlineKeyPrefix != expectedPrefix {
		t.Errorf("expected prefix %q, got %q", expectedPrefix, out.Sensor.InlineKeyPrefix)
	}
}

func TestSensorService_APIKeyUniqueness(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)

	keys := make(map[string]bool)
	for i := 0; i < 10; i++ {
		out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
			TenantID: sensorSvcValidTenantID(),
			Name:     "sensor-" + strings.Repeat("x", i+1),
			Type:     "worker",
		})
		if err != nil {
			t.Fatalf("failed to create sensor %d: %v", i, err)
		}
		if keys[out.APIKey] {
			t.Fatalf("duplicate API key generated at iteration %d", i)
		}
		keys[out.APIKey] = true
	}
}

// ============================================================================
// Tests: Status Transitions
// ============================================================================

func TestSensorService_StatusTransitions(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	tenantID := shared.NewID()

	// Create sensor (active by default)
	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "transition-sensor",
		Type:     "worker",
	})
	if err != nil {
		t.Fatalf("failed to create sensor: %v", err)
	}
	if out.Sensor.Status != sensor.SensorStatusActive {
		t.Fatalf("expected initial status 'active', got %q", out.Sensor.Status)
	}

	sensorID := out.Sensor.ID.String()

	// Active -> Disabled
	disabled, err := svc.DisableSensor(context.Background(), tenantID.String(), sensorID, "test", nil)
	if err != nil {
		t.Fatalf("failed to disable: %v", err)
	}
	if disabled.Status != sensor.SensorStatusDisabled {
		t.Errorf("expected 'disabled', got %q", disabled.Status)
	}

	// Disabled -> Active
	activated, err := svc.ActivateSensor(context.Background(), tenantID.String(), sensorID, nil)
	if err != nil {
		t.Fatalf("failed to activate: %v", err)
	}
	if activated.Status != sensor.SensorStatusActive {
		t.Errorf("expected 'active', got %q", activated.Status)
	}

	// Active -> Revoked
	revoked, err := svc.RevokeSensor(context.Background(), tenantID.String(), sensorID, "bye", nil)
	if err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}
	if revoked.Status != sensor.SensorStatusRevoked {
		t.Errorf("expected 'revoked', got %q", revoked.Status)
	}

	// Revoked -> Active (should fail)
	_, err = svc.ActivateSensor(context.Background(), tenantID.String(), sensorID, nil)
	if err == nil {
		t.Fatal("expected error when activating revoked sensor")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// ============================================================================
// Tests: Nil AuditService (optional dependency)
// ============================================================================

func TestSensorService_NilAuditService_DoesNotPanic(t *testing.T) {
	repo := newSensorSvcMockRepo()
	// Pass nil audit service
	log := logger.NewNop()
	svc := sensorapp.NewSensorService(repo, nil, log)
	tenantID := shared.NewID()

	// CreateSensor with audit context should not panic
	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(),
		Name:     "no-panic-sensor",
		Type:     "worker",
		AuditContext: &audit.AuditContext{
			TenantID: tenantID.String(),
			ActorID:  shared.NewID().String(),
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	sensorID := out.Sensor.ID.String()

	// UpdateSensor with audit context
	_, err = svc.UpdateSensor(context.Background(), sensorapp.UpdateSensorInput{
		TenantID:     tenantID.String(),
		SensorID:     sensorID,
		Name:         "updated",
		AuditContext: &audit.AuditContext{TenantID: tenantID.String()},
	})
	if err != nil {
		t.Fatalf("UpdateSensor should not panic with nil audit service: %v", err)
	}

	// DeleteSensor with audit context
	auditCtx := &audit.AuditContext{TenantID: tenantID.String()}
	err = svc.DeleteSensor(context.Background(), tenantID.String(), sensorID, auditCtx)
	if err != nil {
		t.Fatalf("DeleteSensor should not panic with nil audit service: %v", err)
	}
}

// ============================================================================
// Tests: multi-key store (RFC-014 Phase 3 rotation overlap)
// ============================================================================

// mockSensorAPIKeyRepo is an in-memory sensor.APIKeyRepository for the overlap
// tests. Its rotations write the inline key through sensors, the sensor
// repository the service uses, as the SQL writes both tables in one
// transaction.
type mockSensorAPIKeyRepo struct {
	mu        sync.Mutex
	byID      map[string]*sensor.APIKey
	createErr error
	sensors   sensor.Repository

	// sensorLocks models the per-sensor lock RotateKey and ReplaceInlineKey
	// take (a row lock on the sensor): rotations of one sensor never
	// interleave.
	sensorLocks sync.Map // sensor id -> *sync.Mutex

	// beforeRotate, when set, runs at the start of RotateKey and
	// ReplaceInlineKey, before the lock: whatever it does lands between a
	// renewal's authentication and its rotation.
	beforeRotate func()
}

func (m *mockSensorAPIKeyRepo) runBeforeRotate() {
	if hook := m.beforeRotate; hook != nil {
		m.beforeRotate = nil
		hook()
	}
}

func newMockSensorAPIKeyRepo(sensors sensor.Repository) *mockSensorAPIKeyRepo {
	return &mockSensorAPIKeyRepo{byID: make(map[string]*sensor.APIKey), sensors: sensors}
}

func (m *mockSensorAPIKeyRepo) lockSensor(id shared.ID) func() {
	l, _ := m.sensorLocks.LoadOrStore(id.String(), &sync.Mutex{})
	mu := l.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (m *mockSensorAPIKeyRepo) Create(_ context.Context, k *sensor.APIKey) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *k
	m.byID[k.ID.String()] = &cp
	return nil
}
func (m *mockSensorAPIKeyRepo) GetByID(_ context.Context, id shared.ID) (*sensor.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.byID[id.String()]; ok {
		cp := *k
		return &cp, nil
	}
	return nil, sensor.ErrSensorNotFound
}
func (m *mockSensorAPIKeyRepo) GetByHash(_ context.Context, hash string) (*sensor.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.byID {
		if k.KeyHash == hash && k.IsActive {
			cp := *k
			return &cp, nil
		}
	}
	return nil, sensor.ErrSensorNotFound
}
func (m *mockSensorAPIKeyRepo) GetBySensorID(_ context.Context, sensorID shared.ID) ([]*sensor.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*sensor.APIKey
	for _, k := range m.byID {
		if k.SensorID == sensorID {
			cp := *k
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (m *mockSensorAPIKeyRepo) List(_ context.Context, _ sensor.APIKeyFilter) ([]*sensor.APIKey, error) {
	return nil, nil
}
func (m *mockSensorAPIKeyRepo) Update(_ context.Context, k *sensor.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *k
	m.byID[k.ID.String()] = &cp
	return nil
}
func (m *mockSensorAPIKeyRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id.String())
	return nil
}
func (m *mockSensorAPIKeyRepo) RecordUsage(_ context.Context, id shared.ID, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.byID[id.String()]; ok {
		k.UseCount++
	}
	return nil
}
func (m *mockSensorAPIKeyRepo) Revoke(_ context.Context, id shared.ID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k, ok := m.byID[id.String()]; ok {
		k.Revoke(reason)
	}
	return nil
}
func (m *mockSensorAPIKeyRepo) CountActiveBySensorID(_ context.Context, sensorID shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, k := range m.byID {
		if k.SensorID == sensorID && k.IsActive {
			n++
		}
	}
	return n, nil
}

// retireKeys mirrors retireSensorKeys: active, non-revoked keys of the
// sensor other than except, expiry only brought forward. It returns the
// previous expiries so a failed rotation can be rolled back.
func (m *mockSensorAPIKeyRepo) retireKeys(sensorID shared.ID, except *shared.ID, at time.Time) map[string]*time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := map[string]*time.Time{}
	for id, k := range m.byID {
		if k.SensorID != sensorID || !k.IsActive || k.RevokedAt != nil || (except != nil && k.ID == *except) {
			continue
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.After(at) {
			continue
		}
		prev[id] = k.ExpiresAt
		t := at
		k.ExpiresAt = &t
	}
	return prev
}

func (m *mockSensorAPIKeyRepo) restore(prev map[string]*time.Time, drop *shared.ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, exp := range prev {
		if k, ok := m.byID[id]; ok {
			k.ExpiresAt = exp
		}
	}
	if drop != nil {
		delete(m.byID, drop.String())
	}
}

// lockedState mirrors lockSensorKeys: the sensor's status and inline key as
// read under the sensor's lock.
func (m *mockSensorAPIKeyRepo) lockedState(ctx context.Context, sensorID shared.ID) (sensor.SensorStatus, string, *time.Time, error) {
	a, err := m.sensors.GetByID(ctx, sensorID)
	if err != nil {
		return "", "", nil, sensor.ErrSensorNotFound
	}
	return a.Status, a.APIKeyHash, a.InlineKeyExpiresAt, nil
}

// checkPresented mirrors checkPresentedKey: under the lock, the presented
// key row must still be the sensor's, active, unrevoked and unexpired, or
// the inline hash still the presented key's and unexpired.
func (m *mockSensorAPIKeyRepo) checkPresented(sensorID shared.ID, inlineHash string, inlineExpires *time.Time, p sensor.PresentedKey) error {
	if p.KeyID == nil {
		if inlineHash == "" || !slices.Contains(p.InlineKeyHashes, inlineHash) {
			return sensor.ErrPresentedKeyInvalid
		}
		if inlineExpires != nil && !inlineExpires.After(p.At) {
			return sensor.ErrPresentedKeyInvalid
		}
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.byID[p.KeyID.String()]
	if !ok || k.SensorID != sensorID || !k.IsActive || k.RevokedAt != nil ||
		(k.ExpiresAt != nil && !k.ExpiresAt.After(p.At)) {
		return sensor.ErrPresentedKeyInvalid
	}
	return nil
}

// RotateKey mirrors the SQL transaction: under the sensor's lock, re-check
// the sensor's status and the presented key, issue the key, retire every
// other active key, retire the inline key by hash; a failure undoes it all.
func (m *mockSensorAPIKeyRepo) RotateKey(ctx context.Context, key *sensor.APIKey, presented sensor.PresentedKey, inlineKeyHashes []string, retireAt time.Time) error {
	m.runBeforeRotate()
	defer m.lockSensor(key.SensorID)()
	status, inlineHash, inlineExpires, err := m.lockedState(ctx, key.SensorID)
	if err != nil {
		return err
	}
	switch status {
	case sensor.SensorStatusActive:
	case sensor.SensorStatusRevoked:
		return sensor.ErrSensorRevoked
	default:
		return sensor.ErrSensorDisabled
	}
	if err := m.checkPresented(key.SensorID, inlineHash, inlineExpires, presented); err != nil {
		return err
	}
	if err := m.Create(ctx, key); err != nil {
		return err
	}
	prev := m.retireKeys(key.SensorID, &key.ID, retireAt)
	if len(inlineKeyHashes) > 0 && m.sensors != nil {
		if _, err := m.sensors.RetireInlineKey(ctx, key.SensorID, inlineKeyHashes, retireAt); err != nil {
			m.restore(prev, &key.ID)
			return err
		}
	}
	return nil
}

// ReplaceInlineKey mirrors the SQL transaction: under the sensor's lock,
// re-check the presented key, replace the inline key (active sensors only),
// then retire every key row.
func (m *mockSensorAPIKeyRepo) ReplaceInlineKey(ctx context.Context, sensorID shared.ID, presented sensor.PresentedKey, hash, prefix string, expiresAt *time.Time, retireAt time.Time) (bool, error) {
	m.runBeforeRotate()
	defer m.lockSensor(sensorID)()
	status, inlineHash, inlineExpires, err := m.lockedState(ctx, sensorID)
	if err != nil || status != sensor.SensorStatusActive {
		return false, nil
	}
	if err := m.checkPresented(sensorID, inlineHash, inlineExpires, presented); err != nil {
		return false, err
	}
	updated, err := m.sensors.UpdateAPIKey(ctx, sensorID, hash, prefix, expiresAt, true)
	if err != nil || !updated {
		return false, err
	}
	m.retireKeys(sensorID, nil, retireAt)
	return true, nil
}

// RegenerateKey mirrors the SQL transaction: under the sensor's lock,
// install the inline key (no expiry, any status) and revoke every active key
// row.
func (m *mockSensorAPIKeyRepo) RegenerateKey(ctx context.Context, sensorID shared.ID, hash, prefix, reason string) (bool, error) {
	defer m.lockSensor(sensorID)()
	updated, err := m.sensors.UpdateAPIKey(ctx, sensorID, hash, prefix, nil, false)
	if err != nil || !updated {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.byID {
		if k.SensorID == sensorID && k.IsActive {
			k.Revoke(reason)
		}
	}
	return true, nil
}

// Renew under a TTL with the multi-key store issues a NEW key row that
// authenticates, while the old inline key keeps working during the overlap.
func TestSensorService_RenewAPIKey_Overlap(t *testing.T) {
	repo := newSensorSvcMockRepo()
	keyRepo := newMockSensorAPIKeyRepo(repo)
	svc := newSensorSvcTestService(repo)
	svc.SetKeyTTL(1 * time.Hour)
	svc.SetAPIKeyRepository(keyRepo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(), Name: "overlap-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	oldKey := out.APIKey

	newKey, exp, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: out.Sensor})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if exp == nil {
		t.Fatal("expected an expiry under TTL")
	}
	// The new key was issued as a key row (not an inline-hash replacement).
	if n, _ := keyRepo.CountActiveBySensorID(context.Background(), out.Sensor.ID); n != 1 {
		t.Errorf("expected 1 key row after overlap renewal, got %d", n)
	}
	// New key authenticates via the key row.
	if _, err := svc.AuthenticateByAPIKey(context.Background(), newKey); err != nil {
		t.Errorf("expected the new key to authenticate via the key row, got %v", err)
	}
	// Old inline key still works during the overlap grace window.
	if _, err := svc.AuthenticateByAPIKey(context.Background(), oldKey); err != nil {
		t.Errorf("expected the old inline key to still work during overlap, got %v", err)
	}
}

// Regression (RFC-014 defect): the inline bootstrap key's retirement must not
// be pushed forward by later renewals. A prior guard (!IsKeyExpired) re-ran
// the retirement on every renewal that landed before the grace lapsed and
// kept the original static key alive forever under short TTLs. Retirement
// now only ever brings an expiry earlier.
func TestSensorService_RenewAPIKey_Overlap_RetiresInlineKeyOnce(t *testing.T) {
	repo := newSensorSvcMockRepo()
	keyRepo := newMockSensorAPIKeyRepo(repo)
	svc := newSensorSvcTestService(repo)
	svc.SetKeyTTL(1 * time.Hour)
	svc.SetAPIKeyRepository(keyRepo)
	tenantID := shared.NewID()

	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: tenantID.String(), Name: "retire-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	// Renew several times, each before the grace would lapse.
	var first time.Time
	for i := 0; i < 3; i++ {
		if _, _, err := svc.RenewAPIKey(context.Background(), sensorapp.SensorIdentity{Sensor: out.Sensor}); err != nil {
			t.Fatalf("renew %d: %v", i, err)
		}
		if i == 0 {
			first = *repo.sensors[out.Sensor.ID.String()].InlineKeyExpiresAt
		}
		time.Sleep(2 * time.Millisecond)
	}

	stored := repo.sensors[out.Sensor.ID.String()]
	if stored.InlineKeyExpiresAt == nil {
		t.Fatal("expected inline key to have an expiry after overlap renewal")
	}
	if !stored.InlineKeyExpiresAt.Equal(first) {
		t.Errorf("inline retirement re-extended: first %v, now %v", first, *stored.InlineKeyExpiresAt)
	}
	// And the retirement grace is bounded (≤ ~15m out), not pushed to a full TTL.
	if time.Until(*stored.InlineKeyExpiresAt) > 20*time.Minute {
		t.Errorf("inline expiry pushed too far out (%v) — retirement re-extended?", time.Until(*stored.InlineKeyExpiresAt))
	}
}

// ---- Renewal retires the presented key ----

// defaultRenewGrace is SENSOR_KEY_RENEW_GRACE's default.
const defaultRenewGrace = 15 * time.Minute

// renewFixture is a sensor under rotation overlap (1 day TTL), with its
// bootstrap (inline) key.
type renewFixture struct {
	t       *testing.T
	repo    *sensorSvcMockRepo
	keyRepo *mockSensorAPIKeyRepo
	svc     *sensorapp.SensorService
	sensor  *sensor.Sensor
	inline  string
}

func newRenewFixture(t *testing.T) *renewFixture {
	t.Helper()
	repo := newSensorSvcMockRepo()
	keyRepo := newMockSensorAPIKeyRepo(repo)
	svc := newSensorSvcTestService(repo)
	svc.SetKeyTTL(24 * time.Hour)
	svc.SetAPIKeyRepository(keyRepo)
	out, err := svc.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: shared.NewID().String(), Name: "renew-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	return &renewFixture{t: t, repo: repo, keyRepo: keyRepo, svc: svc, sensor: out.Sensor, inline: out.APIKey}
}

// renew authenticates with key, as the HTTP layer does, and renews with
// that identity.
func (f *renewFixture) renew(key string) string {
	f.t.Helper()
	id, err := f.svc.AuthenticateIdentity(context.Background(), key)
	if err != nil {
		f.t.Fatalf("authenticate before renew: %v", err)
	}
	next, _, err := f.svc.RenewAPIKey(context.Background(), id)
	if err != nil {
		f.t.Fatalf("renew: %v", err)
	}
	return next
}

func (f *renewFixture) works(key string) bool {
	_, err := f.svc.AuthenticateIdentity(context.Background(), key)
	return err == nil
}

// longLived counts the credentials that still authenticate an hour from now.
func (f *renewFixture) longLived() int {
	horizon := time.Now().Add(time.Hour)
	n := 0
	f.keyRepo.mu.Lock()
	for _, k := range f.keyRepo.byID {
		if k.SensorID == f.sensor.ID && k.IsActive && (k.ExpiresAt == nil || k.ExpiresAt.After(horizon)) {
			n++
		}
	}
	f.keyRepo.mu.Unlock()
	f.repo.mu.Lock()
	if a := f.repo.sensors[f.sensor.ID.String()]; a.InlineKeyExpiresAt == nil || a.InlineKeyExpiresAt.After(horizon) {
		n++
	}
	f.repo.mu.Unlock()
	return n
}

// The key a sensor renewed with keeps working through the grace (in-flight
// requests) and stops after it; the new key works.
func TestSensorService_RenewAPIKey_PresentedKeyExpiresAfterGrace(t *testing.T) {
	f := newRenewFixture(t)
	f.svc.SetRenewGrace(30 * time.Millisecond)

	k1 := f.renew(f.inline)
	if !f.works(k1) {
		t.Fatal("the new key must authenticate")
	}
	if !f.works(f.inline) {
		t.Fatal("the presented key must keep working within the grace")
	}
	k2 := f.renew(k1) // presented: a sensor_api_keys row
	if !f.works(k1) {
		t.Fatal("the presented row key must keep working within the grace")
	}

	time.Sleep(60 * time.Millisecond)
	if f.works(f.inline) {
		t.Error("the inline key renewed away still authenticates after the grace")
	}
	if f.works(k1) {
		t.Error("the row key renewed away still authenticates after the grace")
	}
	if !f.works(k2) {
		t.Error("the latest key must keep working")
	}
}

// The default grace is 15 minutes, and the presented key is capped to it —
// not left valid until its own (one day) expiry.
func TestSensorService_RenewAPIKey_PresentedRowCappedToGrace(t *testing.T) {
	f := newRenewFixture(t)
	k1 := f.renew(f.inline)
	id1, err := f.svc.AuthenticateIdentity(context.Background(), k1)
	if err != nil || id1.KeyID == nil {
		t.Fatalf("k1 must authenticate as a key row: %v", err)
	}
	f.renew(k1)
	got, _ := f.keyRepo.GetByID(context.Background(), *id1.KeyID)
	if got.ExpiresAt == nil || time.Until(*got.ExpiresAt) > defaultRenewGrace+time.Minute {
		t.Fatalf("presented key expires at %v, want within the %v grace", got.ExpiresAt, defaultRenewGrace)
	}
}

// A stolen key cannot fork the credential: renewing twice with the same key
// (the sensor and whoever copied it) leaves one long-lived key, the latest.
func TestSensorService_RenewAPIKey_TwiceWithSameKey_OneSuccessor(t *testing.T) {
	f := newRenewFixture(t)
	f.svc.SetRenewGrace(30 * time.Millisecond)

	attacker := f.renew(f.inline)
	legit := f.renew(f.inline) // still within the grace
	if n := f.longLived(); n != 1 {
		t.Fatalf("%d long-lived credentials after two renewals with one key, want 1", n)
	}
	time.Sleep(60 * time.Millisecond)
	if f.works(attacker) {
		t.Error("the earlier successor still authenticates after the grace")
	}
	if !f.works(legit) {
		t.Error("the latest successor must keep working")
	}
}

// Renewing with key K2 retires K2 and keeps the new key: the presented
// credential is identified, not guessed.
func TestSensorService_RenewAPIKey_RetiresWhatWasPresented(t *testing.T) {
	f := newRenewFixture(t)
	k1 := f.renew(f.inline)
	inlineExp := *f.repo.sensors[f.sensor.ID.String()].InlineKeyExpiresAt

	id1, _ := f.svc.AuthenticateIdentity(context.Background(), k1)
	k2 := f.renew(k1)
	id2, err := f.svc.AuthenticateIdentity(context.Background(), k2)
	if err != nil || id2.KeyID == nil {
		t.Fatalf("k2 must authenticate as a key row: %v", err)
	}
	r1, _ := f.keyRepo.GetByID(context.Background(), *id1.KeyID)
	r2, _ := f.keyRepo.GetByID(context.Background(), *id2.KeyID)
	if r1.ExpiresAt == nil || time.Until(*r1.ExpiresAt) > defaultRenewGrace+time.Minute {
		t.Errorf("presented key K1 not retired: expires %v", r1.ExpiresAt)
	}
	if r2.ExpiresAt == nil || time.Until(*r2.ExpiresAt) < 23*time.Hour {
		t.Errorf("new key K2 was retired: expires %v", r2.ExpiresAt)
	}
	if got := *f.repo.sensors[f.sensor.ID.String()].InlineKeyExpiresAt; !got.Equal(inlineExp) {
		t.Errorf("the inline key's retirement moved from %v to %v", inlineExp, got)
	}
	if n := f.longLived(); n != 1 {
		t.Errorf("%d long-lived credentials, want 1", n)
	}
}

// An admin regeneration landing between authentication and renewal installs
// another inline key. The renewal, presenting the replaced key, is refused,
// and the regenerated key is neither cut short nor replaced.
func TestSensorService_RenewAPIKey_DoesNotRetireAdminRegeneratedKey(t *testing.T) {
	f := newRenewFixture(t)
	id, err := f.svc.AuthenticateIdentity(context.Background(), f.inline)
	if err != nil {
		t.Fatal(err)
	}
	adminKey, err := f.svc.RegenerateAPIKey(context.Background(), f.sensor.TenantID.String(), f.sensor.ID.String(), nil)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if _, _, err := f.svc.RenewAPIKey(context.Background(), id); !errors.Is(err, shared.ErrUnauthorized) {
		t.Fatalf("renew with the replaced key: err = %v, want unauthorized", err)
	}
	if exp := f.repo.sensors[f.sensor.ID.String()].InlineKeyExpiresAt; exp != nil {
		t.Errorf("the admin-regenerated inline key was given an expiry %v", exp)
	}
	if !f.works(adminKey) {
		t.Error("the admin-regenerated key must keep working")
	}
}

// Without a TTL the renewal replaces the inline key; key rows issued earlier
// under a TTL (the presented one among them) are retired too.
func TestSensorService_RenewAPIKey_NoTTL_RetiresKeyRows(t *testing.T) {
	f := newRenewFixture(t)
	k1 := f.renew(f.inline)
	f.svc.SetKeyTTL(0)
	f.svc.SetRenewGrace(0)
	k2 := f.renew(k1)
	if f.works(k1) {
		t.Error("the presented key row still authenticates after a no-TTL renewal")
	}
	if !f.works(k2) {
		t.Error("the new inline key must authenticate")
	}
}

// Concurrent renewals with one presented key end with one long-lived key.
func TestSensorService_RenewAPIKey_Concurrent_OneSuccessor(t *testing.T) {
	f := newRenewFixture(t)
	id, err := f.svc.AuthenticateIdentity(context.Background(), f.inline)
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := f.svc.RenewAPIKey(context.Background(), id); err != nil {
				t.Errorf("renew: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := f.longLived(); got != 1 {
		t.Fatalf("%d concurrent renewals left %d long-lived credentials, want 1", n, got)
	}
}

// A renewal whose retirement write fails is refused: the sensor keeps its old
// key and retries, rather than hold a new key while the old one lives on.
func TestSensorService_RenewAPIKey_RetireFailureFailsRenewal(t *testing.T) {
	f := newRenewFixture(t)
	id, err := f.svc.AuthenticateIdentity(context.Background(), f.inline)
	if err != nil {
		t.Fatal(err)
	}
	f.repo.updateErr = errors.New("db down")
	if _, _, err := f.svc.RenewAPIKey(context.Background(), id); err == nil {
		t.Fatal("expected the renewal to fail when the presented key cannot be retired")
	}
}

// An expired key row does not authenticate.
func TestSensorService_AuthenticateByAPIKey_ExpiredKeyRow(t *testing.T) {
	repo := newSensorSvcMockRepo()
	keyRepo := newMockSensorAPIKeyRepo(repo)
	svc := newSensorSvcTestService(repo)
	svc.SetAPIKeyRepository(keyRepo)
	tenantID := shared.NewID()
	a := repo.seedSensor(tenantID, "sensor-1", sensor.SensorTypeWorker)

	// Seed an expired, active key row whose hash matches a known plaintext.
	plaintext := "rda_rowkey_expired_000000000000"
	k, _ := sensor.NewAPIKey(a.ID, "expired", sensor.WorkerScopes())
	k.SetKeyHash(hashForTest(svc, plaintext), "rda_expired0")
	past := time.Now().Add(-time.Hour)
	k.SetExpiration(past)
	_ = keyRepo.Create(context.Background(), k)

	if _, err := svc.AuthenticateByAPIKey(context.Background(), plaintext); err == nil {
		t.Fatal("expected expired key row to be rejected")
	}
}

// hashForTest reproduces the service's key-hash (no pepper configured in tests).
func hashForTest(_ *sensorapp.SensorService, plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func (m *sensorSvcMockRepo) KnownCapabilityNames(_ context.Context, _ *shared.ID, tools, caps []string) (map[string]bool, map[string]bool, error) {
	if m.knownErr != nil {
		return nil, nil, m.knownErr
	}
	kt, kc := map[string]bool{}, map[string]bool{}
	for _, t := range tools {
		if m.knownTools[t] {
			kt[t] = true
		}
	}
	for _, c := range caps {
		if m.knownCaps[c] {
			kc[c] = true
		}
	}
	return kt, kc, nil
}

// RehashKey makes the mock an app.KeyRehasher for the inline key.
func (m *sensorSvcMockRepo) RehashKey(_ context.Context, id shared.ID, oldHash, newHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.sensors[id.String()]
	if !ok || a.APIKeyHash != oldHash {
		return false, nil
	}
	a.APIKeyHash = newHash
	return true, nil
}

func (m *sensorSvcMockRepo) CountKeysNotUnderPepper(context.Context) (int, error) { return 0, nil }

// A sensor key that authenticates through a rotated-out pepper is re-hashed
// with the current pepper and keeps authenticating once the previous key is
// removed (APP_ENCRYPTION_KEY_PREVIOUS).
func TestSensorService_PreviousPepperKeyIsRehashed(t *testing.T) {
	repo := newSensorSvcMockRepo()
	old := newSensorSvcTestService(repo)
	old.SetPepper("old-pepper")
	out, err := old.CreateSensor(context.Background(), sensorapp.CreateSensorInput{
		TenantID: shared.NewID().String(), Name: "pre-rotation", Type: "worker",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rotated := newSensorSvcTestService(repo)
	rotated.SetPepper("new-pepper")
	rotated.SetLegacyPeppers("old-pepper")
	if _, err := rotated.AuthenticateByAPIKey(context.Background(), out.APIKey); err != nil {
		t.Fatalf("authenticate through the previous pepper: %v", err)
	}

	after := newSensorSvcTestService(repo)
	after.SetPepper("new-pepper")
	if _, err := after.AuthenticateByAPIKey(context.Background(), out.APIKey); err != nil {
		t.Fatalf("a re-hashed key must authenticate without the previous pepper: %v", err)
	}
}
