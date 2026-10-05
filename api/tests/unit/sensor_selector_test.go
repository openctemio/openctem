package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	sensorsvc "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// =============================================================================
// Mock: sensor.Repository (prefixed with sensorSel)
// =============================================================================

// sensorSelMockSensorRepo implements sensor.Repository for SensorSelector tests.
type sensorSelMockSensorRepo struct {
	// Return values for FindAvailableWithCapacity
	availableSensors []*sensor.Sensor
	availableErr     error

	// Capture args from FindAvailableWithCapacity calls
	lastTenantID     shared.ID
	lastCapabilities []string
	lastTool         string
	callCount        int
}

func newSensorSelMockSensorRepo() *sensorSelMockSensorRepo {
	return &sensorSelMockSensorRepo{}
}

func (m *sensorSelMockSensorRepo) FindAvailableWithCapacity(_ context.Context, tenantID shared.ID, capabilities []string, tool string) ([]*sensor.Sensor, error) {
	m.lastTenantID = tenantID
	m.lastCapabilities = capabilities
	m.lastTool = tool
	m.callCount++
	return m.availableSensors, m.availableErr
}

// Stub all other Repository methods to satisfy the interface.

func (m *sensorSelMockSensorRepo) Create(_ context.Context, _ *sensor.Sensor) error { return nil }
func (m *sensorSelMockSensorRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *sensorSelMockSensorRepo) GetByID(_ context.Context, _ shared.ID) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) GetByAPIKeyHash(_ context.Context, _ string) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) List(_ context.Context, _ sensor.Filter, _ pagination.Pagination) (pagination.Result[*sensor.Sensor], error) {
	return pagination.Result[*sensor.Sensor]{}, nil
}
func (m *sensorSelMockSensorRepo) Update(_ context.Context, _ *sensor.Sensor) error { return nil }
func (m *sensorSelMockSensorRepo) RetireInlineKey(_ context.Context, _ shared.ID, _ []string, _ time.Time) (bool, error) {
	return false, nil
}
func (m *sensorSelMockSensorRepo) UpdateHeartbeat(_ context.Context, _ shared.ID, _ sensor.HeartbeatUpdate) (bool, error) {
	return true, nil
}
func (m *sensorSelMockSensorRepo) UpdateAPIKey(_ context.Context, _ shared.ID, _, _ string, _ *time.Time, _ bool) (bool, error) {
	return true, nil
}
func (m *sensorSelMockSensorRepo) Delete(_ context.Context, _ shared.ID) error { return nil }
func (m *sensorSelMockSensorRepo) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *sensorSelMockSensorRepo) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}
func (m *sensorSelMockSensorRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *sensorSelMockSensorRepo) ClaimJob(_ context.Context, _ shared.ID) error   { return nil }
func (m *sensorSelMockSensorRepo) ReleaseJob(_ context.Context, _ shared.ID) error { return nil }
func (m *sensorSelMockSensorRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *sensorSelMockSensorRepo) MarkStaleSensorsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) GetSensorsOfflineSince(_ context.Context, _ time.Time) ([]*sensor.Sensor, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) HasSensorForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *sensorSelMockSensorRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) HasSensorForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *sensorSelMockSensorRepo) GetPlatformSensorStats(_ context.Context, _ shared.ID) (*sensor.PlatformSensorStatsResult, error) {
	return nil, nil
}
func (m *sensorSelMockSensorRepo) GetTenantSensorStats(_ context.Context, _ shared.ID) (*sensor.TenantSensorStats, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

// makeSensorSelSensor builds a minimal *sensor.Sensor with the given load values.
func makeSensorSelSensor(name string, currentJobs, maxJobs int) *sensor.Sensor {
	tenantID := shared.NewID()
	return &sensor.Sensor{
		ID:                shared.NewID(),
		TenantID:          &tenantID,
		Name:              name,
		Type:              sensor.SensorTypeWorker,
		Status:            sensor.SensorStatusActive,
		Health:            sensor.SensorHealthOnline,
		CurrentJobs:       currentJobs,
		MaxConcurrentJobs: maxJobs,
		Capabilities:      []string{},
		Tools:             []string{},
	}
}

// newSensorSelector creates a SensorSelector wired to the mock repo.
// commandRepo and sensorState are nil because the current implementation does
// not use them in SelectSensor / CheckSensorAvailability.
func newSensorSelSelector(repo *sensorSelMockSensorRepo) *sensorsvc.SensorSelector {
	log := logger.NewNop()
	return sensorsvc.NewSensorSelector(repo, nil, nil, log)
}

// =============================================================================
// Tests: SelectSensor
// =============================================================================

// TestSensorSelSelectSensor_SingleSensor verifies that the only available sensor
// is returned when exactly one is present.
func TestSensorSelSelectSensor_SingleSensor(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	a := makeSensorSelSensor("alpha", 1, 5)
	repo.availableSensors = []*sensor.Sensor{a}

	sel := newSensorSelSelector(repo)

	tenantID := shared.NewID()
	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: tenantID,
		Mode:     sensorsvc.SelectTenantOnly,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Sensor == nil {
		t.Fatal("expected sensor to be set")
	}
	if result.Sensor.ID != a.ID {
		t.Errorf("expected sensor %s, got %s", a.ID, result.Sensor.ID)
	}
	if result.Queued {
		t.Error("expected Queued=false")
	}
}

// TestSensorSelSelectSensor_MultipleSensors_LeastLoaded verifies that among
// multiple sensors the one with the lowest load ratio is chosen.
func TestSensorSelSelectSensor_MultipleSensors_LeastLoaded(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	// high: 4/5 = 80% load
	high := makeSensorSelSensor("high-load", 4, 5)
	// low: 1/5 = 20% load — should be selected
	low := makeSensorSelSensor("low-load", 1, 5)
	// mid: 3/5 = 60% load
	mid := makeSensorSelSensor("mid-load", 3, 5)

	repo.availableSensors = []*sensor.Sensor{high, low, mid}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
		Mode:     sensorsvc.SelectTenantOnly,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor == nil {
		t.Fatal("expected sensor to be set")
	}
	if result.Sensor.ID != low.ID {
		t.Errorf("expected least-loaded sensor %q, got %q", low.Name, result.Sensor.Name)
	}
}

// TestSensorSelSelectSensor_NoSensors_Error verifies that ErrNoSensorAvailable is
// returned when no sensors are available and AllowQueue is false.
func TestSensorSelSelectSensor_NoSensors_Error(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{} // none

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID:   shared.NewID(),
		Mode:       sensorsvc.SelectTenantOnly,
		AllowQueue: false,
	})

	if result != nil {
		t.Error("expected nil result")
	}
	if !errors.Is(err, sensorsvc.ErrNoSensorAvailable) {
		t.Errorf("expected ErrNoSensorAvailable, got %v", err)
	}
}

// TestSensorSelSelectSensor_NoSensors_AllowQueue verifies that when AllowQueue is
// true and no sensors are available, a queued result is returned without error.
func TestSensorSelSelectSensor_NoSensors_AllowQueue(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID:   shared.NewID(),
		Mode:       sensorsvc.SelectTenantOnly,
		AllowQueue: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.Queued {
		t.Error("expected Queued=true")
	}
	if result.Sensor != nil {
		t.Error("expected Sensor to be nil when queued")
	}
	if result.Message == "" {
		t.Error("expected a non-empty message in queued result")
	}
}

// TestSensorSelSelectSensor_RepoError verifies that repository errors are
// propagated back to the caller.
func TestSensorSelSelectSensor_RepoError(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repoErr := errors.New("db connection lost")
	repo.availableErr = repoErr

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if result != nil {
		t.Error("expected nil result on error")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected wrapped repo error, got %v", err)
	}
}

// TestSensorSelSelectSensor_PassesToolAndCapabilities verifies that the
// Capabilities and Tool fields are forwarded to the repository.
func TestSensorSelSelectSensor_PassesToolAndCapabilities(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	a := makeSensorSelSensor("sensor-with-tool", 0, 5)
	repo.availableSensors = []*sensor.Sensor{a}

	sel := newSensorSelSelector(repo)

	wantCaps := []string{"sast", "sca"}
	wantTool := "semgrep"

	_, _ = sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID:     shared.NewID(),
		Capabilities: wantCaps,
		Tool:         wantTool,
		Mode:         sensorsvc.SelectTenantOnly,
	})

	if repo.lastTool != wantTool {
		t.Errorf("expected tool=%q forwarded to repo, got %q", wantTool, repo.lastTool)
	}
	if len(repo.lastCapabilities) != len(wantCaps) {
		t.Errorf("expected %d capabilities, got %d", len(wantCaps), len(repo.lastCapabilities))
	}
	for i, c := range wantCaps {
		if repo.lastCapabilities[i] != c {
			t.Errorf("capability[%d]: want %q, got %q", i, c, repo.lastCapabilities[i])
		}
	}
}

// TestSensorSelSelectSensor_CorrectTenantID verifies the TenantID is forwarded
// to the repository unchanged.
func TestSensorSelSelectSensor_CorrectTenantID(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	a := makeSensorSelSensor("worker", 0, 5)
	repo.availableSensors = []*sensor.Sensor{a}

	sel := newSensorSelSelector(repo)

	tenantID := shared.NewID()
	_, _ = sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: tenantID,
	})

	if repo.lastTenantID != tenantID {
		t.Errorf("expected tenantID=%s, got %s", tenantID, repo.lastTenantID)
	}
}

// TestSensorSelSelectSensor_EqualLoad verifies that when two sensors have the
// same load the first encountered is returned (stable selection).
func TestSensorSelSelectSensor_EqualLoad(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	first := makeSensorSelSensor("first", 2, 4)   // 50% load
	second := makeSensorSelSensor("second", 2, 4) // 50% load

	repo.availableSensors = []*sensor.Sensor{first, second}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With equal loads, the first sensor in the slice should be selected
	// because the implementation starts bestLoad at 1.0 (100%) and the first
	// sensor with load < 1.0 wins; subsequent equal-load sensors do not replace.
	if result.Sensor.ID != first.ID {
		t.Errorf("expected first sensor to win on equal load, got %s", result.Sensor.Name)
	}
}

// TestSensorSelSelectSensor_SensorWithUnlimitedCapacity verifies that a sensor
// with MaxConcurrentJobs == 0 (no limit) is returned immediately.
func TestSensorSelSelectSensor_SensorWithUnlimitedCapacity(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	unlimited := makeSensorSelSensor("unlimited", 0, 0) // MaxConcurrentJobs = 0 → no limit
	heavy := makeSensorSelSensor("heavy", 4, 5)

	// unlimited is listed second; because it has MaxConcurrentJobs == 0 the
	// implementation returns it immediately when encountered.
	repo.availableSensors = []*sensor.Sensor{heavy, unlimited}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor == nil {
		t.Fatal("expected sensor to be set")
	}
	if result.Sensor.ID != unlimited.ID {
		t.Errorf("expected unlimited-capacity sensor, got %s", result.Sensor.Name)
	}
}

// TestSensorSelSelectSensor_AllFullyLoaded verifies that if every sensor has
// load == 1.0 (CurrentJobs == MaxConcurrentJobs) no sensor is selected and
// the result sensor is nil (because none beat the 100% threshold).
func TestSensorSelSelectSensor_AllFullyLoaded(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	// Three sensors all at 100% capacity
	a1 := makeSensorSelSensor("a1", 5, 5)
	a2 := makeSensorSelSensor("a2", 3, 3)
	a3 := makeSensorSelSensor("a3", 10, 10)
	repo.availableSensors = []*sensor.Sensor{a1, a2, a3}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	// The implementation starts bestLoad at 1.0 and uses strict < so a fully
	// loaded sensor (load == 1.0) will never be selected; best remains nil.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil SelectSensorResult")
	}
	if result.Sensor != nil {
		t.Errorf("expected nil Sensor when all sensors are at 100%% load, got %s", result.Sensor.Name)
	}
}

// TestSensorSelSelectSensor_Message verifies that the result message is
// populated for a successful assignment.
func TestSensorSelSelectSensor_Message(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	a := makeSensorSelSensor("worker", 0, 5)
	repo.availableSensors = []*sensor.Sensor{a}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Message == "" {
		t.Error("expected non-empty message in result")
	}
}

// =============================================================================
// Tests: CheckSensorAvailability
// =============================================================================

// TestSensorSelCheckAvailability_TenantSensorAvailable verifies that when
// sensors exist the result shows availability.
func TestSensorSelCheckAvailability_TenantSensorAvailable(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{makeSensorSelSensor("worker", 1, 5)}

	sel := newSensorSelSelector(repo)

	result := sel.CheckSensorAvailability(context.Background(), shared.NewID(), "nuclei", true)

	if result == nil {
		t.Fatal("expected non-nil availability result")
	}
	if !result.HasTenantSensor {
		t.Error("expected HasTenantSensor=true")
	}
	if !result.Available {
		t.Error("expected Available=true")
	}
	if result.Message == "" {
		t.Error("expected non-empty message")
	}
}

// TestSensorSelCheckAvailability_NoSensorsAvailable verifies that the result
// shows unavailability when no sensors exist.
func TestSensorSelCheckAvailability_NoSensorsAvailable(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{}

	sel := newSensorSelSelector(repo)

	result := sel.CheckSensorAvailability(context.Background(), shared.NewID(), "nuclei", true)

	if result.HasTenantSensor {
		t.Error("expected HasTenantSensor=false")
	}
	if result.Available {
		t.Error("expected Available=false")
	}
	if result.Message == "" {
		t.Error("expected a non-empty message describing unavailability")
	}
}

// TestSensorSelCheckAvailability_RepoError verifies that repository errors
// cause HasTenantSensor to remain false (error is tolerated).
func TestSensorSelCheckAvailability_RepoError(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableErr = errors.New("connection refused")

	sel := newSensorSelSelector(repo)

	result := sel.CheckSensorAvailability(context.Background(), shared.NewID(), "trivy", false)

	if result == nil {
		t.Fatal("expected non-nil result even on repo error")
	}
	if result.HasTenantSensor {
		t.Error("expected HasTenantSensor=false on repo error")
	}
	if result.Available {
		t.Error("expected Available=false on repo error")
	}
}

// TestSensorSelCheckAvailability_ToolPassedToRepo verifies that the tool
// name is forwarded to the repository query.
func TestSensorSelCheckAvailability_ToolPassedToRepo(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{}

	sel := newSensorSelSelector(repo)

	wantTool := "semgrep"
	_ = sel.CheckSensorAvailability(context.Background(), shared.NewID(), wantTool, true)

	if repo.lastTool != wantTool {
		t.Errorf("expected tool=%q forwarded to repo, got %q", wantTool, repo.lastTool)
	}
}

// TestSensorSelCheckAvailability_TenantIDPassedToRepo verifies the tenant ID
// is forwarded to the repository query.
func TestSensorSelCheckAvailability_TenantIDPassedToRepo(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{}

	sel := newSensorSelSelector(repo)

	tenantID := shared.NewID()
	_ = sel.CheckSensorAvailability(context.Background(), tenantID, "nmap", false)

	if repo.lastTenantID != tenantID {
		t.Errorf("expected tenantID=%s, got %s", tenantID, repo.lastTenantID)
	}
}

// TestSensorSelCheckAvailability_MultipleSensors verifies that having multiple
// available sensors still reports a single available status.
func TestSensorSelCheckAvailability_MultipleSensors(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	repo.availableSensors = []*sensor.Sensor{
		makeSensorSelSensor("worker-1", 2, 5),
		makeSensorSelSensor("worker-2", 0, 5),
		makeSensorSelSensor("worker-3", 4, 5),
	}

	sel := newSensorSelSelector(repo)

	result := sel.CheckSensorAvailability(context.Background(), shared.NewID(), "trivy", true)

	if !result.HasTenantSensor {
		t.Error("expected HasTenantSensor=true with multiple sensors")
	}
	if !result.Available {
		t.Error("expected Available=true with multiple sensors")
	}
}

// =============================================================================
// Tests: selectLeastLoaded (exercised via SelectSensor)
// =============================================================================

// TestSensorSelLeastLoaded_ZeroCurrentJobs verifies that a sensor with no
// active jobs (load == 0%) beats one with higher load.
func TestSensorSelLeastLoaded_ZeroCurrentJobs(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	idle := makeSensorSelSensor("idle", 0, 5) // 0% load
	busy := makeSensorSelSensor("busy", 4, 5) // 80% load

	repo.availableSensors = []*sensor.Sensor{busy, idle}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor.ID != idle.ID {
		t.Errorf("expected idle sensor, got %s", result.Sensor.Name)
	}
}

// TestSensorSelLeastLoaded_SingleSensorPartialLoad verifies that a single
// sensor with a partial load is returned.
func TestSensorSelLeastLoaded_SingleSensorPartialLoad(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	a := makeSensorSelSensor("partial", 2, 5) // 40% load
	repo.availableSensors = []*sensor.Sensor{a}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor.ID != a.ID {
		t.Errorf("expected sensor %s, got %s", a.ID, result.Sensor.ID)
	}
}

// TestSensorSelLeastLoaded_MaxJobsOne verifies the boundary case where the
// max concurrent jobs is 1.
func TestSensorSelLeastLoaded_MaxJobsOne(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	empty := makeSensorSelSensor("empty", 0, 1) // 0% load
	full := makeSensorSelSensor("full", 1, 1)   // 100% load

	repo.availableSensors = []*sensor.Sensor{full, empty}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor.ID != empty.ID {
		t.Errorf("expected empty-slot sensor, got %s", result.Sensor.Name)
	}
}

// =============================================================================
// Tests: load-balancing weights actually reach scheduling
// =============================================================================

// withFreshMetrics stamps resource metrics on a sensor and marks them as just
// reported, so the selector treats them as trustworthy.
func withFreshMetrics(a *sensor.Sensor, cpu, mem float64) *sensor.Sensor {
	now := time.Now()
	a.CPUPercent = cpu
	a.MemoryPercent = mem
	a.MetricsUpdatedAt = &now
	return a
}

// TestSensorSelLoadBalancing_CPUBreaksJobLoadTie pins that sensor selection uses
// the reported resource metrics, not just the job-count ratio.
//
// Both sensors sit at the same 2/5 job load. The one pegged at 95% CPU must
// lose to the idle one. Before the load-balancing weights were wired in, the
// selector compared only CurrentJobs/MaxConcurrentJobs, so the tie was broken
// by slice order and CPU was ignored entirely.
func TestSensorSelLoadBalancing_CPUBreaksJobLoadTie(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	hot := withFreshMetrics(makeSensorSelSensor("hot", 2, 5), 95, 10)
	cool := withFreshMetrics(makeSensorSelSensor("cool", 2, 5), 5, 10)

	// hot is listed first: a job-ratio-only selector returns it.
	repo.availableSensors = []*sensor.Sensor{hot, cool}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor == nil {
		t.Fatal("expected a sensor to be selected")
	}
	if result.Sensor.ID != cool.ID {
		t.Errorf("selected %q (95%% CPU) over %q (5%% CPU) at identical job load; "+
			"CPU/memory metrics are not influencing scheduling", result.Sensor.Name, cool.Name)
	}
}

// TestSensorSelLoadBalancing_WeightsChangeSelection pins that the SENSOR_LB_*
// weights are the knob they claim to be: an operator who declares memory the
// dominant signal must get a different placement decision than one who
// declares CPU dominant, from identical sensor state.
func TestSensorSelLoadBalancing_WeightsChangeSelection(t *testing.T) {
	t.Parallel()

	// cpuHeavy: 90% CPU / 10% memory. memHeavy: 10% CPU / 90% memory.
	// Same job load, so only the weights decide.
	newPair := func() (*sensor.Sensor, *sensor.Sensor) {
		return withFreshMetrics(makeSensorSelSensor("cpu-heavy", 1, 5), 90, 10),
			withFreshMetrics(makeSensorSelSensor("mem-heavy", 1, 5), 10, 90)
	}

	selectWith := func(w sensor.LoadBalancingWeights) string {
		cpuHeavy, memHeavy := newPair()
		repo := newSensorSelMockSensorRepo()
		repo.availableSensors = []*sensor.Sensor{cpuHeavy, memHeavy}

		sel := newSensorSelSelector(repo)
		sel.SetLoadBalancingWeights(w)

		result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
			TenantID: shared.NewID(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Sensor == nil {
			t.Fatal("expected a sensor to be selected")
		}
		return result.Sensor.Name
	}

	// CPU dominant → avoid the CPU-heavy sensor.
	if got := selectWith(sensor.LoadBalancingWeights{JobLoad: 0.1, CPU: 0.9}); got != "mem-heavy" {
		t.Errorf("with CPU weighted 0.9 the CPU-heavy sensor should lose; selected %q", got)
	}

	// Memory dominant → avoid the memory-heavy sensor instead.
	if got := selectWith(sensor.LoadBalancingWeights{JobLoad: 0.1, Memory: 0.9}); got != "cpu-heavy" {
		t.Errorf("with memory weighted 0.9 the memory-heavy sensor should lose; selected %q; "+
			"SENSOR_LB_* weights do not affect scheduling", got)
	}
}

// TestSensorSelLoadBalancing_StaleMetricsIgnored pins the safety valve: an
// sensor whose last metrics report is ancient must be ranked on queue depth
// alone. Otherwise one bad CPU sample from a wedged sensor would bias
// scheduling forever, since nothing refreshes the row while it is stuck.
func TestSensorSelLoadBalancing_StaleMetricsIgnored(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()

	stale := makeSensorSelSensor("stale-but-idle", 0, 5)
	old := time.Now().Add(-2 * time.Hour)
	stale.CPUPercent = 99
	stale.MetricsUpdatedAt = &old

	busy := withFreshMetrics(makeSensorSelSensor("fresh-but-busy", 4, 5), 1, 1)

	repo.availableSensors = []*sensor.Sensor{busy, stale}

	sel := newSensorSelSelector(repo)

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor.ID != stale.ID {
		t.Errorf("selected %q; a two-hour-old 99%% CPU reading should not outweigh "+
			"an 80%% job queue", result.Sensor.Name)
	}
}

// TestSensorSelLoadBalancing_ZeroWeightsRejected pins that a misconfigured
// all-zero weight set is ignored rather than flattening every sensor's score to
// zero (which would make selection arbitrary).
func TestSensorSelLoadBalancing_ZeroWeightsRejected(t *testing.T) {
	t.Parallel()

	repo := newSensorSelMockSensorRepo()
	hot := withFreshMetrics(makeSensorSelSensor("hot", 2, 5), 95, 95)
	cool := withFreshMetrics(makeSensorSelSensor("cool", 2, 5), 1, 1)
	repo.availableSensors = []*sensor.Sensor{hot, cool}

	sel := newSensorSelSelector(repo)
	sel.SetLoadBalancingWeights(sensor.LoadBalancingWeights{}) // all zero

	result, err := sel.SelectSensor(context.Background(), sensorsvc.SelectSensorRequest{
		TenantID: shared.NewID(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Sensor.ID != cool.ID {
		t.Errorf("all-zero weights should fall back to the defaults, but selection "+
			"picked %q over the idle sensor", result.Sensor.Name)
	}
}

// =============================================================================
// Tests: mode constants
// =============================================================================

// TestSensorSelModeConstants verifies that the exported mode constants have
// the expected string values documented in the code.
func TestSensorSelModeConstants(t *testing.T) {
	t.Parallel()

	if sensorsvc.SelectTenantOnly != "tenant_only" {
		t.Errorf("SelectTenantOnly = %q, want %q", sensorsvc.SelectTenantOnly, "tenant_only")
	}
	if sensorsvc.SelectAny != "any" {
		t.Errorf("SelectAny = %q, want %q", sensorsvc.SelectAny, "any")
	}
}

// TestSensorSelErrNoSensorAvailable verifies that ErrNoSensorAvailable is
// exported and has a non-empty message.
func TestSensorSelErrNoSensorAvailable(t *testing.T) {
	t.Parallel()

	if sensorsvc.ErrNoSensorAvailable == nil {
		t.Fatal("ErrNoSensorAvailable should not be nil")
	}
	if sensorsvc.ErrNoSensorAvailable.Error() == "" {
		t.Error("ErrNoSensorAvailable should have a non-empty message")
	}
}

func (m *sensorSelMockSensorRepo) KnownCapabilityNames(_ context.Context, _ *shared.ID, _, _ []string) (map[string]bool, map[string]bool, error) {
	return map[string]bool{}, map[string]bool{}, nil
}
