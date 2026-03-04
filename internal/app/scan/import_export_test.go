package scan

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repository
// =============================================================================

// mockScanRepository implements scan.Repository for testing.
type mockScanRepository struct {
	scans map[string]*scan.Scan
}

func newMockScanRepository() *mockScanRepository {
	return &mockScanRepository{
		scans: make(map[string]*scan.Scan),
	}
}

func (m *mockScanRepository) Create(_ context.Context, s *scan.Scan) error {
	m.scans[s.ID.String()] = s
	return nil
}

func (m *mockScanRepository) GetByID(_ context.Context, id shared.ID) (*scan.Scan, error) {
	s, ok := m.scans[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *mockScanRepository) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scan.Scan, error) {
	s, ok := m.scans[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *mockScanRepository) GetByName(_ context.Context, tenantID shared.ID, name string) (*scan.Scan, error) {
	for _, s := range m.scans {
		if s.TenantID == tenantID && s.Name == name {
			return s, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockScanRepository) List(_ context.Context, _ scan.Filter, _ pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	return pagination.Result[*scan.Scan]{}, nil
}

func (m *mockScanRepository) Update(_ context.Context, s *scan.Scan) error {
	if _, ok := m.scans[s.ID.String()]; !ok {
		return shared.ErrNotFound
	}
	m.scans[s.ID.String()] = s
	return nil
}

func (m *mockScanRepository) Delete(_ context.Context, id shared.ID) error {
	if _, ok := m.scans[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.scans, id.String())
	return nil
}

func (m *mockScanRepository) ListDueForExecution(_ context.Context, _ time.Time) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *mockScanRepository) UpdateNextRunAt(_ context.Context, _ shared.ID, _ *time.Time) error {
	return nil
}

func (m *mockScanRepository) RecordRun(_ context.Context, _ shared.ID, _ shared.ID, _ string) error {
	return nil
}

func (m *mockScanRepository) GetStats(_ context.Context, _ shared.ID) (*scan.Stats, error) {
	return &scan.Stats{}, nil
}

func (m *mockScanRepository) Count(_ context.Context, _ scan.Filter) (int64, error) {
	return int64(len(m.scans)), nil
}

func (m *mockScanRepository) ListByAssetGroupID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *mockScanRepository) ListByPipelineID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *mockScanRepository) UpdateStatusByAssetGroupID(_ context.Context, _ shared.ID, _ scan.Status) error {
	return nil
}

// addScan is a test helper to insert a scan into the mock repository.
func (m *mockScanRepository) addScan(s *scan.Scan) {
	m.scans[s.ID.String()] = s
}

// =============================================================================
// Helper: create a minimal Service with only scanRepo (for export/import tests)
// =============================================================================

func newTestImportExportService(repo scan.Repository) *Service {
	log := logger.NewDevelopment()
	return &Service{
		scanRepo: repo,
		logger:   log.With("service", "scan-test"),
	}
}

// =============================================================================
// ExportConfig Tests
// =============================================================================

func TestExportConfig_HappyPath(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	assetGroupID := shared.NewID()

	sc, err := scan.NewScan(tenantID, "My Test Scan", assetGroupID, scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"
	sc.Description = "Test description"
	sc.Tags = []string{"web", "prod"}
	sc.Targets = []string{"example.com", "test.com"}
	sc.ScheduleTimezone = "UTC"
	sc.TargetsPerJob = 5
	sc.ScannerConfig = map[string]any{
		"severity": "critical",
		"rate":     100,
	}
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var export ScanConfigExport
	err = json.Unmarshal(data, &export)
	require.NoError(t, err)

	assert.Equal(t, "My Test Scan", export.Name)
	assert.Equal(t, "Test description", export.Description)
	assert.Equal(t, "single", export.ScanType)
	assert.Equal(t, "nuclei", export.ScannerName)
	assert.Equal(t, 5, export.TargetsPerJob)
	assert.Equal(t, []string{"web", "prod"}, export.Tags)
	assert.Equal(t, []string{"example.com", "test.com"}, export.Targets)
	assert.Equal(t, "UTC", export.ScheduleTimezone)
	assert.NotNil(t, export.ScannerConfig)
	assert.Equal(t, "critical", export.ScannerConfig["severity"])
}

func TestExportConfig_HasMetadata(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	sc, err := scan.NewScan(tenantID, "Export Metadata Test", shared.NewID(), scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	var export ScanConfigExport
	err = json.Unmarshal(data, &export)
	require.NoError(t, err)

	// Verify metadata fields
	assert.NotEmpty(t, export.ExportedAt, "exported_at should be populated")
	assert.Equal(t, configExportVersion, export.Version, "version should match configExportVersion")

	// Verify exported_at is a valid RFC3339 timestamp
	_, parseErr := time.Parse(time.RFC3339, export.ExportedAt)
	assert.NoError(t, parseErr, "exported_at should be valid RFC3339 format")
}

func TestExportConfig_ExcludesRuntimeData(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	sc, err := scan.NewScan(tenantID, "Runtime Exclusion Test", shared.NewID(), scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"

	// Set runtime data that should NOT be exported
	runID := shared.NewID()
	sc.RecordRun(runID, "completed")
	sc.TotalRuns = 42
	sc.SuccessfulRuns = 40
	sc.FailedRuns = 2
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	// Parse as raw JSON map to check for unexpected fields
	var rawMap map[string]any
	err = json.Unmarshal(data, &rawMap)
	require.NoError(t, err)

	// Runtime fields should NOT be present in the export
	assert.NotContains(t, rawMap, "status", "status should not be exported")
	assert.NotContains(t, rawMap, "last_run_id", "last_run_id should not be exported")
	assert.NotContains(t, rawMap, "last_run_at", "last_run_at should not be exported")
	assert.NotContains(t, rawMap, "last_run_status", "last_run_status should not be exported")
	assert.NotContains(t, rawMap, "total_runs", "total_runs should not be exported")
	assert.NotContains(t, rawMap, "successful_runs", "successful_runs should not be exported")
	assert.NotContains(t, rawMap, "failed_runs", "failed_runs should not be exported")
	assert.NotContains(t, rawMap, "created_at", "created_at should not be exported")
	assert.NotContains(t, rawMap, "updated_at", "updated_at should not be exported")
}

func TestExportConfig_ScanNotFound(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	nonExistentID := shared.NewID()

	data, err := svc.ExportConfig(context.Background(), tenantID, nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.ErrorIs(t, err, shared.ErrNotFound)
}

func TestExportConfig_WrongTenant(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantA := shared.NewID()
	tenantB := shared.NewID()

	sc, err := scan.NewScan(tenantA, "Tenant A Scan", shared.NewID(), scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"
	repo.addScan(sc)

	// Try to export with wrong tenant ID
	data, err := svc.ExportConfig(context.Background(), tenantB, sc.ID)
	assert.Error(t, err)
	assert.Nil(t, data)
}

func TestExportConfig_AssetGroupIDsConverted(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	primaryGroup := shared.NewID()

	sc, err := scan.NewScan(tenantID, "Multi Group Scan", primaryGroup, scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"

	group2 := shared.NewID()
	group3 := shared.NewID()
	sc.AssetGroupIDs = []shared.ID{group2, group3}
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	var export ScanConfigExport
	err = json.Unmarshal(data, &export)
	require.NoError(t, err)

	// Should include primary + additional groups
	assert.NotEmpty(t, export.AssetGroupIDs)
	assert.Contains(t, export.AssetGroupIDs, primaryGroup.String())
	assert.Contains(t, export.AssetGroupIDs, group2.String())
	assert.Contains(t, export.AssetGroupIDs, group3.String())
}

func TestExportConfig_PipelineIDConverted(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	pipelineID := shared.NewID()

	sc, err := scan.NewScan(tenantID, "Workflow Scan", shared.NewID(), scan.ScanTypeWorkflow)
	require.NoError(t, err)
	sc.PipelineID = &pipelineID
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	var export ScanConfigExport
	err = json.Unmarshal(data, &export)
	require.NoError(t, err)

	require.NotNil(t, export.PipelineID)
	assert.Equal(t, pipelineID.String(), *export.PipelineID)
}

func TestExportConfig_ScheduleTimeConverted(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	sc, err := scan.NewScan(tenantID, "Scheduled Scan", shared.NewID(), scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"

	schedTime, _ := time.Parse("15:04", "14:30")
	sc.ScheduleTime = &schedTime
	sc.ScheduleType = scan.ScheduleDaily
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	var export ScanConfigExport
	err = json.Unmarshal(data, &export)
	require.NoError(t, err)

	require.NotNil(t, export.ScheduleTime)
	assert.Equal(t, "14:30", *export.ScheduleTime)
}

func TestExportConfig_ReturnsValidJSON(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	sc, err := scan.NewScan(tenantID, "JSON Validity Test", shared.NewID(), scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"
	repo.addScan(sc)

	data, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	assert.True(t, json.Valid(data), "exported data should be valid JSON")
}

// =============================================================================
// ImportConfig Tests
// =============================================================================

// For ImportConfig, the Service.CreateScan method requires many dependencies
// (toolRepo, assetGroupRepo, securityValidator, agentSelector, etc.).
// We test ImportConfig by verifying the JSON parsing and validation logic
// directly, since the full CreateScan path is tested elsewhere.

func TestImportConfig_InvalidJSON(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "completely invalid JSON",
			data: []byte(`{not valid json}`),
		},
		{
			name: "truncated JSON",
			data: []byte(`{"name": "test`),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0x03},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := svc.ImportConfig(context.Background(), tenantID, tc.data)
			assert.Error(t, err)
			assert.Nil(t, result)
			assert.ErrorIs(t, err, shared.ErrValidation)
		})
	}
}

func TestImportConfig_MissingRequiredFields(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()

	testCases := []struct {
		name        string
		data        string
		errContains string
	}{
		{
			name:        "missing name",
			data:        `{"scan_type": "single"}`,
			errContains: "name is required",
		},
		{
			name:        "missing scan_type",
			data:        `{"name": "My Scan"}`,
			errContains: "scan_type is required",
		},
		{
			name:        "both name and scan_type missing",
			data:        `{"description": "just a description"}`,
			errContains: "name is required",
		},
		{
			name:        "empty name",
			data:        `{"name": "", "scan_type": "single"}`,
			errContains: "name is required",
		},
		{
			name:        "empty scan_type",
			data:        `{"name": "My Scan", "scan_type": ""}`,
			errContains: "scan_type is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := svc.ImportConfig(context.Background(), tenantID, []byte(tc.data))
			assert.Error(t, err)
			assert.Nil(t, result)
			assert.ErrorIs(t, err, shared.ErrValidation)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestImportConfig_EmptyData(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "nil data",
			data: nil,
		},
		{
			name: "empty bytes",
			data: []byte{},
		},
		{
			name: "whitespace only",
			data: []byte("   "),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := svc.ImportConfig(context.Background(), tenantID, tc.data)
			assert.Error(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestImportConfig_InvalidScheduleTime(t *testing.T) {
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()

	invalidTime := "25:99"
	data := ScanConfigExport{
		Name:         "Bad Schedule",
		ScanType:     "single",
		ScheduleTime: &invalidTime,
	}

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	result, err := svc.ImportConfig(context.Background(), tenantID, jsonData)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, shared.ErrValidation)
	assert.Contains(t, err.Error(), "schedule_time")
}

func TestImportConfig_ValidScheduleTimeParsing(t *testing.T) {
	// Test that a valid schedule_time in HH:MM format can be correctly parsed.
	// We verify parsing directly since ImportConfig -> CreateScan requires many deps.

	testCases := []struct {
		name     string
		timeStr  string
		expected string
	}{
		{"morning", "09:30", "09:30"},
		{"midnight", "00:00", "00:00"},
		{"evening", "23:59", "23:59"},
		{"noon", "12:00", "12:00"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := time.Parse("15:04", tc.timeStr)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, parsed.Format("15:04"))
		})
	}

	// Also verify invalid times are rejected (same logic used in ImportConfig)
	invalidTimes := []string{"25:00", "12:60", "ab:cd", "9:30:00", ""}
	for _, invalid := range invalidTimes {
		t.Run("invalid_"+invalid, func(t *testing.T) {
			_, err := time.Parse("15:04", invalid)
			assert.Error(t, err, "time %q should fail to parse", invalid)
		})
	}
}

func TestImportConfig_ParsedFieldsMapping(t *testing.T) {
	// Test that the ScanConfigExport JSON structure round-trips correctly.
	// This verifies the JSON tags and field types are consistent.

	pipelineID := shared.NewID().String()
	scheduleDay := 3
	scheduleTime := "14:30"

	original := ScanConfigExport{
		Name:              "Imported Scan",
		Description:       "Imported description",
		ScanType:          "single",
		ScannerName:       "nuclei",
		ScannerConfig:     map[string]any{"rate": float64(100)},
		TargetsPerJob:     10,
		ScheduleType:      "daily",
		ScheduleCron:      "0 2 * * 1",
		ScheduleDay:       &scheduleDay,
		ScheduleTime:      &scheduleTime,
		ScheduleTimezone:  "America/New_York",
		Tags:              []string{"imported", "ci"},
		RunOnTenantRunner: true,
		AgentPreference:   "tenant",
		PipelineID:        &pipelineID,
		AssetGroupIDs:     []string{shared.NewID().String()},
		Targets:           []string{"target.example.com"},
		Version:           "1.0",
		ExportedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Verify we can unmarshal the export format
	var parsed ScanConfigExport
	err = json.Unmarshal(jsonData, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Name, parsed.Name)
	assert.Equal(t, original.Description, parsed.Description)
	assert.Equal(t, original.ScanType, parsed.ScanType)
	assert.Equal(t, original.ScannerName, parsed.ScannerName)
	assert.Equal(t, original.TargetsPerJob, parsed.TargetsPerJob)
	assert.Equal(t, original.ScheduleType, parsed.ScheduleType)
	assert.Equal(t, original.ScheduleCron, parsed.ScheduleCron)
	assert.Equal(t, original.ScheduleTimezone, parsed.ScheduleTimezone)
	assert.Equal(t, original.Tags, parsed.Tags)
	assert.True(t, parsed.RunOnTenantRunner)
	assert.Equal(t, original.AgentPreference, parsed.AgentPreference)
	assert.NotNil(t, parsed.PipelineID)
	assert.Equal(t, pipelineID, *parsed.PipelineID)
	assert.NotNil(t, parsed.ScheduleDay)
	assert.Equal(t, scheduleDay, *parsed.ScheduleDay)
	assert.NotNil(t, parsed.ScheduleTime)
	assert.Equal(t, scheduleTime, *parsed.ScheduleTime)
	assert.Equal(t, original.Targets, parsed.Targets)
	assert.Equal(t, original.AssetGroupIDs, parsed.AssetGroupIDs)
	assert.Equal(t, original.Version, parsed.Version)
	assert.Equal(t, original.ExportedAt, parsed.ExportedAt)
}

// =============================================================================
// Export/Import Round-Trip (JSON Parsing Only)
// =============================================================================

func TestExportImport_JSONRoundTrip(t *testing.T) {
	// Verify that an exported config can be unmarshaled back to the same structure.
	repo := newMockScanRepository()
	svc := newTestImportExportService(repo)

	tenantID := shared.NewID()
	assetGroupID := shared.NewID()

	sc, err := scan.NewScan(tenantID, "Round Trip Scan", assetGroupID, scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = "nuclei"
	sc.Description = "Round trip test"
	sc.Tags = []string{"ci", "nightly"}
	sc.Targets = []string{"api.example.com"}
	sc.TargetsPerJob = 3
	sc.ScannerConfig = map[string]any{"template": "cves"}
	sc.ScheduleType = scan.ScheduleManual
	sc.RunOnTenantRunner = true
	sc.AgentPreference = scan.AgentPreferenceTenant
	repo.addScan(sc)

	// Export
	exportedData, err := svc.ExportConfig(context.Background(), tenantID, sc.ID)
	require.NoError(t, err)

	// Parse the exported JSON
	var exported ScanConfigExport
	err = json.Unmarshal(exportedData, &exported)
	require.NoError(t, err)

	// Verify round-trip fidelity
	assert.Equal(t, sc.Name, exported.Name)
	assert.Equal(t, sc.Description, exported.Description)
	assert.Equal(t, string(sc.ScanType), exported.ScanType)
	assert.Equal(t, sc.ScannerName, exported.ScannerName)
	assert.Equal(t, sc.TargetsPerJob, exported.TargetsPerJob)
	assert.Equal(t, sc.Targets, exported.Targets)
	assert.Equal(t, sc.Tags, exported.Tags)
	assert.Equal(t, sc.RunOnTenantRunner, exported.RunOnTenantRunner)
	assert.Equal(t, string(sc.AgentPreference), exported.AgentPreference)
	assert.Equal(t, string(sc.ScheduleType), exported.ScheduleType)
	assert.Equal(t, sc.ScheduleTimezone, exported.ScheduleTimezone)

	// Verify metadata is present in the exported config
	assert.NotEmpty(t, exported.ExportedAt)
	assert.Equal(t, "1.0", exported.Version)
}
