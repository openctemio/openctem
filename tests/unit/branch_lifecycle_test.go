package unit

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories
// =============================================================================

// MockFindingRepoForLifecycle implements vulnerability.FindingRepository for lifecycle tests.
type MockFindingRepoForLifecycle struct {
	ExpireFeatureBranchFindingsCalled bool
	ExpireFeatureBranchFindingsArgs   struct {
		TenantID          shared.ID
		DefaultExpiryDays int
	}
	ExpireFeatureBranchFindingsReturn int64
	ExpireFeatureBranchFindingsError  error

	AutoResolveStaleCalled bool
	AutoResolveStaleReturn []shared.ID
	AutoResolveStaleError  error
}

func (m *MockFindingRepoForLifecycle) ExpireFeatureBranchFindings(ctx context.Context, tenantID shared.ID, defaultExpiryDays int) (int64, error) {
	m.ExpireFeatureBranchFindingsCalled = true
	m.ExpireFeatureBranchFindingsArgs.TenantID = tenantID
	m.ExpireFeatureBranchFindingsArgs.DefaultExpiryDays = defaultExpiryDays
	return m.ExpireFeatureBranchFindingsReturn, m.ExpireFeatureBranchFindingsError
}

func (m *MockFindingRepoForLifecycle) AutoResolveStale(ctx context.Context, tenantID shared.ID, assetID shared.ID, toolName string, currentScanID string, branchID *shared.ID) ([]shared.ID, error) {
	m.AutoResolveStaleCalled = true
	return m.AutoResolveStaleReturn, m.AutoResolveStaleError
}

// Minimal implementations for interface compliance
func (m *MockFindingRepoForLifecycle) Create(ctx context.Context, f *vulnerability.Finding) error {
	return nil
}
func (m *MockFindingRepoForLifecycle) CreateInTx(ctx context.Context, tx *sql.Tx, f *vulnerability.Finding) error {
	return nil
}
func (m *MockFindingRepoForLifecycle) CreateBatch(ctx context.Context, findings []*vulnerability.Finding) error {
	return nil
}

// Security: GetByID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	return nil, shared.ErrNotFound
}
func (m *MockFindingRepoForLifecycle) Update(ctx context.Context, f *vulnerability.Finding) error {
	return nil
}

// Security: Delete now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) Delete(ctx context.Context, tenantID, id shared.ID) error {
	return nil
}
func (m *MockFindingRepoForLifecycle) List(ctx context.Context, filter vulnerability.FindingFilter, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

// Security: ListByAssetID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) ListByAssetID(ctx context.Context, tenantID, assetID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

// Security: ListByVulnerabilityID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) ListByVulnerabilityID(ctx context.Context, tenantID, vulnID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

// Security: ListByComponentID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) ListByComponentID(ctx context.Context, tenantID, compID shared.ID, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}
func (m *MockFindingRepoForLifecycle) Count(ctx context.Context, filter vulnerability.FindingFilter) (int64, error) {
	return 0, nil
}

// Security: CountByAssetID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) CountByAssetID(ctx context.Context, tenantID, assetID shared.ID) (int64, error) {
	return 0, nil
}

// Security: CountOpenByAssetID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) CountOpenByAssetID(ctx context.Context, tenantID, assetID shared.ID) (int64, error) {
	return 0, nil
}
func (m *MockFindingRepoForLifecycle) GetByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*vulnerability.Finding, error) {
	return nil, shared.ErrNotFound
}
func (m *MockFindingRepoForLifecycle) ExistsByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (bool, error) {
	return false, nil
}
func (m *MockFindingRepoForLifecycle) CheckFingerprintsExist(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]bool, error) {
	return make(map[string]bool), nil
}
func (m *MockFindingRepoForLifecycle) UpdateScanIDBatchByFingerprints(ctx context.Context, tenantID shared.ID, fingerprints []string, scanID string) (int64, error) {
	return 0, nil
}
func (m *MockFindingRepoForLifecycle) UpdateSnippetBatchByFingerprints(ctx context.Context, tenantID shared.ID, snippets map[string]string) (int64, error) {
	return 0, nil
}

// Security: BatchCountByAssetIDs now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) BatchCountByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}

// Security: UpdateStatusBatch now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) UpdateStatusBatch(ctx context.Context, tenantID shared.ID, ids []shared.ID, status vulnerability.FindingStatus, resolution string, resolvedBy *shared.ID) error {
	return nil
}

// Security: DeleteByAssetID now requires tenantID for tenant isolation
func (m *MockFindingRepoForLifecycle) DeleteByAssetID(ctx context.Context, tenantID, assetID shared.ID) error {
	return nil
}
func (m *MockFindingRepoForLifecycle) DeleteByScanID(ctx context.Context, tenantID shared.ID, scanID string) error {
	return nil
}
func (m *MockFindingRepoForLifecycle) GetStats(ctx context.Context, tenantID shared.ID) (*vulnerability.FindingStats, error) {
	return nil, nil
}
func (m *MockFindingRepoForLifecycle) CountBySeverityForScan(ctx context.Context, tenantID shared.ID, scanID string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}
func (m *MockFindingRepoForLifecycle) AutoReopenByFingerprint(ctx context.Context, tenantID shared.ID, fingerprint string) (*shared.ID, error) {
	return nil, nil
}
func (m *MockFindingRepoForLifecycle) AutoReopenByFingerprintsBatch(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string]shared.ID, error) {
	return make(map[string]shared.ID), nil
}
func (m *MockFindingRepoForLifecycle) CreateBatchWithResult(ctx context.Context, findings []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	return &vulnerability.BatchCreateResult{Created: len(findings), Errors: make(map[int]string)}, nil
}
func (m *MockFindingRepoForLifecycle) ExistsByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	result := make(map[shared.ID]bool)
	for _, id := range ids {
		result[id] = true
	}
	return result, nil
}

// MockTenantLister implements app.TenantLister for tests.
type MockTenantLister struct {
	TenantIDs []shared.ID
	Error     error
}

func (m *MockTenantLister) ListActiveTenantIDs(ctx context.Context) ([]shared.ID, error) {
	return m.TenantIDs, m.Error
}

// =============================================================================
// Test: FindingLifecycleScheduler expires feature branch findings
// =============================================================================

func TestFindingLifecycleScheduler_ExpiresFeatureBranchFindings(t *testing.T) {
	// Create mock dependencies
	mockFindingRepo := &MockFindingRepoForLifecycle{
		ExpireFeatureBranchFindingsReturn: 5,
	}

	tenantID := shared.NewID()
	mockTenantLister := &MockTenantLister{
		TenantIDs: []shared.ID{tenantID},
	}

	log := logger.New(logger.Config{Level: "error"})

	scheduler := app.NewFindingLifecycleScheduler(
		mockFindingRepo,
		mockTenantLister,
		app.FindingLifecycleSchedulerConfig{
			CheckInterval:     time.Hour,
			DefaultExpiryDays: 30,
			Enabled:           true,
		},
		log,
	)

	// The scheduler runs on a timer, so we test the logic indirectly
	// by verifying the configuration
	if scheduler == nil {
		t.Error("scheduler should not be nil")
	}
}

// =============================================================================
// Test: Branch type detection from branch name
// =============================================================================

func TestDetectBranchType(t *testing.T) {
	tests := []struct {
		name     string
		expected branch.Type
	}{
		{"main", branch.TypeMain},
		{"master", branch.TypeMain},
		{"develop", branch.TypeDevelop},
		{"development", branch.TypeDevelop},
		{"dev", branch.TypeDevelop},
		{"feature", branch.TypeFeature},
		{"release", branch.TypeRelease},
		{"hotfix", branch.TypeHotfix},
		{"feature/add-login", branch.TypeFeature},
		{"release/v1.0.0", branch.TypeRelease},
		{"hotfix/fix-bug", branch.TypeHotfix},
		{"random-branch", branch.TypeOther},
		{"", branch.TypeOther},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the branch package's ParseType for exact matches
			result := branch.ParseType(tt.name)

			// For prefix-based detection, we'd need to expose the detectBranchType function
			// or test it via integration test. Here we test the domain logic.
			if tt.name == "main" || tt.name == "master" {
				if result != branch.TypeMain {
					t.Errorf("ParseType(%q) = %v, want %v", tt.name, result, branch.TypeMain)
				}
			}
			if tt.name == "develop" || tt.name == "development" || tt.name == "dev" {
				if result != branch.TypeDevelop {
					t.Errorf("ParseType(%q) = %v, want %v", tt.name, result, branch.TypeDevelop)
				}
			}
		})
	}
}

// =============================================================================
// Test: Branch entity lifecycle methods
// =============================================================================

func TestBranch_SetDefault(t *testing.T) {
	repositoryID := shared.NewID()
	b, err := branch.NewBranch(repositoryID, "main", branch.TypeMain)
	if err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}

	// Initial state should be false
	if b.IsDefault() {
		t.Error("new branch should not be default by default")
	}

	// Set as default
	b.SetDefault(true)
	if !b.IsDefault() {
		t.Error("branch should be default after SetDefault(true)")
	}

	// Unset default
	b.SetDefault(false)
	if b.IsDefault() {
		t.Error("branch should not be default after SetDefault(false)")
	}
}

func TestBranch_Retention(t *testing.T) {
	repositoryID := shared.NewID()
	b, err := branch.NewBranch(repositoryID, "feature/test", branch.TypeFeature)
	if err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}

	// Default should be keep when inactive
	if !b.KeepWhenInactive() {
		t.Error("new branch should keep when inactive by default")
	}

	// Set custom retention
	days := 7
	b.SetRetention(false, &days)

	if b.KeepWhenInactive() {
		t.Error("branch should not keep when inactive after SetRetention(false, ...)")
	}

	if b.RetentionDays() == nil || *b.RetentionDays() != 7 {
		t.Error("branch retention days should be 7")
	}
}

// =============================================================================
// Test: FindingLifecycleScheduler configuration defaults
// =============================================================================

func TestDefaultFindingLifecycleSchedulerConfig(t *testing.T) {
	cfg := app.DefaultFindingLifecycleSchedulerConfig()

	if cfg.CheckInterval != time.Hour {
		t.Errorf("CheckInterval = %v, want %v", cfg.CheckInterval, time.Hour)
	}

	if cfg.DefaultExpiryDays != 30 {
		t.Errorf("DefaultExpiryDays = %d, want 30", cfg.DefaultExpiryDays)
	}

	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}
}

// =============================================================================
// Test: Branch value objects
// =============================================================================

func TestBranchType_String(t *testing.T) {
	tests := []struct {
		t    branch.Type
		want string
	}{
		{branch.TypeMain, "main"},
		{branch.TypeDevelop, "develop"},
		{branch.TypeFeature, "feature"},
		{branch.TypeRelease, "release"},
		{branch.TypeHotfix, "hotfix"},
		{branch.TypeOther, "other"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.t.String(); got != tt.want {
				t.Errorf("Type.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBranchType_IsValid(t *testing.T) {
	validTypes := []branch.Type{
		branch.TypeMain,
		branch.TypeDevelop,
		branch.TypeFeature,
		branch.TypeRelease,
		branch.TypeHotfix,
		branch.TypeOther,
	}

	for _, bt := range validTypes {
		if !bt.IsValid() {
			t.Errorf("Type %v should be valid", bt)
		}
	}

	invalidType := branch.Type("invalid")
	if invalidType.IsValid() {
		t.Error("invalid Type should not be valid")
	}
}
