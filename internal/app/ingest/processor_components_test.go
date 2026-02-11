package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockComponentRepository is a mock implementation of component.Repository for testing.
type MockComponentRepository struct {
	mock.Mock
}

func (m *MockComponentRepository) Upsert(ctx context.Context, comp *component.Component) (shared.ID, error) {
	args := m.Called(ctx, comp)
	return args.Get(0).(shared.ID), args.Error(1)
}

func (m *MockComponentRepository) GetByPURL(ctx context.Context, purl string) (*component.Component, error) {
	args := m.Called(ctx, purl)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*component.Component), args.Error(1)
}

func (m *MockComponentRepository) GetByID(ctx context.Context, id shared.ID) (*component.Component, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*component.Component), args.Error(1)
}

func (m *MockComponentRepository) LinkLicenses(ctx context.Context, componentID shared.ID, licenses []string) (int, error) {
	args := m.Called(ctx, componentID, licenses)
	return args.Int(0), args.Error(1)
}

func (m *MockComponentRepository) LinkAsset(ctx context.Context, dep *component.AssetDependency) error {
	args := m.Called(ctx, dep)
	return args.Error(0)
}

func (m *MockComponentRepository) GetDependency(ctx context.Context, id shared.ID) (*component.AssetDependency, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*component.AssetDependency), args.Error(1)
}

func (m *MockComponentRepository) UpdateDependency(ctx context.Context, dep *component.AssetDependency) error {
	args := m.Called(ctx, dep)
	return args.Error(0)
}

func (m *MockComponentRepository) DeleteDependency(ctx context.Context, id shared.ID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockComponentRepository) DeleteByAssetID(ctx context.Context, assetID shared.ID) error {
	args := m.Called(ctx, assetID)
	return args.Error(0)
}

func (m *MockComponentRepository) GetExistingDependencyByPURL(ctx context.Context, assetID shared.ID, purl string) (*component.AssetDependency, error) {
	args := m.Called(ctx, assetID, purl)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*component.AssetDependency), args.Error(1)
}

func (m *MockComponentRepository) GetExistingDependencyByComponentID(ctx context.Context, assetID shared.ID, componentID shared.ID, path string) (*component.AssetDependency, error) {
	args := m.Called(ctx, assetID, componentID, path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*component.AssetDependency), args.Error(1)
}

func (m *MockComponentRepository) UpdateAssetDependencyParent(ctx context.Context, id shared.ID, parentID shared.ID, depth int) error {
	args := m.Called(ctx, id, parentID, depth)
	return args.Error(0)
}

// Implement remaining interface methods with stubs
func (m *MockComponentRepository) ListComponents(ctx context.Context, filter component.Filter, page pagination.Pagination) (pagination.Result[*component.Component], error) {
	return pagination.Result[*component.Component]{}, nil
}

func (m *MockComponentRepository) ListDependencies(ctx context.Context, assetID shared.ID, page pagination.Pagination) (pagination.Result[*component.AssetDependency], error) {
	return pagination.Result[*component.AssetDependency]{}, nil
}

func (m *MockComponentRepository) GetStats(ctx context.Context, tenantID shared.ID) (*component.ComponentStats, error) {
	return nil, nil
}

func (m *MockComponentRepository) GetEcosystemStats(ctx context.Context, tenantID shared.ID) ([]component.EcosystemStats, error) {
	return nil, nil
}

func (m *MockComponentRepository) GetVulnerableComponents(ctx context.Context, tenantID shared.ID, limit int) ([]component.VulnerableComponent, error) {
	return nil, nil
}

func (m *MockComponentRepository) GetLicenseStats(ctx context.Context, tenantID shared.ID) ([]component.LicenseStats, error) {
	return nil, nil
}

func TestComponentProcessor_ProcessBatch_WithLicenses(t *testing.T) {
	// Setup
	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	assetMap := map[string]shared.ID{
		"asset-1": assetID,
	}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "lodash",
				Version:      "4.17.21",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/lodash@4.17.21",
				Licenses:     []string{"MIT"},
				Relationship: "direct",
			},
			{
				Name:         "axios",
				Version:      "0.21.1",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/axios@0.21.1",
				Licenses:     []string{"MIT", "Apache-2.0"},
				Relationship: "direct",
			},
		},
	}

	output := &Output{}

	// Mock expectations
	mockRepo.On("Upsert", mock.Anything, mock.Anything).Return(componentID, nil).Times(2)
	mockRepo.On("LinkLicenses", mock.Anything, componentID, []string{"MIT"}).Return(1, nil).Once()
	mockRepo.On("LinkLicenses", mock.Anything, componentID, []string{"MIT", "Apache-2.0"}).Return(2, nil).Once()
	mockRepo.On("LinkAsset", mock.Anything, mock.Anything).Return(nil).Times(2)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	// Note: ComponentsUpdated is incremented because mock returns a different ID than comp.ID()
	// In real scenarios with INSERT, the same ID would be returned and ComponentsCreated would increment
	assert.Equal(t, 2, output.ComponentsUpdated)
	assert.Equal(t, 2, output.DependenciesLinked)
	assert.Equal(t, 3, output.LicensesLinked) // 1 + 2 = 3
	assert.Empty(t, output.Warnings)

	mockRepo.AssertExpectations(t)
}

func TestComponentProcessor_ProcessBatch_NoAsset(t *testing.T) {
	// Setup
	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetMap := map[string]shared.ID{} // Empty - no assets

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:      "lodash",
				Version:   "4.17.21",
				Ecosystem: "npm",
			},
		},
	}

	output := &Output{}

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert - should not error, just skip processing
	require.NoError(t, err)
	assert.Equal(t, 0, output.ComponentsCreated)
	assert.Equal(t, 0, output.DependenciesLinked)
}

func TestComponentProcessor_ProcessBatch_LicenseLinkingError(t *testing.T) {
	// Setup
	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	assetMap := map[string]shared.ID{
		"asset-1": assetID,
	}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:      "lodash",
				Version:   "4.17.21",
				Ecosystem: "npm",
				Licenses:  []string{"MIT"},
			},
		},
	}

	output := &Output{}

	// Mock expectations - license linking fails but should not stop processing
	mockRepo.On("Upsert", mock.Anything, mock.Anything).Return(componentID, nil)
	mockRepo.On("LinkLicenses", mock.Anything, componentID, []string{"MIT"}).Return(0, assert.AnError)
	mockRepo.On("LinkAsset", mock.Anything, mock.Anything).Return(nil)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert - should succeed with warning
	require.NoError(t, err)
	// Note: ComponentsUpdated is incremented because mock returns a different ID than comp.ID()
	assert.Equal(t, 1, output.ComponentsUpdated)
	assert.Equal(t, 1, output.DependenciesLinked)
	assert.Equal(t, 0, output.LicensesLinked)
	assert.Len(t, output.Warnings, 1)
	assert.Contains(t, output.Warnings[0], "license linking failed")

	mockRepo.AssertExpectations(t)
}

func TestComponentProcessor_ProcessBatch_EmptyDependencies(t *testing.T) {
	// Setup
	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{}, // Empty
	}

	output := &Output{}

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 0, output.ComponentsCreated)
}

// =============================================================================
// Edge Case Tests: Component Reuse Scenarios
// =============================================================================

func TestComponentProcessor_ProcessBatch_ComponentAlreadyExists(t *testing.T) {
	// Scenario: Agent sends lodash@4.17.21 for Asset B
	//           Component lodash@4.17.21 already exists from Asset A
	//           Expected: Use existing component ID, create new asset_components link

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	existingComponentID := shared.NewID() // This is the ID returned from DB (already exists)

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "lodash",
				Version:      "4.17.21",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/lodash@4.17.21",
				Relationship: "direct",
			},
		},
	}

	output := &Output{}

	// Mock: Upsert returns EXISTING component ID (different from comp.ID())
	// This simulates ON CONFLICT (purl) DO UPDATE ... RETURNING id
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(comp *component.Component) bool {
		return comp.Name() == "lodash" && comp.Version() == "4.17.21"
	})).Return(existingComponentID, nil)

	// Mock: LinkAsset should be called with the existing component ID
	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		return dep.ComponentID() == existingComponentID && dep.AssetID() == assetID
	})).Return(nil)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	// ComponentsUpdated because existing component ID was returned (different from new comp.ID())
	assert.Equal(t, 1, output.ComponentsUpdated)
	assert.Equal(t, 0, output.ComponentsCreated)
	assert.Equal(t, 1, output.DependenciesLinked)

	mockRepo.AssertExpectations(t)
}

func TestComponentProcessor_ProcessBatch_SameComponentDifferentPath(t *testing.T) {
	// Scenario: Same component (lodash) appears in two different paths
	//           package.json and packages/ui/package.json
	//           Expected: Same component ID, two asset_components links

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "lodash",
				Version:      "4.17.21",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/lodash@4.17.21",
				Path:         "package.json",
				Relationship: "direct",
			},
			{
				Name:         "lodash",
				Version:      "4.17.21",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/lodash@4.17.21",
				Path:         "packages/ui/package.json",
				Relationship: "direct",
			},
		},
	}

	output := &Output{}

	// Mock: Upsert returns same component ID for both (same PURL)
	mockRepo.On("Upsert", mock.Anything, mock.Anything).Return(componentID, nil).Times(2)

	// Mock: LinkAsset called twice with different paths
	linkAssetCalls := 0
	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		linkAssetCalls++
		// Both should have same component ID but different paths
		return dep.ComponentID() == componentID
	})).Return(nil).Times(2)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 2, output.ComponentsUpdated) // Both are "updates" in mock
	assert.Equal(t, 2, output.DependenciesLinked)

	mockRepo.AssertExpectations(t)
}

// =============================================================================
// Edge Case Tests: Depth Tracking
// =============================================================================

func TestComponentProcessor_ProcessBatch_TransitiveDepthCalculation(t *testing.T) {
	// Scenario: express (direct) -> lodash (transitive)
	//           express depth = 1, lodash depth = 2

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	expressID := shared.NewID()
	lodashID := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "express",
				Version:      "4.18.0",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/express@4.18.0",
				Relationship: "direct",
			},
			{
				Name:         "lodash",
				Version:      "4.17.21",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/lodash@4.17.21",
				Relationship: "transitive",
				DependsOn:    []string{"pkg:npm/express@4.18.0"}, // lodash depends on express
			},
		},
	}

	output := &Output{}

	// Mock Upserts
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(comp *component.Component) bool {
		return comp.Name() == "express"
	})).Return(expressID, nil)

	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(comp *component.Component) bool {
		return comp.Name() == "lodash"
	})).Return(lodashID, nil)

	// Track depths from LinkAsset calls
	var expressDepth, lodashDepth int

	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		if dep.ComponentID() == expressID {
			expressDepth = dep.Depth()
		} else if dep.ComponentID() == lodashID {
			lodashDepth = dep.Depth()
		}
		return true
	})).Return(nil).Times(2)

	// Mock UpdateAssetDependencyParent for transitive dependency updates
	mockRepo.On("UpdateAssetDependencyParent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 1, expressDepth, "express (direct) should have depth 1")
	assert.Equal(t, 2, lodashDepth, "lodash (transitive from express) should have depth 2")

	mockRepo.AssertExpectations(t)
}

func TestComponentProcessor_ProcessBatch_DeepTransitiveChain(t *testing.T) {
	// Scenario: A (direct) -> B (transitive) -> C (transitive) -> D (transitive)
	//           A depth = 1, B depth = 2, C depth = 3, D depth = 4

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Create IDs for each component
	idA := shared.NewID()
	idB := shared.NewID()
	idC := shared.NewID()
	idD := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{Name: "A", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/A@1.0.0", Relationship: "direct"},
			{Name: "B", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/B@1.0.0", Relationship: "transitive", DependsOn: []string{"pkg:npm/A@1.0.0"}},
			{Name: "C", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/C@1.0.0", Relationship: "transitive", DependsOn: []string{"pkg:npm/B@1.0.0"}},
			{Name: "D", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/D@1.0.0", Relationship: "transitive", DependsOn: []string{"pkg:npm/C@1.0.0"}},
		},
	}

	output := &Output{}

	// Mock Upserts - return component IDs
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(c *component.Component) bool { return c.Name() == "A" })).Return(idA, nil)
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(c *component.Component) bool { return c.Name() == "B" })).Return(idB, nil)
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(c *component.Component) bool { return c.Name() == "C" })).Return(idC, nil)
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(c *component.Component) bool { return c.Name() == "D" })).Return(idD, nil)

	// Track depths from Pass 2 (LinkAsset) - direct gets depth=1, transitive gets depth=2
	depths := make(map[shared.ID]int)
	assetDepToComp := make(map[shared.ID]shared.ID) // assetDep ID → component ID
	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		depths[dep.ComponentID()] = dep.Depth()
		assetDepToComp[dep.ID()] = dep.ComponentID()
		return true
	})).Return(nil).Times(4)

	// Capture FINAL depths from Pass 3 (UpdateAssetDependencyParent)
	mockRepo.On("UpdateAssetDependencyParent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			assetDepID := args.Get(1).(shared.ID)
			depth := args.Get(3).(int)
			if compID, ok := assetDepToComp[assetDepID]; ok {
				depths[compID] = depth
			}
		}).
		Return(nil).Maybe()

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 1, depths[idA], "A (direct) should have depth 1")
	assert.Equal(t, 2, depths[idB], "B (transitive from A) should have depth 2")
	assert.Equal(t, 3, depths[idC], "C (transitive from B) should have depth 3")
	assert.Equal(t, 4, depths[idD], "D (transitive from C) should have depth 4")

	mockRepo.AssertExpectations(t)
}

func TestComponentProcessor_ProcessBatch_TransitiveWithoutParent(t *testing.T) {
	// Scenario: Transitive dependency without DependsOn (parent unknown)
	//           Expected: depth defaults to 2

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "orphan-lib",
				Version:      "1.0.0",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/orphan-lib@1.0.0",
				Relationship: "transitive",
				DependsOn:    nil, // No parent info
			},
		},
	}

	output := &Output{}

	mockRepo.On("Upsert", mock.Anything, mock.Anything).Return(componentID, nil)

	var capturedDepth int
	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		capturedDepth = dep.Depth()
		return true
	})).Return(nil)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 2, capturedDepth, "transitive without parent should default to depth 2")

	mockRepo.AssertExpectations(t)
}

// =============================================================================
// Edge Case Tests: Multiple Key Formats for DependsOn
// =============================================================================

func TestComponentProcessor_BuildDependencyKeys(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(nil, logger)

	tests := []struct {
		name     string
		dep      *ctis.Dependency
		expected []string
	}{
		{
			name: "full PURL + name + version",
			dep: &ctis.Dependency{
				Name:    "lodash",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
			},
			expected: []string{
				"pkg:npm/lodash@4.17.21",
				"lodash@4.17.21",
				"lodash",
			},
		},
		{
			name: "with ID different from name",
			dep: &ctis.Dependency{
				ID:      "npm:lodash:4.17.21",
				Name:    "lodash",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
			},
			expected: []string{
				"pkg:npm/lodash@4.17.21",
				"lodash@4.17.21",
				"lodash",
				"npm:lodash:4.17.21",
			},
		},
		{
			name: "no PURL",
			dep: &ctis.Dependency{
				Name:    "lodash",
				Version: "4.17.21",
			},
			expected: []string{
				"lodash@4.17.21",
				"lodash",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := processor.buildDependencyKeys(tt.dep)
			assert.Equal(t, tt.expected, keys)
		})
	}
}

func TestComponentProcessor_FindParentInMaps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(nil, logger)

	parentID := shared.NewID()

	assetDepIDMap := map[string]shared.ID{
		"pkg:npm/express@4.18.0": parentID,
		"express@4.18.0":         parentID,
		"express":                parentID,
	}

	assetDepDepthMap := map[string]int{
		"pkg:npm/express@4.18.0": 1,
		"express@4.18.0":         1,
		"express":                1,
	}

	tests := []struct {
		name      string
		dependsOn []string
		found     bool
		depth     int
	}{
		{
			name:      "match by PURL",
			dependsOn: []string{"pkg:npm/express@4.18.0"},
			found:     true,
			depth:     1,
		},
		{
			name:      "match by name@version",
			dependsOn: []string{"express@4.18.0"},
			found:     true,
			depth:     1,
		},
		{
			name:      "match by name only",
			dependsOn: []string{"express"},
			found:     true,
			depth:     1,
		},
		{
			name:      "match with pkg: prefix added",
			dependsOn: []string{"npm/express@4.18.0"}, // Without pkg: prefix
			found:     true,
			depth:     1,
		},
		{
			name:      "no match",
			dependsOn: []string{"unknown-package"},
			found:     false,
			depth:     0,
		},
		{
			name:      "first match wins",
			dependsOn: []string{"unknown", "express@4.18.0"},
			found:     true,
			depth:     1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foundID, depth, found := processor.findParentInMaps(tt.dependsOn, assetDepIDMap, assetDepDepthMap)

			assert.Equal(t, tt.found, found)
			if tt.found {
				assert.NotNil(t, foundID)
				assert.Equal(t, tt.depth, depth)
			} else {
				assert.Nil(t, foundID)
			}
		})
	}
}

// =============================================================================
// Edge Case Tests: Duplicate Detection
// =============================================================================

func TestComponentProcessor_ProcessBatch_DuplicateLinkIgnored(t *testing.T) {
	// Scenario: LinkAsset returns "duplicate" error (already linked)
	//           Expected: Continue processing, don't increment DependenciesLinked

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "lodash",
				Version:      "4.17.21",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/lodash@4.17.21",
				Relationship: "direct",
			},
		},
	}

	output := &Output{}

	mockRepo.On("Upsert", mock.Anything, mock.Anything).Return(componentID, nil)

	// Mock: LinkAsset returns duplicate error (should be ignored)
	duplicateErr := fmt.Errorf("unique constraint violation: duplicate key value")
	mockRepo.On("LinkAsset", mock.Anything, mock.Anything).Return(duplicateErr)

	// Mock: GetExistingDependencyByComponentID is called when duplicate error occurs
	mockRepo.On("GetExistingDependencyByComponentID", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert - should succeed, duplicate errors are ignored
	require.NoError(t, err)
	assert.Equal(t, 0, output.DependenciesLinked) // Not incremented because duplicate

	mockRepo.AssertExpectations(t)
}

// =============================================================================
// Edge Case Tests: Parent Lookup from DB (Rescan scenario)
// =============================================================================

func TestComponentProcessor_ProcessBatch_ParentFromPreviousScan(t *testing.T) {
	// Scenario: Child dependency depends on parent that exists from previous scan
	//           Parent is NOT in current batch, so lookup falls back to DB
	//           Expected: Parent found in DB, correct depth calculated
	//
	// Previous scan: express@4.18.0 (direct, depth=1) was created
	// Current scan: body-parser@1.20.0 (transitive, depends_on: express) - only child sent

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Parent from previous scan
	parentAssetDepID := shared.NewID()
	parentComponentID := shared.NewID()

	// Child component ID
	childComponentID := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	// Current scan only sends child, not parent
	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "body-parser",
				Version:      "1.20.0",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/body-parser@1.20.0",
				Relationship: "transitive",
				DependsOn:    []string{"pkg:npm/express@4.18.0"}, // Parent not in batch
			},
		},
	}

	output := &Output{}

	// Mock: Upsert child component
	mockRepo.On("Upsert", mock.Anything, mock.MatchedBy(func(c *component.Component) bool {
		return c.Name() == "body-parser"
	})).Return(childComponentID, nil)

	// Mock: DB lookup finds parent from previous scan
	// This simulates finding express in asset_components table
	parentDep := component.ReconstituteAssetDependency(
		parentAssetDepID,
		tenantID,
		assetID,
		parentComponentID,
		"package.json",
		component.DependencyTypeDirect,
		"package.json",
		nil, // No parent (it's a direct dep)
		1,   // Depth 1 (direct)
		time.Now(),
		time.Now(),
	)
	mockRepo.On("GetExistingDependencyByPURL", mock.Anything, assetID, "pkg:npm/express@4.18.0").
		Return(parentDep, nil)

	// Pass 2: LinkAsset captures initial depth (transitive defaults to 2, no parent yet)
	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		return dep.ComponentID() == childComponentID
	})).Return(nil)

	// Pass 3: Capture parent ID and final depth from UpdateAssetDependencyParent
	var capturedParentID *shared.ID
	var capturedFinalDepth int
	mockRepo.On("UpdateAssetDependencyParent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			parentID := args.Get(2).(shared.ID)
			capturedParentID = &parentID
			capturedFinalDepth = args.Get(3).(int)
		}).
		Return(nil).Maybe()

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 2, capturedFinalDepth, "child should have depth 2 (parent depth 1 + 1)")
	assert.NotNil(t, capturedParentID, "parent component ID should be set")
	assert.Equal(t, parentAssetDepID, *capturedParentID, "parent should be the one from DB")
	assert.Equal(t, 1, output.DependenciesLinked)

	mockRepo.AssertExpectations(t)
}

func TestComponentProcessor_ProcessBatch_ParentNotFoundAnywhere(t *testing.T) {
	// Scenario: Child depends on parent that doesn't exist in batch OR in DB
	//           Expected: depth defaults to 2, parent_component_id is nil

	mockRepo := new(MockComponentRepository)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	processor := NewComponentProcessor(mockRepo, logger)

	tenantID := shared.NewID()
	assetID := shared.NewID()
	childComponentID := shared.NewID()

	assetMap := map[string]shared.ID{"asset-1": assetID}

	report := &ctis.Report{
		Dependencies: []ctis.Dependency{
			{
				Name:         "orphan-lib",
				Version:      "1.0.0",
				Ecosystem:    "npm",
				PURL:         "pkg:npm/orphan-lib@1.0.0",
				Relationship: "transitive",
				DependsOn:    []string{"pkg:npm/ghost-parent@1.0.0"}, // Parent doesn't exist
			},
		},
	}

	output := &Output{}

	mockRepo.On("Upsert", mock.Anything, mock.Anything).Return(childComponentID, nil)

	// Mock: DB lookup returns nil (parent not found)
	mockRepo.On("GetExistingDependencyByPURL", mock.Anything, assetID, "pkg:npm/ghost-parent@1.0.0").
		Return(nil, nil)

	var capturedDepth int
	var capturedParentID *shared.ID
	mockRepo.On("LinkAsset", mock.Anything, mock.MatchedBy(func(dep *component.AssetDependency) bool {
		capturedDepth = dep.Depth()
		capturedParentID = dep.ParentComponentID()
		return true
	})).Return(nil)

	// Execute
	err := processor.ProcessBatch(context.Background(), tenantID, report, assetMap, output)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, 2, capturedDepth, "orphan transitive should default to depth 2")
	assert.Nil(t, capturedParentID, "parent should be nil when not found")

	mockRepo.AssertExpectations(t)
}
