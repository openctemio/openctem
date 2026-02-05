package component

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Component Entity Tests
// =============================================================================

func TestNewComponent_Valid(t *testing.T) {
	comp, err := NewComponent("lodash", "4.17.21", EcosystemNPM)

	require.NoError(t, err)
	assert.NotNil(t, comp)
	assert.Equal(t, "lodash", comp.Name())
	assert.Equal(t, "4.17.21", comp.Version())
	assert.Equal(t, EcosystemNPM, comp.Ecosystem())
	assert.Contains(t, comp.PURL(), "pkg:npm/lodash@4.17.21")
	assert.NotEmpty(t, comp.ID())
}

func TestNewComponent_ValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		compName  string
		version   string
		ecosystem Ecosystem
		wantErr   string
	}{
		{
			name:      "empty name",
			compName:  "",
			version:   "1.0.0",
			ecosystem: EcosystemNPM,
			wantErr:   "name is required",
		},
		{
			name:      "empty version",
			compName:  "lodash",
			version:   "",
			ecosystem: EcosystemNPM,
			wantErr:   "version is required",
		},
		{
			name:      "invalid ecosystem",
			compName:  "lodash",
			version:   "1.0.0",
			ecosystem: Ecosystem("invalid"),
			wantErr:   "invalid ecosystem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp, err := NewComponent(tt.compName, tt.version, tt.ecosystem)

			assert.Error(t, err)
			assert.Nil(t, comp)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// =============================================================================
// Metadata Size Limit Tests (Security - DoS Prevention)
// =============================================================================

func TestSetMetadata_WithinLimits(t *testing.T) {
	comp, err := NewComponent("test", "1.0.0", EcosystemNPM)
	require.NoError(t, err)

	// Should succeed with normal metadata
	err = comp.SetMetadata("key1", "value1")
	assert.NoError(t, err)

	err = comp.SetMetadata("key2", map[string]string{"nested": "value"})
	assert.NoError(t, err)

	// Verify metadata was set
	meta := comp.Metadata()
	assert.Equal(t, "value1", meta["key1"])
}

func TestSetMetadata_ExceedsMaxSize(t *testing.T) {
	comp, err := NewComponent("test", "1.0.0", EcosystemNPM)
	require.NoError(t, err)

	// Create a very large value that exceeds MaxMetadataSize (64KB)
	largeValue := strings.Repeat("x", MaxMetadataSize+1000)

	err = comp.SetMetadata("large_key", largeValue)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata size exceeds limit")

	// Verify the key was NOT added
	meta := comp.Metadata()
	_, exists := meta["large_key"]
	assert.False(t, exists)
}

func TestSetMetadata_ExceedsMaxKeys(t *testing.T) {
	comp, err := NewComponent("test", "1.0.0", EcosystemNPM)
	require.NoError(t, err)

	// Add MaxMetadataKeys keys
	for i := 0; i < MaxMetadataKeys; i++ {
		err := comp.SetMetadata(strings.Repeat("k", 5)+string(rune('a'+i%26))+string(rune('0'+i/26)), "value")
		if err != nil {
			// May fail due to size limit before key limit
			break
		}
	}

	// Fill up to max keys with small values
	comp2, _ := NewComponent("test2", "1.0.0", EcosystemNPM)
	for i := 0; i < MaxMetadataKeys; i++ {
		key := "k" + string(rune('a'+i%26)) + string(rune('0'+i/26%10)) + string(rune('0'+i/260))
		_ = comp2.SetMetadata(key, "v")
	}

	// Try to add one more key
	err = comp2.SetMetadata("one_more_key", "value")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata key limit exceeded")
}

func TestSetMetadata_InvalidValue(t *testing.T) {
	comp, err := NewComponent("test", "1.0.0", EcosystemNPM)
	require.NoError(t, err)

	// Channels cannot be JSON marshaled
	ch := make(chan int)

	err = comp.SetMetadata("channel", ch)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid metadata value")
}

func TestSetMetadata_UpdateExistingKey(t *testing.T) {
	comp, err := NewComponent("test", "1.0.0", EcosystemNPM)
	require.NoError(t, err)

	// Set initial value
	err = comp.SetMetadata("key", "value1")
	require.NoError(t, err)

	// Update existing key (should not count against key limit)
	err = comp.SetMetadata("key", "value2")
	assert.NoError(t, err)

	meta := comp.Metadata()
	assert.Equal(t, "value2", meta["key"])
}

// =============================================================================
// AssetDependency Tests
// =============================================================================

func TestNewAssetDependency_Valid(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	dep, err := NewAssetDependency(tenantID, assetID, componentID, "package.json", DependencyTypeDirect)

	require.NoError(t, err)
	assert.NotNil(t, dep)
	assert.Equal(t, tenantID, dep.TenantID())
	assert.Equal(t, assetID, dep.AssetID())
	assert.Equal(t, componentID, dep.ComponentID())
	assert.Equal(t, "package.json", dep.Path())
	assert.Equal(t, DependencyTypeDirect, dep.DependencyType())
	assert.Equal(t, 1, dep.Depth()) // Default depth for direct
	assert.Nil(t, dep.ParentComponentID())
}

func TestNewAssetDependency_MissingIDs(t *testing.T) {
	tests := []struct {
		name        string
		tenantID    shared.ID
		assetID     shared.ID
		componentID shared.ID
	}{
		{"missing tenant", shared.ID{}, shared.NewID(), shared.NewID()},
		{"missing asset", shared.NewID(), shared.ID{}, shared.NewID()},
		{"missing component", shared.NewID(), shared.NewID(), shared.ID{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep, err := NewAssetDependency(tt.tenantID, tt.assetID, tt.componentID, "path", DependencyTypeDirect)

			assert.Error(t, err)
			assert.Nil(t, dep)
			assert.Contains(t, err.Error(), "missing required IDs")
		})
	}
}

// =============================================================================
// Circular Dependency Prevention Tests
// =============================================================================

func TestSetParentComponentID_Valid(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()
	parentID := shared.NewID()

	dep, err := NewAssetDependency(tenantID, assetID, componentID, "path", DependencyTypeTransitive)
	require.NoError(t, err)

	err = dep.SetParentComponentID(&parentID)

	assert.NoError(t, err)
	assert.Equal(t, &parentID, dep.ParentComponentID())
}

func TestSetParentComponentID_Nil(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	dep, err := NewAssetDependency(tenantID, assetID, componentID, "path", DependencyTypeDirect)
	require.NoError(t, err)

	err = dep.SetParentComponentID(nil)

	assert.NoError(t, err)
	assert.Nil(t, dep.ParentComponentID())
}

func TestSetParentComponentID_CircularDependency_SelfReference(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	dep, err := NewAssetDependency(tenantID, assetID, componentID, "path", DependencyTypeTransitive)
	require.NoError(t, err)

	// Try to set self as parent (circular dependency)
	selfID := dep.ID()
	err = dep.SetParentComponentID(&selfID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency detected")

	// Verify parent was NOT set
	assert.Nil(t, dep.ParentComponentID())
}

// =============================================================================
// Depth Tracking Tests
// =============================================================================

func TestSetDepth_Valid(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	dep, err := NewAssetDependency(tenantID, assetID, componentID, "path", DependencyTypeTransitive)
	require.NoError(t, err)

	// Default depth is 1
	assert.Equal(t, 1, dep.Depth())

	// Set depth 2 (transitive)
	dep.SetDepth(2)
	assert.Equal(t, 2, dep.Depth())

	// Set depth 5 (deep transitive)
	dep.SetDepth(5)
	assert.Equal(t, 5, dep.Depth())
}

func TestSetDepth_MinimumIsOne(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()

	dep, err := NewAssetDependency(tenantID, assetID, componentID, "path", DependencyTypeDirect)
	require.NoError(t, err)

	// Try to set depth 0
	dep.SetDepth(0)
	assert.Equal(t, 1, dep.Depth()) // Should be clamped to 1

	// Try to set negative depth
	dep.SetDepth(-5)
	assert.Equal(t, 1, dep.Depth()) // Should be clamped to 1
}

// =============================================================================
// Reconstitute Tests (From Database)
// =============================================================================

func TestReconstituteAssetDependency_WithParent(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()
	parentID := shared.NewID()
	now := time.Now().UTC()

	dep := ReconstituteAssetDependency(
		id, tenantID, assetID, componentID,
		"package.json", DependencyTypeTransitive, "package.json",
		&parentID, 3, // depth 3
		now, now,
	)

	assert.Equal(t, id, dep.ID())
	assert.Equal(t, &parentID, dep.ParentComponentID())
	assert.Equal(t, 3, dep.Depth())
}

func TestReconstituteAssetDependency_InvalidDepth_ClampsToOne(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	assetID := shared.NewID()
	componentID := shared.NewID()
	now := time.Now().UTC()

	// Reconstitute with depth 0 (invalid)
	dep := ReconstituteAssetDependency(
		id, tenantID, assetID, componentID,
		"path", DependencyTypeDirect, "",
		nil, 0, // depth 0 - invalid
		now, now,
	)

	// Should be clamped to 1
	assert.Equal(t, 1, dep.Depth())
}

// =============================================================================
// PURL Override Tests
// =============================================================================

func TestSetPURL_OverridesGeneratedPURL(t *testing.T) {
	comp, err := NewComponent("lodash", "4.17.21", EcosystemNPM)
	require.NoError(t, err)

	// Generated PURL
	generatedPURL := comp.PURL()
	assert.Contains(t, generatedPURL, "pkg:npm/lodash@4.17.21")

	// Override with agent's PURL (may include namespace, qualifiers)
	agentPURL := "pkg:npm/@types/lodash@4.17.21"
	comp.SetPURL(agentPURL)

	assert.Equal(t, agentPURL, comp.PURL())
	assert.NotEqual(t, generatedPURL, comp.PURL())
}

func TestSetPURL_EmptyDoesNotOverride(t *testing.T) {
	comp, err := NewComponent("lodash", "4.17.21", EcosystemNPM)
	require.NoError(t, err)

	generatedPURL := comp.PURL()

	// Empty PURL should not override
	comp.SetPURL("")

	assert.Equal(t, generatedPURL, comp.PURL())
}

// =============================================================================
// Edge Case: Component with same name, different ecosystem
// =============================================================================

func TestNewComponent_DifferentEcosystems_DifferentPURLs(t *testing.T) {
	compNPM, err := NewComponent("lodash", "4.17.21", EcosystemNPM)
	require.NoError(t, err)

	compPyPI, err := NewComponent("lodash", "4.17.21", EcosystemPyPI)
	require.NoError(t, err)

	// Same name/version but different ecosystems should have different PURLs
	assert.NotEqual(t, compNPM.PURL(), compPyPI.PURL())
	assert.Contains(t, compNPM.PURL(), "pkg:npm/")
	assert.Contains(t, compPyPI.PURL(), "pkg:pypi/")
}

// =============================================================================
// Edge Case: Metadata copy (not shared reference)
// =============================================================================

func TestMetadata_ReturnsDefensiveCopy(t *testing.T) {
	comp, err := NewComponent("test", "1.0.0", EcosystemNPM)
	require.NoError(t, err)

	err = comp.SetMetadata("key", "value")
	require.NoError(t, err)

	// Get metadata and modify it
	meta := comp.Metadata()
	meta["key"] = "modified"
	meta["new_key"] = "new_value"

	// Original should be unchanged
	originalMeta := comp.Metadata()
	assert.Equal(t, "value", originalMeta["key"])
	_, exists := originalMeta["new_key"]
	assert.False(t, exists)
}

// =============================================================================
// ParseDependencyType Tests - Scanner compatibility
// =============================================================================

func TestParseDependencyType_DirectMappings(t *testing.T) {
	tests := []struct {
		input    string
		expected DependencyType
	}{
		// Direct mappings
		{"direct", DependencyTypeDirect},
		{"Direct", DependencyTypeDirect},
		{"DIRECT", DependencyTypeDirect},
		{"root", DependencyTypeDirect}, // Trivy uses "root" for top-level

		// Transitive mappings (Trivy compatibility)
		{"transitive", DependencyTypeTransitive},
		{"indirect", DependencyTypeTransitive}, // Trivy uses "indirect"
		{"transit", DependencyTypeTransitive},  // Some scanners use "transit"
		{"INDIRECT", DependencyTypeTransitive},

		// Dev mappings
		{"dev", DependencyTypeDev},
		{"development", DependencyTypeDev},

		// Optional mappings
		{"optional", DependencyTypeOptional},
		{"peer", DependencyTypeOptional}, // npm peer deps

		// Unknown defaults to direct
		{"unknown", DependencyTypeDirect},
		{"", DependencyTypeDirect},
		{"  ", DependencyTypeDirect},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseDependencyType(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result, "input: %q", tt.input)
		})
	}
}
