package ingest

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ValidateReport tests
// =============================================================================

func TestValidateReport_ValidReport(t *testing.T) {
	v := NewValidator()
	report := &ctis.Report{
		Assets:   make([]ctis.Asset, 10),
		Findings: make([]ctis.Finding, 10),
	}
	assert.NoError(t, v.ValidateReport(report))
}

func TestValidateReport_EmptyReport(t *testing.T) {
	v := NewValidator()
	report := &ctis.Report{}
	assert.NoError(t, v.ValidateReport(report))
}

func TestValidateReport_TooManyAssets(t *testing.T) {
	v := NewValidator()
	report := &ctis.Report{
		Assets: make([]ctis.Asset, MaxAssetsPerReport+1),
	}
	err := v.ValidateReport(report)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PAYLOAD_TOO_LARGE")
}

func TestValidateReport_TooManyFindings(t *testing.T) {
	v := NewValidator()
	report := &ctis.Report{
		Findings: make([]ctis.Finding, MaxFindingsPerReport+1),
	}
	err := v.ValidateReport(report)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PAYLOAD_TOO_LARGE")
}

func TestValidateReport_ExactlyAtLimit(t *testing.T) {
	v := NewValidator()
	report := &ctis.Report{
		Assets:   make([]ctis.Asset, MaxAssetsPerReport),
		Findings: make([]ctis.Finding, MaxFindingsPerReport),
	}
	assert.NoError(t, v.ValidateReport(report))
}

// =============================================================================
// ValidatePropertySize tests
// =============================================================================

func TestValidatePropertySize_WithinLimit(t *testing.T) {
	v := NewValidator()
	props := map[string]any{
		"key": "small value",
	}
	key, size := v.ValidatePropertySize(props)
	assert.Empty(t, key)
	assert.Equal(t, 0, size)
}

func TestValidatePropertySize_ExceedsLimit(t *testing.T) {
	v := NewValidator()
	// Create a property larger than MaxPropertySize (1MB)
	large := strings.Repeat("x", MaxPropertySize+1)
	props := map[string]any{
		"large_prop": large,
	}
	key, size := v.ValidatePropertySize(props)
	assert.Equal(t, "large_prop", key)
	assert.Greater(t, size, MaxPropertySize)
}

func TestValidatePropertySize_EmptyProperties(t *testing.T) {
	v := NewValidator()
	key, size := v.ValidatePropertySize(map[string]any{})
	assert.Empty(t, key)
	assert.Equal(t, 0, size)
}

// =============================================================================
// ValidatePropertiesCount tests
// =============================================================================

func TestValidatePropertiesCount_WithinLimit(t *testing.T) {
	v := NewValidator()
	props := make(map[string]any)
	for i := 0; i < MaxPropertiesPerAsset; i++ {
		props[strings.Repeat("k", i+1)] = "v"
	}
	assert.True(t, v.ValidatePropertiesCount(props))
}

func TestValidatePropertiesCount_ExceedsLimit(t *testing.T) {
	v := NewValidator()
	props := make(map[string]any)
	for i := 0; i < MaxPropertiesPerAsset+1; i++ {
		props[strings.Repeat("k", i+1)] = "v"
	}
	assert.False(t, v.ValidatePropertiesCount(props))
}

func TestValidatePropertiesCount_Empty(t *testing.T) {
	v := NewValidator()
	assert.True(t, v.ValidatePropertiesCount(map[string]any{}))
}
