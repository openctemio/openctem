package tool

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/stretchr/testify/assert"
)

func TestNewTargetAssetTypeMapping(t *testing.T) {
	tests := []struct {
		name       string
		targetType string
		assetType  asset.AssetType
	}{
		{
			name:       "url to website mapping",
			targetType: "url",
			assetType:  asset.AssetTypeWebsite,
		},
		{
			name:       "domain to domain mapping",
			targetType: "domain",
			assetType:  asset.AssetTypeDomain,
		},
		{
			name:       "ip to ip_address mapping",
			targetType: "ip",
			assetType:  asset.AssetTypeIPAddress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewTargetAssetTypeMapping(tt.targetType, tt.assetType)

			assert.NotNil(t, m)
			assert.False(t, m.ID.IsZero(), "ID should be set")
			assert.Equal(t, tt.targetType, m.TargetType)
			assert.Equal(t, tt.assetType, m.AssetType)
			assert.Equal(t, 100, m.Priority, "Default priority should be 100")
			assert.True(t, m.IsActive, "Default should be active")
			assert.Empty(t, m.Description)
			assert.Nil(t, m.CreatedBy)
			assert.False(t, m.CreatedAt.IsZero())
			assert.False(t, m.UpdatedAt.IsZero())
		})
	}
}

func TestTargetAssetTypeMapping_IsPrimary(t *testing.T) {
	tests := []struct {
		name     string
		priority int
		want     bool
	}{
		{
			name:     "priority 10 is primary",
			priority: 10,
			want:     true,
		},
		{
			name:     "priority 100 is not primary",
			priority: 100,
			want:     false,
		},
		{
			name:     "priority 20 is not primary",
			priority: 20,
			want:     false,
		},
		{
			name:     "priority 0 is not primary",
			priority: 0,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewTargetAssetTypeMapping("url", asset.AssetTypeWebsite)
			m.Priority = tt.priority

			assert.Equal(t, tt.want, m.IsPrimary())
		})
	}
}

func TestTargetAssetTypeMapping_SetPrimary(t *testing.T) {
	tests := []struct {
		name            string
		initialPriority int
		setPrimary      bool
		wantPriority    int
	}{
		{
			name:            "set primary from default",
			initialPriority: 100,
			setPrimary:      true,
			wantPriority:    10,
		},
		{
			name:            "set primary from 20",
			initialPriority: 20,
			setPrimary:      true,
			wantPriority:    10,
		},
		{
			name:            "unset primary (was primary)",
			initialPriority: 10,
			setPrimary:      false,
			wantPriority:    100,
		},
		{
			name:            "unset primary (was not primary)",
			initialPriority: 50,
			setPrimary:      false,
			wantPriority:    50, // Should not change
		},
		{
			name:            "set primary when already primary",
			initialPriority: 10,
			setPrimary:      true,
			wantPriority:    10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewTargetAssetTypeMapping("url", asset.AssetTypeWebsite)
			m.Priority = tt.initialPriority

			m.SetPrimary(tt.setPrimary)

			assert.Equal(t, tt.wantPriority, m.Priority)
		})
	}
}

func TestIsValidTargetType(t *testing.T) {
	tests := []struct {
		name       string
		targetType string
		want       bool
	}{
		{
			name:       "url is valid",
			targetType: "url",
			want:       true,
		},
		{
			name:       "domain is valid",
			targetType: "domain",
			want:       true,
		},
		{
			name:       "ip is valid",
			targetType: "ip",
			want:       true,
		},
		{
			name:       "repository is valid",
			targetType: "repository",
			want:       true,
		},
		{
			name:       "container is valid",
			targetType: "container",
			want:       true,
		},
		{
			name:       "kubernetes is valid",
			targetType: "kubernetes",
			want:       true,
		},
		{
			name:       "cloud_account is valid",
			targetType: "cloud_account",
			want:       true,
		},
		{
			name:       "network is valid",
			targetType: "network",
			want:       true,
		},
		{
			name:       "invalid type",
			targetType: "invalid",
			want:       false,
		},
		{
			name:       "empty string",
			targetType: "",
			want:       false,
		},
		{
			name:       "URL uppercase",
			targetType: "URL",
			want:       false, // Case sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTargetType(tt.targetType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTargetMappingFilter_Empty(t *testing.T) {
	filter := TargetMappingFilter{}

	assert.Nil(t, filter.TargetType)
	assert.Nil(t, filter.AssetType)
	assert.Nil(t, filter.IsActive)
	assert.Empty(t, filter.TargetTypes)
	assert.Empty(t, filter.AssetTypes)
}

func TestTargetMappingFilter_WithValues(t *testing.T) {
	targetType := "url"
	assetType := "website"
	isActive := true

	filter := TargetMappingFilter{
		TargetType:  &targetType,
		AssetType:   &assetType,
		IsActive:    &isActive,
		TargetTypes: []string{"url", "domain"},
		AssetTypes:  []string{"website", "domain"},
	}

	assert.Equal(t, &targetType, filter.TargetType)
	assert.Equal(t, &assetType, filter.AssetType)
	assert.Equal(t, &isActive, filter.IsActive)
	assert.Equal(t, []string{"url", "domain"}, filter.TargetTypes)
	assert.Equal(t, []string{"website", "domain"}, filter.AssetTypes)
}
