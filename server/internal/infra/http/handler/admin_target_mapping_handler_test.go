package handler

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateTargetMappingRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		check   func(t *testing.T, req CreateTargetMappingRequest)
	}{
		{
			name:    "valid minimal request",
			body:    `{"target_type": "url", "asset_type": "website"}`,
			wantErr: false,
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.Equal(t, "url", req.TargetType)
				assert.Equal(t, "website", req.AssetType)
				assert.Nil(t, req.Priority)
				assert.Nil(t, req.IsPrimary)
				assert.Nil(t, req.IsActive)
				assert.Nil(t, req.Description)
			},
		},
		{
			name:    "valid with is_primary true",
			body:    `{"target_type": "url", "asset_type": "website", "is_primary": true}`,
			wantErr: false,
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.NotNil(t, req.IsPrimary)
				assert.True(t, *req.IsPrimary)
			},
		},
		{
			name:    "valid with is_active false",
			body:    `{"target_type": "url", "asset_type": "website", "is_active": false}`,
			wantErr: false,
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.NotNil(t, req.IsActive)
				assert.False(t, *req.IsActive)
			},
		},
		{
			name:    "valid with priority",
			body:    `{"target_type": "url", "asset_type": "website", "priority": 20}`,
			wantErr: false,
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.NotNil(t, req.Priority)
				assert.Equal(t, 20, *req.Priority)
			},
		},
		{
			name:    "valid with description",
			body:    `{"target_type": "url", "asset_type": "website", "description": "Maps URL to website"}`,
			wantErr: false,
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.NotNil(t, req.Description)
				assert.Equal(t, "Maps URL to website", *req.Description)
			},
		},
		{
			name:    "valid full request",
			body:    `{"target_type": "url", "asset_type": "website", "priority": 10, "is_primary": true, "is_active": true, "description": "Primary URL mapping"}`,
			wantErr: false,
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.Equal(t, "url", req.TargetType)
				assert.Equal(t, "website", req.AssetType)
				assert.NotNil(t, req.Priority)
				assert.Equal(t, 10, *req.Priority)
				assert.NotNil(t, req.IsPrimary)
				assert.True(t, *req.IsPrimary)
				assert.NotNil(t, req.IsActive)
				assert.True(t, *req.IsActive)
				assert.NotNil(t, req.Description)
				assert.Equal(t, "Primary URL mapping", *req.Description)
			},
		},
		{
			name:    "invalid json",
			body:    `{invalid}`,
			wantErr: true,
		},
		{
			name:    "empty body",
			body:    `{}`,
			wantErr: false, // Parsing succeeds, validation happens in handler
			check: func(t *testing.T, req CreateTargetMappingRequest) {
				assert.Empty(t, req.TargetType)
				assert.Empty(t, req.AssetType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req CreateTargetMappingRequest
			err := json.NewDecoder(bytes.NewReader([]byte(tt.body))).Decode(&req)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.check != nil {
					tt.check(t, req)
				}
			}
		})
	}
}

func TestUpdateTargetMappingRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		check   func(t *testing.T, req UpdateTargetMappingRequest)
	}{
		{
			name:    "empty body is valid",
			body:    `{}`,
			wantErr: false,
			check: func(t *testing.T, req UpdateTargetMappingRequest) {
				assert.Nil(t, req.Priority)
				assert.Nil(t, req.IsPrimary)
				assert.Nil(t, req.IsActive)
				assert.Nil(t, req.Description)
			},
		},
		{
			name:    "update is_primary only",
			body:    `{"is_primary": true}`,
			wantErr: false,
			check: func(t *testing.T, req UpdateTargetMappingRequest) {
				assert.NotNil(t, req.IsPrimary)
				assert.True(t, *req.IsPrimary)
				assert.Nil(t, req.IsActive)
			},
		},
		{
			name:    "update is_active only",
			body:    `{"is_active": false}`,
			wantErr: false,
			check: func(t *testing.T, req UpdateTargetMappingRequest) {
				assert.Nil(t, req.IsPrimary)
				assert.NotNil(t, req.IsActive)
				assert.False(t, *req.IsActive)
			},
		},
		{
			name:    "update priority only",
			body:    `{"priority": 50}`,
			wantErr: false,
			check: func(t *testing.T, req UpdateTargetMappingRequest) {
				assert.NotNil(t, req.Priority)
				assert.Equal(t, 50, *req.Priority)
			},
		},
		{
			name:    "update description only",
			body:    `{"description": "Updated description"}`,
			wantErr: false,
			check: func(t *testing.T, req UpdateTargetMappingRequest) {
				assert.NotNil(t, req.Description)
				assert.Equal(t, "Updated description", *req.Description)
			},
		},
		{
			name:    "update multiple fields",
			body:    `{"is_primary": false, "is_active": true, "description": "Modified"}`,
			wantErr: false,
			check: func(t *testing.T, req UpdateTargetMappingRequest) {
				assert.NotNil(t, req.IsPrimary)
				assert.False(t, *req.IsPrimary)
				assert.NotNil(t, req.IsActive)
				assert.True(t, *req.IsActive)
				assert.NotNil(t, req.Description)
				assert.Equal(t, "Modified", *req.Description)
			},
		},
		{
			name:    "invalid json",
			body:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req UpdateTargetMappingRequest
			err := json.NewDecoder(bytes.NewReader([]byte(tt.body))).Decode(&req)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.check != nil {
					tt.check(t, req)
				}
			}
		})
	}
}

func TestTargetMappingResponse_JSON(t *testing.T) {
	// Test that TargetMappingResponse marshals correctly with all fields
	description := "Test description"
	createdBy := "550e8400-e29b-41d4-a716-446655440000"

	resp := TargetMappingResponse{
		ID:          "550e8400-e29b-41d4-a716-446655440001",
		TargetType:  "url",
		AssetType:   "website",
		Priority:    10,
		IsActive:    true,
		IsPrimary:   true,
		Description: &description,
		CreatedBy:   &createdBy,
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
	}

	data, err := json.Marshal(resp)
	assert.NoError(t, err)

	var unmarshaled map[string]any
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440001", unmarshaled["id"])
	assert.Equal(t, "url", unmarshaled["target_type"])
	assert.Equal(t, "website", unmarshaled["asset_type"])
	assert.Equal(t, float64(10), unmarshaled["priority"])
	assert.Equal(t, true, unmarshaled["is_active"])
	assert.Equal(t, true, unmarshaled["is_primary"])
	assert.Equal(t, "Test description", unmarshaled["description"])
	assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", unmarshaled["created_by"])
}

func TestTargetMappingResponse_JSON_OmitEmpty(t *testing.T) {
	// Test that optional fields are omitted when nil
	resp := TargetMappingResponse{
		ID:         "550e8400-e29b-41d4-a716-446655440001",
		TargetType: "url",
		AssetType:  "website",
		Priority:   100,
		IsActive:   true,
		IsPrimary:  false,
		CreatedAt:  "2024-01-01T00:00:00Z",
		UpdatedAt:  "2024-01-01T00:00:00Z",
	}

	data, err := json.Marshal(resp)
	assert.NoError(t, err)

	var unmarshaled map[string]any
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	// These should be present but nil
	_, hasDescription := unmarshaled["description"]
	_, hasCreatedBy := unmarshaled["created_by"]

	assert.False(t, hasDescription, "description should be omitted when nil")
	assert.False(t, hasCreatedBy, "created_by should be omitted when nil")
}

func TestTargetMappingListResponse_JSON(t *testing.T) {
	resp := TargetMappingListResponse{
		Data: []TargetMappingResponse{
			{
				ID:         "1",
				TargetType: "url",
				AssetType:  "website",
				Priority:   10,
				IsActive:   true,
				IsPrimary:  true,
				CreatedAt:  "2024-01-01T00:00:00Z",
				UpdatedAt:  "2024-01-01T00:00:00Z",
			},
		},
		Total:      1,
		Page:       1,
		PerPage:    50,
		TotalPages: 1,
	}

	data, err := json.Marshal(resp)
	assert.NoError(t, err)

	var unmarshaled TargetMappingListResponse
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Len(t, unmarshaled.Data, 1)
	assert.Equal(t, int64(1), unmarshaled.Total)
	assert.Equal(t, 1, unmarshaled.Page)
	assert.Equal(t, 50, unmarshaled.PerPage)
	assert.Equal(t, 1, unmarshaled.TotalPages)
}

func TestTargetMappingStatsResponse_JSON(t *testing.T) {
	resp := TargetMappingStatsResponse{
		Total: 10,
		ByTargetType: map[string]int64{
			"url":    5,
			"domain": 3,
			"ip":     2,
		},
		ByAssetType: map[string]int64{
			"website":    5,
			"domain":     3,
			"ip_address": 2,
		},
		ActiveCount:   8,
		InactiveCount: 2,
	}

	data, err := json.Marshal(resp)
	assert.NoError(t, err)

	var unmarshaled TargetMappingStatsResponse
	err = json.Unmarshal(data, &unmarshaled)
	assert.NoError(t, err)

	assert.Equal(t, int64(10), unmarshaled.Total)
	assert.Equal(t, int64(5), unmarshaled.ByTargetType["url"])
	assert.Equal(t, int64(5), unmarshaled.ByAssetType["website"])
	assert.Equal(t, int64(8), unmarshaled.ActiveCount)
	assert.Equal(t, int64(2), unmarshaled.InactiveCount)
}
