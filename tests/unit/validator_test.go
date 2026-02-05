package unit

import (
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/validator"
)

// Test structs
type CreateAssetRequest struct {
	Name        string   `validate:"required,min=1,max=255"`
	Type        string   `validate:"required,asset_type"`
	Criticality string   `validate:"required,criticality"`
	Description string   `validate:"max=1000"`
	Tags        []string `validate:"max=20,dive,max=50"`
}

type UpdateAssetRequest struct {
	Name        *string  `validate:"omitempty,min=1,max=255"`
	Criticality *string  `validate:"omitempty,criticality"`
	Description *string  `validate:"omitempty,max=1000"`
	Tags        []string `validate:"omitempty,max=20,dive,max=50"`
}

func TestValidator_CreateAssetRequest_Valid(t *testing.T) {
	v := validator.New()

	req := CreateAssetRequest{
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "high",
		Description: "Test description",
		Tags:        []string{"tag1", "tag2"},
	}

	err := v.Validate(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidator_CreateAssetRequest_MissingRequired(t *testing.T) {
	v := validator.New()

	tests := []struct {
		name    string
		req     CreateAssetRequest
		field   string
		message string
	}{
		{
			name:    "missing name",
			req:     CreateAssetRequest{Type: "server", Criticality: "high"},
			field:   "name",
			message: "is required",
		},
		{
			name:    "missing type",
			req:     CreateAssetRequest{Name: "Test", Criticality: "high"},
			field:   "type",
			message: "is required",
		},
		{
			name:    "missing criticality",
			req:     CreateAssetRequest{Name: "Test", Type: "server"},
			field:   "criticality",
			message: "is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.req)
			if err == nil {
				t.Fatal("expected error")
			}

			validationErrors, ok := err.(validator.ValidationErrors)
			if !ok {
				t.Fatalf("expected ValidationErrors, got %T", err)
			}

			found := false
			for _, ve := range validationErrors {
				if ve.Field == tt.field && strings.Contains(ve.Message, tt.message) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error for field %s with message containing %q, got %v", tt.field, tt.message, validationErrors)
			}
		})
	}
}

func TestValidator_CreateAssetRequest_InvalidType(t *testing.T) {
	v := validator.New()

	req := CreateAssetRequest{
		Name:        "Test Asset",
		Type:        "invalid_type",
		Criticality: "high",
	}

	err := v.Validate(req)
	if err == nil {
		t.Fatal("expected error for invalid type")
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}

	found := false
	for _, ve := range validationErrors {
		if ve.Field == "type" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for type field")
	}
}

func TestValidator_CreateAssetRequest_InvalidCriticality(t *testing.T) {
	v := validator.New()

	req := CreateAssetRequest{
		Name:        "Test Asset",
		Type:        "server",
		Criticality: "super_critical",
	}

	err := v.Validate(req)
	if err == nil {
		t.Fatal("expected error for invalid criticality")
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}

	found := false
	for _, ve := range validationErrors {
		if ve.Field == "criticality" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error for criticality field")
	}
}

func TestValidator_CreateAssetRequest_NameTooLong(t *testing.T) {
	v := validator.New()

	req := CreateAssetRequest{
		Name:        strings.Repeat("a", 256),
		Type:        "server",
		Criticality: "high",
	}

	err := v.Validate(req)
	if err == nil {
		t.Fatal("expected error for name too long")
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}

	found := false
	for _, ve := range validationErrors {
		if ve.Field == "name" && strings.Contains(ve.Message, "255") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected max length error for name field, got %v", validationErrors)
	}
}

func TestValidator_UpdateAssetRequest_Valid(t *testing.T) {
	v := validator.New()

	name := "Updated Name"
	criticality := "medium"
	description := "Updated description"

	req := UpdateAssetRequest{
		Name:        &name,
		Criticality: &criticality,
		Description: &description,
		Tags:        []string{"new-tag"},
	}

	err := v.Validate(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestValidator_UpdateAssetRequest_PartialUpdate(t *testing.T) {
	v := validator.New()

	// Only update name
	name := "New Name"
	req := UpdateAssetRequest{
		Name: &name,
	}

	err := v.Validate(req)
	if err != nil {
		t.Fatalf("expected no error for partial update, got %v", err)
	}
}

func TestValidator_UpdateAssetRequest_EmptyIsValid(t *testing.T) {
	v := validator.New()

	// Empty update request should be valid
	req := UpdateAssetRequest{}

	err := v.Validate(req)
	if err != nil {
		t.Fatalf("expected no error for empty update, got %v", err)
	}
}

func TestValidator_AllAssetTypes(t *testing.T) {
	v := validator.New()

	// Valid asset types per the validator's asset_type enum
	validTypes := []string{
		"domain", "subdomain", "certificate", "ip_address", "website",
		"web_application", "api", "mobile_app", "service", "repository",
		"cloud_account", "compute", "storage", "serverless", "container_registry",
		"host", "server", "container", "kubernetes_cluster", "kubernetes_namespace",
		"database", "data_store", "s3_bucket", "network", "vpc", "subnet",
		"load_balancer", "firewall", "iam_user", "iam_role", "service_account",
		"unclassified", "http_service", "open_port", "discovered_url",
	}

	for _, assetType := range validTypes {
		t.Run(assetType, func(t *testing.T) {
			req := CreateAssetRequest{
				Name:        "Test",
				Type:        assetType,
				Criticality: "high",
			}

			err := v.Validate(req)
			if err != nil {
				t.Errorf("expected %s to be valid, got error: %v", assetType, err)
			}
		})
	}
}

func TestValidator_AllCriticalities(t *testing.T) {
	v := validator.New()

	validCriticalities := []string{
		"critical", "high", "medium", "low", "none",
	}

	for _, crit := range validCriticalities {
		t.Run(crit, func(t *testing.T) {
			req := CreateAssetRequest{
				Name:        "Test",
				Type:        "server",
				Criticality: crit,
			}

			err := v.Validate(req)
			if err != nil {
				t.Errorf("expected %s to be valid, got error: %v", crit, err)
			}
		})
	}
}
