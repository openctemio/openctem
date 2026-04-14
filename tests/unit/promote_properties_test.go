package unit

import (
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/stretchr/testify/assert"
)

func TestPromoteKnownProperties_SubType(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "fw-01",
		Type:        "network",
		Criticality: "high",
		Properties: map[string]any{
			"sub_type": "firewall",
			"vendor":   "Cisco",
		},
	}

	result := app.PromoteKnownProperties(input)

	// sub_type promoted to __promoted_sub_type, removed from properties
	assert.Equal(t, "firewall", result.Properties["__promoted_sub_type"])
	assert.Nil(t, result.Properties["sub_type"])
	// vendor stays in properties
	assert.Equal(t, "Cisco", result.Properties["vendor"])
}

func TestPromoteKnownProperties_TypeAlias(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "fw-01",
		Type:        "host",
		Criticality: "high",
		Properties: map[string]any{
			"type":   "firewall",
			"vendor": "Palo Alto",
		},
	}

	result := app.PromoteKnownProperties(input)

	// type resolved via alias: firewall → network
	assert.Equal(t, "network", result.Type)
	// sub_type promoted from alias resolution
	assert.Equal(t, "firewall", result.Properties["__promoted_sub_type"])
	// original "type" key removed from properties
	assert.Nil(t, result.Properties["type"])
	// vendor stays
	assert.Equal(t, "Palo Alto", result.Properties["vendor"])
}

func TestPromoteKnownProperties_ScopeExposure(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
		// Scope/Exposure empty at top level
		Properties: map[string]any{
			"scope":    "internal",
			"exposure": "private",
		},
	}

	result := app.PromoteKnownProperties(input)

	assert.Equal(t, "internal", result.Scope)
	assert.Equal(t, "private", result.Exposure)
	// Removed from properties
	assert.Nil(t, result.Properties["scope"])
	assert.Nil(t, result.Properties["exposure"])
}

func TestPromoteKnownProperties_ScopeNoOverride(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
		Scope:       "external", // Already set
		Properties: map[string]any{
			"scope": "internal", // Should NOT override
		},
	}

	result := app.PromoteKnownProperties(input)

	// Top-level scope preserved, properties scope ignored
	assert.Equal(t, "external", result.Scope)
}

func TestPromoteKnownProperties_Tags(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
		Tags:        []string{"existing"},
		Properties: map[string]any{
			"tags": []any{"production", "critical"},
		},
	}

	result := app.PromoteKnownProperties(input)

	assert.Contains(t, result.Tags, "existing")
	assert.Contains(t, result.Tags, "production")
	assert.Contains(t, result.Tags, "critical")
	assert.Nil(t, result.Properties["tags"])
}

func TestPromoteKnownProperties_TagsString(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
		Properties: map[string]any{
			"tags": "prod, staging, critical",
		},
	}

	result := app.PromoteKnownProperties(input)

	assert.Contains(t, result.Tags, "prod")
	assert.Contains(t, result.Tags, "staging")
	assert.Contains(t, result.Tags, "critical")
}

func TestPromoteKnownProperties_RemoveColumnNames(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
		Properties: map[string]any{
			"name":        "should-be-removed",
			"tenant_id":   "should-be-removed",
			"criticality": "should-be-removed",
			"status":      "should-be-removed",
			"owner_ref":   "should-be-removed",
			"vendor":      "should-stay",
		},
	}

	result := app.PromoteKnownProperties(input)

	assert.Nil(t, result.Properties["name"])
	assert.Nil(t, result.Properties["tenant_id"])
	assert.Nil(t, result.Properties["criticality"])
	assert.Nil(t, result.Properties["status"])
	assert.Nil(t, result.Properties["owner_ref"])
	assert.Equal(t, "should-stay", result.Properties["vendor"])
}

func TestPromoteKnownProperties_EmptyProperties(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
	}

	result := app.PromoteKnownProperties(input)

	// No panic, returns as-is
	assert.Equal(t, "host", result.Type)
	assert.Nil(t, result.Properties)
}

func TestPromoteKnownProperties_Description(t *testing.T) {
	input := app.CreateAssetInput{
		Name:        "srv-01",
		Type:        "host",
		Criticality: "high",
		Properties: map[string]any{
			"description": "From collector",
		},
	}

	result := app.PromoteKnownProperties(input)

	assert.Equal(t, "From collector", result.Description)
	assert.Nil(t, result.Properties["description"])
}
