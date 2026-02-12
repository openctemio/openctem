package ingest

import (
	"encoding/json"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/validator"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// Validator validates ingest inputs.
type Validator struct {
	propsValidator *validator.PropertiesValidator
}

// NewValidator creates a new ingest validator.
func NewValidator() *Validator {
	return &Validator{
		propsValidator: validator.NewPropertiesValidator(),
	}
}

// ValidateReport validates a CTIS report.
func (v *Validator) ValidateReport(report *ctis.Report) error {
	if len(report.Assets) > MaxAssetsPerReport {
		return shared.NewDomainError("PAYLOAD_TOO_LARGE",
			fmt.Sprintf("report contains %d assets, maximum is %d", len(report.Assets), MaxAssetsPerReport), nil)
	}

	if len(report.Findings) > MaxFindingsPerReport {
		return shared.NewDomainError("PAYLOAD_TOO_LARGE",
			fmt.Sprintf("report contains %d findings, maximum is %d", len(report.Findings), MaxFindingsPerReport), nil)
	}

	return nil
}

// ValidateAssetProperties validates asset properties and returns warnings.
func (v *Validator) ValidateAssetProperties(assetType string, properties map[string]any) []string {
	if v.propsValidator == nil {
		return nil
	}

	errs := v.propsValidator.ValidateProperties(assetType, properties)
	if errs == nil {
		return nil
	}

	warnings := make([]string, 0, len(errs))
	for _, err := range errs {
		warnings = append(warnings, fmt.Sprintf("%s: %s", err.Path, err.Message))
	}
	return warnings
}

// ValidatePropertySize checks if any property value exceeds the maximum allowed size.
// Returns the key of the first oversized property, or empty string if all are valid.
func (v *Validator) ValidatePropertySize(properties map[string]any) (oversizedKey string, size int) {
	for key, value := range properties {
		// Marshal value to JSON to get its size
		data, err := json.Marshal(value)
		if err != nil {
			continue
		}
		if len(data) > MaxPropertySize {
			return key, len(data)
		}
	}
	return "", 0
}

// ValidatePropertiesCount checks if the number of properties exceeds the limit.
func (v *Validator) ValidatePropertiesCount(properties map[string]any) bool {
	return len(properties) <= MaxPropertiesPerAsset
}
