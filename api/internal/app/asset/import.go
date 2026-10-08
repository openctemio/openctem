package asset

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetImportService handles bulk asset import from various formats.
type AssetImportService struct {
	assetRepo assetdom.Repository
	logger    *logger.Logger
}

// NewAssetImportService creates a new AssetImportService.
func NewAssetImportService(assetRepo assetdom.Repository, log *logger.Logger) *AssetImportService {
	return &AssetImportService{
		assetRepo: assetRepo,
		logger:    log.With("service", "asset-import"),
	}
}

// AssetImportResult contains the result of an import operation.
type AssetImportResult struct {
	AssetsCreated int      `json:"assets_created"`
	AssetsUpdated int      `json:"assets_updated"`
	AssetsSkipped int      `json:"assets_skipped"`
	Errors        []string `json:"errors,omitempty"`
}

// ImportCSVAssets imports assets from CSV data.
// Expected columns: name, type, sub_type, description, tags, properties (JSON)
func (s *AssetImportService) ImportCSVAssets(ctx context.Context, tenantID string, reader io.Reader) (*AssetImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	csvReader := csv.NewReader(reader)
	header, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read CSV header", shared.ErrValidation)
	}

	colIndex := make(map[string]int, len(header))
	for i, col := range header {
		colIndex[strings.ToLower(strings.TrimSpace(col))] = i
	}

	nameIdx, hasName := colIndex["name"]
	typeIdx, hasType := colIndex["type"]
	if !hasName || !hasType {
		return nil, fmt.Errorf("%w: CSV must have 'name' and 'type' columns", shared.ErrValidation)
	}

	const maxRows = 100000
	const maxErrors = 100

	result := &AssetImportResult{}
	for rowNum := 0; rowNum < maxRows; rowNum++ {
		record, readErr := csvReader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			if len(result.Errors) < maxErrors {
				result.Errors = append(result.Errors, fmt.Sprintf("row %d: %v", rowNum+2, readErr))
			}
			continue
		}

		name := strings.TrimSpace(record[nameIdx])
		assetType := strings.TrimSpace(record[typeIdx])
		if name == "" || assetType == "" {
			result.AssetsSkipped++
			continue
		}

		subType := ""
		if idx, ok := colIndex["sub_type"]; ok && idx < len(record) {
			subType = strings.TrimSpace(record[idx])
		}
		// Resolve aliases and legacy sub-types to the stored pair
		// (RFC-042 §6.3.8); an unknown type or sub-type is a row error.
		resolved, resolveErr := assetdom.ResolveInputType(assetType, subType)
		if resolveErr != nil {
			if len(result.Errors) < maxErrors {
				result.Errors = append(result.Errors, fmt.Sprintf("row %d (%s): %v", rowNum+2, name, resolveErr))
			}
			continue
		}
		// Normalize with the sub-type, as lookups do (RFC-043 section 10).
		a, createErr := assetdom.NewAssetWithSubType(name, resolved.Type, resolved.SubType, assetdom.CriticalityMedium)
		if createErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid asset %s: %v", name, createErr))
			continue
		}
		a.SetTenantID(tid)
		if idx, ok := colIndex["description"]; ok && idx < len(record) {
			a.UpdateDescription(strings.TrimSpace(record[idx]))
		}
		if idx, ok := colIndex["tags"]; ok && idx < len(record) {
			for _, t := range strings.Split(record[idx], ";") {
				if t = strings.TrimSpace(t); t != "" {
					a.AddTag(t)
				}
			}
		}
		if idx, ok := colIndex["properties"]; ok && idx < len(record) {
			var props map[string]any
			if json.Unmarshal([]byte(record[idx]), &props) == nil {
				assetdom.NormalizeAssetProperties(resolved.Type, resolved.SubType, props)
				err := RejectReservedProperties(props)
				if err == nil {
					err = rejectMisplacedProperties(resolved.Type, resolved.SubType, props)
				}
				if err != nil {
					if len(result.Errors) < maxErrors {
						result.Errors = append(result.Errors, fmt.Sprintf("row %d: %v", rowNum+2, err))
					}
					continue
				}
				a.SetProperties(props)
			}
		}
		a.ApplyResolvedType(resolved)

		if createErr := s.assetRepo.Create(ctx, a); createErr != nil {
			if strings.Contains(createErr.Error(), "already exists") {
				result.AssetsSkipped++
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("create %s: %v", name, createErr))
			}
			continue
		}
		result.AssetsCreated++
	}

	s.logger.Info("CSV asset import completed",
		"tenant_id", tenantID,
		"created", result.AssetsCreated,
		"skipped", result.AssetsSkipped,
	)
	return result, nil
}
