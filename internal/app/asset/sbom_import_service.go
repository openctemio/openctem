package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	componentdom "github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SPDX specifies "NOASSERTION" as the string used when a licence
// cannot be determined. Treat it like an empty value.
//
// CycloneDX uses "optional" and "excluded" for scope values that mean
// the component is not a direct runtime dependency — mapped to
// transitive on import.
const (
	spdxLicenseNoAssertion    = "NOASSERTION"
	cycloneDXScopeOptional    = "optional"
	cycloneDXScopeExcluded    = "excluded"
	cycloneDXExtRefTypePurl   = "purl"
)

// SBOMImportService handles importing SBOM files (CycloneDX, SPDX).
type SBOMImportService struct {
	repo   componentdom.Repository
	logger *logger.Logger
}

// NewSBOMImportService creates a new SBOMImportService.
func NewSBOMImportService(repo componentdom.Repository, log *logger.Logger) *SBOMImportService {
	return &SBOMImportService{
		repo:   repo,
		logger: log.With("service", "sbom-import"),
	}
}

// SBOMImportResult contains the result of an SBOM import.
type SBOMImportResult struct {
	Format           string   `json:"format"`            // cyclonedx or spdx
	SpecVersion      string   `json:"spec_version"`
	ComponentsTotal  int      `json:"components_total"`   // total in file
	ComponentsImported int    `json:"components_imported"` // successfully imported
	ComponentsSkipped  int    `json:"components_skipped"`
	LicensesFound    int      `json:"licenses_found"`
	Errors           []string `json:"errors,omitempty"`
}

// ImportSBOM detects format and imports components from a SBOM file.
func (s *SBOMImportService) ImportSBOM(ctx context.Context, tenantID, assetID string, reader io.Reader) (*SBOMImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid asset ID", shared.ErrValidation)
	}

	// Read body (max 50MB)
	data, err := io.ReadAll(io.LimitReader(reader, 50*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM data: %w", err)
	}

	// Detect format
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON format", shared.ErrValidation)
	}

	if _, ok := raw["bomFormat"]; ok {
		return s.importCycloneDX(ctx, tid, aid, data)
	}
	if _, ok := raw["spdxVersion"]; ok {
		return s.importSPDX(ctx, tid, aid, data)
	}

	return nil, fmt.Errorf("%w: unrecognized SBOM format (expected CycloneDX or SPDX)", shared.ErrValidation)
}

// =============================================================================
// CycloneDX Import
// =============================================================================

type cycloneDXBOM struct {
	BOMFormat   string             `json:"bomFormat"`
	SpecVersion string             `json:"specVersion"`
	Components  []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	Type    string              `json:"type"`    // library, framework, application
	Name    string              `json:"name"`
	Version string              `json:"version"`
	PURL    string              `json:"purl"`
	Licenses []cycloneDXLicense `json:"licenses,omitempty"`
	Scope   string              `json:"scope,omitempty"` // required, optional, excluded
}

type cycloneDXLicense struct {
	License struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
}

func (s *SBOMImportService) importCycloneDX(ctx context.Context, tenantID, assetID shared.ID, data []byte) (*SBOMImportResult, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("%w: invalid CycloneDX JSON", shared.ErrValidation)
	}

	result := &SBOMImportResult{
		Format:          "cyclonedx",
		SpecVersion:     bom.SpecVersion,
		ComponentsTotal: len(bom.Components),
	}

	for _, comp := range bom.Components {
		if comp.Name == "" {
			result.ComponentsSkipped++
			continue
		}

		ecosystem := detectEcosystemFromPURL(comp.PURL)
		license := ""
		if len(comp.Licenses) > 0 {
			license = comp.Licenses[0].License.ID
			if license == "" {
				license = comp.Licenses[0].License.Name
			}
			result.LicensesFound++
		}

		depType := componentdom.DependencyTypeDirect
		if comp.Scope == cycloneDXScopeOptional || comp.Scope == cycloneDXScopeExcluded {
			depType = componentdom.DependencyTypeTransitive
		}

		if err := s.upsertComponent(ctx, tenantID, assetID, comp.Name, comp.Version, ecosystem, comp.PURL, license, depType); err != nil {
			if len(result.Errors) < 50 {
				result.Errors = append(result.Errors, fmt.Sprintf("%s@%s: %v", comp.Name, comp.Version, err))
			}
			result.ComponentsSkipped++
			continue
		}
		result.ComponentsImported++
	}

	s.logger.Info("CycloneDX import completed",
		"components_total", result.ComponentsTotal,
		"imported", result.ComponentsImported,
		"skipped", result.ComponentsSkipped,
	)
	return result, nil
}

// =============================================================================
// SPDX Import
// =============================================================================

type spdxDocument struct {
	SPDXVersion string          `json:"spdxVersion"`
	Packages    []spdxPackage   `json:"packages"`
}

type spdxPackage struct {
	Name            string `json:"name"`
	VersionInfo     string `json:"versionInfo"`
	ExternalRefs    []spdxExternalRef `json:"externalRefs,omitempty"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"` // PURL
}

func (s *SBOMImportService) importSPDX(ctx context.Context, tenantID, assetID shared.ID, data []byte) (*SBOMImportResult, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: invalid SPDX JSON", shared.ErrValidation)
	}

	result := &SBOMImportResult{
		Format:          "spdx",
		SpecVersion:     doc.SPDXVersion,
		ComponentsTotal: len(doc.Packages),
	}

	for _, pkg := range doc.Packages {
		if pkg.Name == "" {
			result.ComponentsSkipped++
			continue
		}

		// Extract PURL from external refs
		purl := ""
		for _, ref := range pkg.ExternalRefs {
			if ref.ReferenceType == cycloneDXExtRefTypePurl {
				purl = ref.ReferenceLocator
				break
			}
		}

		ecosystem := detectEcosystemFromPURL(purl)
		if ecosystem == "" {
			ecosystem = "other"
		}

		license := pkg.LicenseDeclared
		if license == "" || license == spdxLicenseNoAssertion {
			license = pkg.LicenseConcluded
		}
		if license == spdxLicenseNoAssertion {
			license = ""
		}
		if license != "" {
			result.LicensesFound++
		}

		if err := s.upsertComponent(ctx, tenantID, assetID, pkg.Name, pkg.VersionInfo, ecosystem, purl, license, componentdom.DependencyTypeDirect); err != nil {
			if len(result.Errors) < 50 {
				result.Errors = append(result.Errors, fmt.Sprintf("%s@%s: %v", pkg.Name, pkg.VersionInfo, err))
			}
			result.ComponentsSkipped++
			continue
		}
		result.ComponentsImported++
	}

	s.logger.Info("SPDX import completed",
		"components_total", result.ComponentsTotal,
		"imported", result.ComponentsImported,
		"skipped", result.ComponentsSkipped,
	)
	return result, nil
}

// =============================================================================
// Helpers
// =============================================================================

func (s *SBOMImportService) upsertComponent(
	ctx context.Context, tenantID, assetID shared.ID,
	name, version, ecosystem, purl, license string,
	depType componentdom.DependencyType,
) error {
	eco, err := componentdom.ParseEcosystem(ecosystem)
	if err != nil {
		eco = componentdom.EcosystemOther
	}

	c, err := componentdom.NewComponent(name, version, eco)
	if err != nil {
		return err
	}

	if purl != "" {
		c.SetPURL(purl)
	}
	if license != "" {
		c.UpdateLicense(license)
	}

	compID, err := s.repo.Upsert(ctx, c)
	if err != nil {
		return fmt.Errorf("upsert: %w", err)
	}

	dep, err := componentdom.NewAssetDependency(tenantID, assetID, compID, "", depType)
	if err != nil {
		return fmt.Errorf("dependency: %w", err)
	}

	if err := s.repo.LinkAsset(ctx, dep); err != nil {
		// Duplicate link is OK — skip silently
		if !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "duplicate") {
			return fmt.Errorf("link: %w", err)
		}
	}

	// Link license if available
	if license != "" {
		_, _ = s.repo.LinkLicenses(ctx, compID, []string{license})
	}

	return nil
}

// detectEcosystemFromPURL extracts the ecosystem from a Package URL.
// Example: "pkg:npm/express@4.18.2" → "npm"
func detectEcosystemFromPURL(purl string) string {
	if purl == "" {
		return "other"
	}
	// pkg:TYPE/...
	purl = strings.TrimPrefix(purl, "pkg:")
	idx := strings.Index(purl, "/")
	if idx <= 0 {
		return "other"
	}
	ecosystem := purl[:idx]
	// Normalize known aliases
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	case "golang", "go":
		return "go"
	case "cargo":
		return "cargo"
	case "nuget":
		return "nuget"
	case "gem", "rubygems":
		return "rubygems"
	case "composer", "packagist":
		return "composer"
	case "cocoapods":
		return "cocoapods"
	case "hex":
		return "hex"
	case "pub":
		return "pub"
	case "swift", "swiftpm":
		return "swiftpm"
	default:
		return "other"
	}
}
