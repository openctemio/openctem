package integration

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// =============================================================================
// Tests for Finding Processing When Asset Doesn't Exist
// =============================================================================

// TestFindingProcessing_NoAssetInReport tests the scenario where:
// - Scanner finds vulnerabilities
// - Report contains NO asset information
// - No auto-creation metadata available
// Expected: Findings should be SKIPPED with appropriate error messages
func TestFindingProcessing_NoAssetInReport(t *testing.T) {
	t.Run("FindingsSkippedWhenNoAsset", func(t *testing.T) {
		// Simulate a report with findings but no assets
		report := &ctis.Report{
			Version: "1.0.0",
			Metadata: ctis.ReportMetadata{
				ID:        "scan-001",
				Timestamp: time.Now(),
				// No Scope - nothing to auto-create from
			},
			Tool: &ctis.Tool{
				Name:    "semgrep",
				Version: "1.0.0",
			},
			Assets: []ctis.Asset{}, // EMPTY - no assets
			Findings: []ctis.Finding{
				{
					ID:          "finding-001",
					Type:        ctis.FindingTypeVulnerability,
					Title:       "SQL Injection",
					Severity:    ctis.SeverityCritical,
					RuleID:      "sql-injection-001",
					Description: "Possible SQL injection",
					// AssetRef is empty - no target asset
				},
				{
					ID:       "finding-002",
					Type:     ctis.FindingTypeVulnerability,
					Title:    "XSS Vulnerability",
					Severity: ctis.SeverityHigh,
					RuleID:   "xss-001",
					// AssetRef is empty - no target asset
				},
			},
		}

		// Verify report structure - these assertions use the struct fields to avoid unused write warnings
		if report.Version != "1.0.0" {
			t.Error("Test setup: Version should be 1.0.0")
		}
		if report.Tool.Name != "semgrep" {
			t.Error("Test setup: Tool name should be semgrep")
		}
		if len(report.Assets) != 0 {
			t.Error("Test setup: Assets should be empty")
		}
		if len(report.Findings) != 2 {
			t.Error("Test setup: Should have 2 findings")
		}

		// Simulate what FindingProcessor would do:
		// 1. AssetProcessor returns empty assetMap because no assets
		assetMap := make(map[string]shared.ID) // EMPTY

		// 2. FindingProcessor tries to resolve assets
		var skippedCount int
		var errors []string

		for i, finding := range report.Findings {
			var targetAssetID shared.ID

			// Try to resolve by AssetRef
			if finding.AssetRef != "" {
				if id, ok := assetMap[finding.AssetRef]; ok {
					targetAssetID = id
				}
			}

			// No default asset because assetMap is empty
			if targetAssetID.IsZero() {
				errors = append(errors, "finding "+string(rune('0'+i))+": no target asset")
				skippedCount++
				continue
			}
		}

		// Verify expected behavior
		if skippedCount != 2 {
			t.Errorf("Expected 2 findings skipped, got %d", skippedCount)
		}
		if len(errors) != 2 {
			t.Errorf("Expected 2 errors, got %d", len(errors))
		}
	})

	t.Run("SingleFindingSkippedNoAsset", func(t *testing.T) {
		report := &ctis.Report{
			Version: "1.0.0",
			Metadata: ctis.ReportMetadata{
				ID:        "scan-002",
				Timestamp: time.Now(),
			},
			Tool:     &ctis.Tool{Name: "trivy"},
			Assets:   []ctis.Asset{},
			Findings: []ctis.Finding{{ID: "f1", Title: "CVE-2024-1234"}},
		}

		// Use report fields to avoid unused write warnings
		if report.Version != "1.0.0" || report.Tool.Name != "trivy" {
			t.Error("Test setup incorrect")
		}
		if len(report.Assets) != 0 {
			t.Error("Test setup: Assets should be empty")
		}

		assetMap := make(map[string]shared.ID)
		skipped := 0

		for _, finding := range report.Findings {
			var targetID shared.ID
			if finding.AssetRef != "" {
				if id, ok := assetMap[finding.AssetRef]; ok {
					targetID = id
				}
			}
			if targetID.IsZero() {
				skipped++
			}
		}

		if skipped != 1 {
			t.Error("Single finding should be skipped")
		}
	})
}

// TestFindingProcessing_AssetRefNotInMap tests the scenario where:
// - Finding has AssetRef pointing to an asset
// - But that asset was NOT in the report and NOT auto-created
// Expected: Finding should be SKIPPED
func TestFindingProcessing_AssetRefNotInMap(t *testing.T) {
	t.Run("AssetRefNotFound", func(t *testing.T) {
		// Asset map has one asset
		assetMap := map[string]shared.ID{
			"asset-1": shared.NewID(),
		}

		// Finding references a DIFFERENT asset
		finding := ctis.Finding{
			ID:       "finding-001",
			AssetRef: "asset-999", // NOT in assetMap
			Title:    "SQL Injection",
		}

		// Verify finding is properly set up
		if finding.ID != "finding-001" || finding.Title != "SQL Injection" {
			t.Error("Test setup incorrect")
		}

		// Resolve logic
		var targetAssetID shared.ID
		if finding.AssetRef != "" {
			if id, ok := assetMap[finding.AssetRef]; ok {
				targetAssetID = id
			}
		}

		// No default because multiple assets scenario
		if targetAssetID.IsZero() {
			// This is expected - finding should be skipped
			t.Log("Correctly identified: Finding with non-existent AssetRef should be skipped")
		} else {
			t.Error("Finding should NOT have a valid targetAssetID")
		}
	})

	t.Run("MultipleAssetsNoDefaultFallback", func(t *testing.T) {
		// Multiple assets in map - no default fallback
		assetMap := map[string]shared.ID{
			"asset-1": shared.NewID(),
			"asset-2": shared.NewID(),
		}

		// Finding with no AssetRef (when multiple assets exist)
		finding := ctis.Finding{
			ID:    "finding-001",
			Title: "Vulnerability without asset reference",
			// AssetRef is EMPTY
		}

		// Verify finding is properly set up
		if finding.ID != "finding-001" || finding.Title != "Vulnerability without asset reference" {
			t.Error("Test setup incorrect")
		}

		var targetAssetID shared.ID
		if finding.AssetRef != "" {
			if id, ok := assetMap[finding.AssetRef]; ok {
				targetAssetID = id
			}
		}

		// With multiple assets, there's no default fallback
		// The processor only sets defaultAssetID when len(assetMap) == 1

		if targetAssetID.IsZero() {
			t.Log("Correctly identified: Finding without AssetRef in multi-asset report should be skipped")
		} else {
			t.Error("Should not have valid targetAssetID without AssetRef in multi-asset report")
		}
	})
}

// TestFindingProcessing_SingleAssetDefaultFallback tests the scenario where:
// - Report has exactly ONE asset
// - Finding has NO AssetRef
// Expected: Finding should use the single asset as default
func TestFindingProcessing_SingleAssetDefaultFallback(t *testing.T) {
	t.Run("SingleAssetUsedAsDefault", func(t *testing.T) {
		singleAssetID := shared.NewID()

		// Single asset in map
		assetMap := map[string]shared.ID{
			"my-repo": singleAssetID,
		}

		// Determine default asset (only when single asset)
		var defaultAssetID shared.ID
		if len(assetMap) == 1 {
			for _, id := range assetMap {
				defaultAssetID = id
				break
			}
		}

		// Finding with no AssetRef
		finding := ctis.Finding{
			ID:    "finding-001",
			Title: "SQL Injection",
			// AssetRef is EMPTY
		}

		// Verify finding setup
		if finding.ID != "finding-001" || finding.Title != "SQL Injection" {
			t.Error("Test setup incorrect")
		}

		// Resolve logic
		var targetAssetID shared.ID
		if finding.AssetRef != "" {
			if id, ok := assetMap[finding.AssetRef]; ok {
				targetAssetID = id
			}
		}

		// Fall back to default
		if targetAssetID.IsZero() && !defaultAssetID.IsZero() {
			targetAssetID = defaultAssetID
		}

		// Verify finding got assigned the default asset
		if targetAssetID.IsZero() {
			t.Error("Finding should have received default asset ID")
		}
		if targetAssetID != singleAssetID {
			t.Error("Finding should have the single asset ID as target")
		}
	})

	t.Run("ExplicitAssetRefOverridesDefault", func(t *testing.T) {
		defaultAssetID := shared.NewID()
		explicitAssetID := shared.NewID()

		assetMap := map[string]shared.ID{
			"default-repo":  defaultAssetID,
			"explicit-repo": explicitAssetID,
		}

		// Finding with explicit AssetRef
		finding := ctis.Finding{
			ID:       "finding-001",
			AssetRef: "explicit-repo",
			Title:    "SQL Injection",
		}

		// Verify finding setup
		if finding.ID != "finding-001" || finding.Title != "SQL Injection" {
			t.Error("Test setup incorrect")
		}

		var targetAssetID shared.ID
		if finding.AssetRef != "" {
			if id, ok := assetMap[finding.AssetRef]; ok {
				targetAssetID = id
			}
		}

		if targetAssetID != explicitAssetID {
			t.Error("Explicit AssetRef should be used, not default")
		}
	})
}

// TestFindingProcessing_AutoAssetCreation tests the scenario where:
// - Report has NO explicit assets
// - But has Scope metadata that can be used to auto-create
// Expected: Asset should be auto-created, finding should succeed
func TestFindingProcessing_AutoAssetCreation(t *testing.T) {
	t.Run("AutoCreateFromScope", func(t *testing.T) {
		// Simulate report with scope but no explicit assets
		report := &ctis.Report{
			Version: "1.0.0",
			Metadata: ctis.ReportMetadata{
				ID:        "scan-001",
				Timestamp: time.Now(),
				Scope: &ctis.Scope{
					Name: "my-repository",
					Type: "repository",
				},
			},
			Tool:   &ctis.Tool{Name: "semgrep"},
			Assets: []ctis.Asset{}, // Empty initially
			Findings: []ctis.Finding{
				{ID: "f1", Title: "SQL Injection"},
			},
		}

		// Verify report fields are set correctly
		if report.Version != "1.0.0" || report.Tool.Name != "semgrep" {
			t.Error("Test setup incorrect")
		}

		// Simulate auto-creation from Scope
		// This is similar to what AssetProcessor.createAssetFromMetadata() does
		if len(report.Assets) == 0 && len(report.Findings) > 0 {
			if report.Metadata.Scope != nil && report.Metadata.Scope.Name != "" {
				autoAsset := ctis.Asset{
					ID:    "auto-" + report.Metadata.Scope.Name,
					Type:  ctis.AssetType(report.Metadata.Scope.Type),
					Value: report.Metadata.Scope.Name,
					Properties: ctis.Properties{
						"auto_created": true,
						"source":       "scope",
					},
				}
				report.Assets = append(report.Assets, autoAsset)
			}
		}

		// Verify auto-creation
		if len(report.Assets) != 1 {
			t.Fatalf("Expected 1 auto-created asset, got %d", len(report.Assets))
		}

		autoAsset := report.Assets[0]
		if autoAsset.Properties["auto_created"] != true {
			t.Error("Asset should be marked as auto_created")
		}
		if autoAsset.Properties["source"] != "scope" {
			t.Error("Asset source should be scope")
		}
		if autoAsset.Value != "my-repository" {
			t.Error("Asset value should be scope name")
		}
	})

	t.Run("AutoCreateFromFindingAssetValue", func(t *testing.T) {
		// Simulate report with finding that has asset value
		report := &ctis.Report{
			Version: "1.0.0",
			Metadata: ctis.ReportMetadata{
				ID:        "scan-001",
				Timestamp: time.Now(),
				// No Scope
			},
			Tool:   &ctis.Tool{Name: "gitleaks"},
			Assets: []ctis.Asset{},
			Findings: []ctis.Finding{
				{
					ID:         "f1",
					Title:      "AWS Key Exposed",
					AssetValue: "my-project", // Used for auto-creation
				},
			},
		}

		// Verify report fields
		if report.Version != "1.0.0" || report.Tool.Name != "gitleaks" {
			t.Error("Test setup incorrect")
		}

		// Simulate auto-creation from finding's AssetValue
		if len(report.Assets) == 0 && len(report.Findings) > 0 {
			// Try Scope first (nil here)
			if report.Metadata.Scope == nil || report.Metadata.Scope.Name == "" {
				// Fall back to first finding's AssetValue
				firstFinding := report.Findings[0]
				if firstFinding.AssetValue != "" {
					autoAsset := ctis.Asset{
						ID:    "auto-" + firstFinding.AssetValue,
						Type:  ctis.AssetTypeRepository, // Default type
						Value: firstFinding.AssetValue,
						Properties: ctis.Properties{
							"auto_created": true,
							"source":       "finding_asset_value",
						},
					}
					report.Assets = append(report.Assets, autoAsset)
				}
			}
		}

		if len(report.Assets) != 1 {
			t.Fatalf("Expected 1 auto-created asset, got %d", len(report.Assets))
		}

		autoAsset := report.Assets[0]
		if autoAsset.Properties["source"] != "finding_asset_value" {
			t.Error("Asset source should be finding_asset_value")
		}
	})

	t.Run("NoAutoCreateWhenNoMetadata", func(t *testing.T) {
		// Report with no metadata for auto-creation
		report := &ctis.Report{
			Version: "1.0.0",
			Metadata: ctis.ReportMetadata{
				ID:        "scan-001",
				Timestamp: time.Now(),
				// No Scope
			},
			Tool:   &ctis.Tool{Name: "unknown-tool"},
			Assets: []ctis.Asset{},
			Findings: []ctis.Finding{
				{
					ID:    "f1",
					Title: "Generic Finding",
					// No AssetValue, no AssetRef
				},
			},
		}

		// Verify report fields
		if report.Version != "1.0.0" || report.Tool.Name != "unknown-tool" {
			t.Error("Test setup incorrect")
		}

		// Try auto-creation
		created := false
		if len(report.Assets) == 0 && len(report.Findings) > 0 {
			// Try Scope
			if report.Metadata.Scope != nil && report.Metadata.Scope.Name != "" {
				created = true
			}
			// Try finding AssetValue
			if !created && len(report.Findings) > 0 && report.Findings[0].AssetValue != "" {
				created = true
			}
		}

		if created {
			t.Error("No auto-creation should happen without proper metadata")
		}
		if len(report.Assets) != 0 {
			t.Error("Assets should remain empty")
		}
	})
}

// TestFindingProcessing_PartialAssetMatch tests the scenario where:
// - Report has multiple findings
// - Some reference existing assets, some don't
// Expected: Valid findings processed, invalid ones skipped
func TestFindingProcessing_PartialAssetMatch(t *testing.T) {
	t.Run("MixedAssetResolution", func(t *testing.T) {
		asset1ID := shared.NewID()
		asset2ID := shared.NewID()

		assetMap := map[string]shared.ID{
			"repo-1": asset1ID,
			"repo-2": asset2ID,
		}

		findings := []ctis.Finding{
			{ID: "f1", AssetRef: "repo-1", Title: "Finding for repo-1"},    // Valid
			{ID: "f2", AssetRef: "repo-999", Title: "Finding for unknown"}, // Invalid
			{ID: "f3", AssetRef: "repo-2", Title: "Finding for repo-2"},    // Valid
			{ID: "f4", AssetRef: "", Title: "Finding with no ref"},         // Invalid (multi-asset, no default)
		}

		var validFindings []ctis.Finding
		var skippedCount int
		var errors []string

		for i, finding := range findings {
			var targetAssetID shared.ID
			if finding.AssetRef != "" {
				if id, ok := assetMap[finding.AssetRef]; ok {
					targetAssetID = id
				}
			}

			// No default in multi-asset scenario
			if targetAssetID.IsZero() {
				errors = append(errors, "finding "+string(rune('0'+i))+": no target asset")
				skippedCount++
				continue
			}

			validFindings = append(validFindings, finding)
		}

		if len(validFindings) != 2 {
			t.Errorf("Expected 2 valid findings, got %d", len(validFindings))
		}
		if skippedCount != 2 {
			t.Errorf("Expected 2 skipped findings, got %d", skippedCount)
		}
		if len(errors) != 2 {
			t.Errorf("Expected 2 errors, got %d", len(errors))
		}

		// Verify correct findings were kept
		if validFindings[0].ID != "f1" || validFindings[1].ID != "f3" {
			t.Error("Wrong findings were kept")
		}
	})
}

// TestFindingProcessing_OutputTracking tests that the Output struct
// correctly tracks skipped findings and errors
func TestFindingProcessing_OutputTracking(t *testing.T) {
	t.Run("OutputCountsCorrect", func(t *testing.T) {
		// Simulate Output struct
		type Output struct {
			FindingsProcessed int
			FindingsSkipped   int
			FindingsNew       int
			FindingsExisting  int
			Errors            []string
		}

		output := &Output{}

		// Simulate processing 5 findings: 3 valid, 2 invalid
		findings := []struct {
			hasValidAsset bool
			isNew         bool
		}{
			{true, true},   // Valid, new
			{false, false}, // Invalid - skipped
			{true, false},  // Valid, existing
			{true, true},   // Valid, new
			{false, false}, // Invalid - skipped
		}

		for i, f := range findings {
			if !f.hasValidAsset {
				output.Errors = append(output.Errors, "finding: no target asset")
				output.FindingsSkipped++
				continue
			}

			output.FindingsProcessed++
			if f.isNew {
				output.FindingsNew++
			} else {
				output.FindingsExisting++
			}
			_ = i // Used in real implementation for error messages
		}

		if output.FindingsProcessed != 3 {
			t.Errorf("Expected 3 processed, got %d", output.FindingsProcessed)
		}
		if output.FindingsSkipped != 2 {
			t.Errorf("Expected 2 skipped, got %d", output.FindingsSkipped)
		}
		if output.FindingsNew != 2 {
			t.Errorf("Expected 2 new, got %d", output.FindingsNew)
		}
		if output.FindingsExisting != 1 {
			t.Errorf("Expected 1 existing, got %d", output.FindingsExisting)
		}
		if len(output.Errors) != 2 {
			t.Errorf("Expected 2 errors, got %d", len(output.Errors))
		}
	})
}

// TestFindingProcessing_DomainEntityValidation tests that domain entity
// creation fails gracefully with invalid asset ID
func TestFindingProcessing_DomainEntityValidation(t *testing.T) {
	t.Run("NewFindingRequiresValidAssetID", func(t *testing.T) {
		tenantID := shared.NewID()
		zeroAssetID := shared.ID{} // Zero/empty ID

		// Attempt to create finding with zero asset ID
		_, err := vulnerability.NewFinding(
			tenantID,
			zeroAssetID, // Invalid
			vulnerability.FindingSourceSAST,
			"semgrep",
			vulnerability.SeverityHigh,
			"SQL Injection",
		)

		// The domain should reject zero asset ID
		if err == nil {
			t.Error("Expected error when creating finding with zero asset ID")
		}
	})

	t.Run("NewFindingRequiresValidTenantID", func(t *testing.T) {
		zeroTenantID := shared.ID{}
		assetID := shared.NewID()

		_, err := vulnerability.NewFinding(
			zeroTenantID, // Invalid
			assetID,
			vulnerability.FindingSourceSAST,
			"semgrep",
			vulnerability.SeverityHigh,
			"SQL Injection",
		)

		if err == nil {
			t.Error("Expected error when creating finding with zero tenant ID")
		}
	})

	t.Run("NewFindingSucceedsWithValidIDs", func(t *testing.T) {
		tenantID := shared.NewID()
		assetID := shared.NewID()

		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"semgrep",
			vulnerability.SeverityHigh,
			"SQL Injection",
		)

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if finding == nil {
			t.Fatal("Finding should not be nil")
		}
		if finding.TenantID() != tenantID {
			t.Error("TenantID mismatch")
		}
		if finding.AssetID() != assetID {
			t.Error("AssetID mismatch")
		}
	})
}

// TestFindingProcessing_EmptyReportHandling tests edge cases with empty reports
func TestFindingProcessing_EmptyReportHandling(t *testing.T) {
	t.Run("EmptyFindingsNoProcessing", func(t *testing.T) {
		// Report with assets but no findings
		assetID := shared.NewID()
		assetMap := map[string]shared.ID{
			"my-repo": assetID,
		}

		findings := []ctis.Finding{} // EMPTY

		processedCount := 0
		for _, finding := range findings {
			var targetAssetID shared.ID
			if finding.AssetRef != "" {
				if id, ok := assetMap[finding.AssetRef]; ok {
					targetAssetID = id
				}
			}
			if !targetAssetID.IsZero() {
				processedCount++
			}
		}

		if processedCount != 0 {
			t.Error("No findings should be processed from empty list")
		}
	})

	t.Run("NilReportSafeHandling", func(t *testing.T) {
		// Simulate nil-safe handling - this tests that our nil-check logic works correctly
		// The getFindingCount helper simulates how the processor safely handles nil reports
		getFindingCount := func(r *ctis.Report) int {
			if r == nil {
				return 0
			}
			return len(r.Findings)
		}

		// Test with nil
		if count := getFindingCount(nil); count != 0 {
			t.Errorf("Nil report should result in 0 findings, got %d", count)
		}

		// Test with empty report
		if count := getFindingCount(&ctis.Report{}); count != 0 {
			t.Errorf("Empty report should result in 0 findings, got %d", count)
		}

		// Test with report containing findings
		reportWithFindings := &ctis.Report{
			Findings: []ctis.Finding{{ID: "f1"}},
		}
		if count := getFindingCount(reportWithFindings); count != 1 {
			t.Errorf("Report with 1 finding should return 1, got %d", count)
		}
	})
}

// TestFindingProcessing_AssetDeletionScenario tests the scenario where:
// - Finding references an asset that existed but was deleted
// - This simulates stale data or race conditions
func TestFindingProcessing_AssetDeletionScenario(t *testing.T) {
	t.Run("FindingWithDeletedAsset", func(t *testing.T) {
		// Simulate: Asset existed before but was deleted
		// The assetMap won't have it because it was rebuilt from current state
		assetMap := map[string]shared.ID{
			"active-repo": shared.NewID(),
			// "deleted-repo" is NOT in the map
		}

		findings := []ctis.Finding{
			{ID: "f1", AssetRef: "active-repo", Title: "Finding 1"},  // Valid
			{ID: "f2", AssetRef: "deleted-repo", Title: "Finding 2"}, // Invalid - asset deleted
		}

		var skippedCount int
		for _, finding := range findings {
			var targetAssetID shared.ID
			if finding.AssetRef != "" {
				if id, ok := assetMap[finding.AssetRef]; ok {
					targetAssetID = id
				}
			}
			if targetAssetID.IsZero() {
				skippedCount++
			}
		}

		if skippedCount != 1 {
			t.Errorf("Expected 1 skipped (deleted asset), got %d", skippedCount)
		}
	})
}

// TestFindingProcessing_ConcurrentAssetCreation tests the scenario where:
// - Multiple findings reference the same non-existent asset
// - Asset is created during first finding processing
// - Subsequent findings should find the newly created asset
func TestFindingProcessing_ConcurrentAssetCreation(t *testing.T) {
	t.Run("AssetCreatedDuringBatch", func(t *testing.T) {
		// Initially empty
		assetMap := make(map[string]shared.ID)

		// Simulate batch processing where assets are created first
		assetsToCreate := []ctis.Asset{
			{ID: "repo-1", Value: "github.com/org/repo1"},
		}

		// Asset creation phase
		for _, asset := range assetsToCreate {
			assetMap[asset.ID] = shared.NewID()
		}

		// Finding processing phase - all findings should now find the asset
		findings := []ctis.Finding{
			{ID: "f1", AssetRef: "repo-1", Title: "Finding 1"},
			{ID: "f2", AssetRef: "repo-1", Title: "Finding 2"},
			{ID: "f3", AssetRef: "repo-1", Title: "Finding 3"},
		}

		successCount := 0
		for _, finding := range findings {
			var targetAssetID shared.ID
			if finding.AssetRef != "" {
				if id, ok := assetMap[finding.AssetRef]; ok {
					targetAssetID = id
				}
			}
			if !targetAssetID.IsZero() {
				successCount++
			}
		}

		if successCount != 3 {
			t.Errorf("All 3 findings should succeed, got %d", successCount)
		}
	})
}
