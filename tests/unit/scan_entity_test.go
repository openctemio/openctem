package unit

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestScanAssetGroupIDs tests the AssetGroupIDs functionality in Scan entity.
//
// Run with: go test -v ./tests/unit -run TestScanAssetGroupIDs
func TestScanAssetGroupIDs(t *testing.T) {
	tenantID := shared.NewID()
	assetGroupID := shared.NewID()

	t.Run("NewScan_InitializesEmptyAssetGroupIDs", func(t *testing.T) {
		sc, err := scan.NewScan(tenantID, "Test Scan", assetGroupID, scan.ScanTypeSingle)
		if err != nil {
			t.Fatalf("Failed to create scan: %v", err)
		}

		if sc.AssetGroupIDs == nil {
			t.Error("Expected AssetGroupIDs to be initialized, got nil")
		}
		if len(sc.AssetGroupIDs) != 0 {
			t.Errorf("Expected empty AssetGroupIDs, got %d items", len(sc.AssetGroupIDs))
		}
	})

	t.Run("NewScanWithTargets_InitializesEmptyAssetGroupIDs", func(t *testing.T) {
		targets := []string{"example.com", "test.com"}
		sc, err := scan.NewScanWithTargets(tenantID, "Target Scan", targets, scan.ScanTypeSingle)
		if err != nil {
			t.Fatalf("Failed to create scan with targets: %v", err)
		}

		if sc.AssetGroupIDs == nil {
			t.Error("Expected AssetGroupIDs to be initialized, got nil")
		}
		if len(sc.AssetGroupIDs) != 0 {
			t.Errorf("Expected empty AssetGroupIDs, got %d items", len(sc.AssetGroupIDs))
		}
	})

	t.Run("SetAssetGroupIDs_SetsMultipleGroups", func(t *testing.T) {
		sc, _ := scan.NewScan(tenantID, "Multi Group Scan", assetGroupID, scan.ScanTypeSingle)

		group1 := shared.NewID()
		group2 := shared.NewID()
		group3 := shared.NewID()

		sc.SetAssetGroupIDs([]shared.ID{group1, group2, group3})

		if len(sc.AssetGroupIDs) != 3 {
			t.Errorf("Expected 3 asset group IDs, got %d", len(sc.AssetGroupIDs))
		}
		if sc.AssetGroupIDs[0] != group1 {
			t.Errorf("Expected first group ID %s, got %s", group1, sc.AssetGroupIDs[0])
		}
	})

	t.Run("SetAssetGroupIDs_SetsPrimaryIfNotSet", func(t *testing.T) {
		targets := []string{"example.com"}
		sc, _ := scan.NewScanWithTargets(tenantID, "Target Scan", targets, scan.ScanTypeSingle)

		// Initially no AssetGroupID
		if !sc.AssetGroupID.IsZero() {
			t.Error("Expected AssetGroupID to be zero initially")
		}

		group1 := shared.NewID()
		group2 := shared.NewID()
		sc.SetAssetGroupIDs([]shared.ID{group1, group2})

		// Should set primary to first one
		if sc.AssetGroupID != group1 {
			t.Errorf("Expected primary AssetGroupID to be %s, got %s", group1, sc.AssetGroupID)
		}
	})

	t.Run("SetAssetGroupIDs_DoesntOverridePrimary", func(t *testing.T) {
		originalGroup := shared.NewID()
		sc, _ := scan.NewScan(tenantID, "Scan", originalGroup, scan.ScanTypeSingle)

		group1 := shared.NewID()
		group2 := shared.NewID()
		sc.SetAssetGroupIDs([]shared.ID{group1, group2})

		// Should NOT override existing primary
		if sc.AssetGroupID != originalGroup {
			t.Errorf("Expected primary AssetGroupID to remain %s, got %s", originalGroup, sc.AssetGroupID)
		}
	})

	t.Run("SetAssetGroupIDs_HandlesNil", func(t *testing.T) {
		sc, _ := scan.NewScan(tenantID, "Scan", assetGroupID, scan.ScanTypeSingle)
		sc.SetAssetGroupIDs([]shared.ID{shared.NewID()})

		// Set to nil
		sc.SetAssetGroupIDs(nil)

		if sc.AssetGroupIDs == nil {
			t.Error("Expected AssetGroupIDs to be empty slice, not nil")
		}
		if len(sc.AssetGroupIDs) != 0 {
			t.Errorf("Expected empty AssetGroupIDs after nil, got %d", len(sc.AssetGroupIDs))
		}
	})

	t.Run("GetAllAssetGroupIDs_CombinesPrimaryAndMultiple", func(t *testing.T) {
		primaryGroup := shared.NewID()
		sc, _ := scan.NewScan(tenantID, "Scan", primaryGroup, scan.ScanTypeSingle)

		group1 := shared.NewID()
		group2 := shared.NewID()
		sc.AssetGroupIDs = []shared.ID{group1, group2}

		allIDs := sc.GetAllAssetGroupIDs()

		if len(allIDs) != 3 {
			t.Errorf("Expected 3 total IDs, got %d", len(allIDs))
		}
		if allIDs[0] != primaryGroup {
			t.Errorf("Expected first ID to be primary %s, got %s", primaryGroup, allIDs[0])
		}
	})

	t.Run("GetAllAssetGroupIDs_AvoidsDuplicates", func(t *testing.T) {
		primaryGroup := shared.NewID()
		sc, _ := scan.NewScan(tenantID, "Scan", primaryGroup, scan.ScanTypeSingle)

		// Add same ID to AssetGroupIDs
		sc.AssetGroupIDs = []shared.ID{primaryGroup, shared.NewID()}

		allIDs := sc.GetAllAssetGroupIDs()

		// Should not duplicate the primary
		if len(allIDs) != 2 {
			t.Errorf("Expected 2 IDs (no duplicate), got %d", len(allIDs))
		}
	})

	t.Run("GetAllAssetGroupIDs_HandlesOnlyPrimary", func(t *testing.T) {
		primaryGroup := shared.NewID()
		sc, _ := scan.NewScan(tenantID, "Scan", primaryGroup, scan.ScanTypeSingle)

		allIDs := sc.GetAllAssetGroupIDs()

		if len(allIDs) != 1 {
			t.Errorf("Expected 1 ID, got %d", len(allIDs))
		}
		if allIDs[0] != primaryGroup {
			t.Errorf("Expected ID to be %s, got %s", primaryGroup, allIDs[0])
		}
	})

	t.Run("GetAllAssetGroupIDs_HandlesOnlyMultiple", func(t *testing.T) {
		targets := []string{"example.com"}
		sc, _ := scan.NewScanWithTargets(tenantID, "Scan", targets, scan.ScanTypeSingle)

		group1 := shared.NewID()
		group2 := shared.NewID()
		sc.AssetGroupIDs = []shared.ID{group1, group2}

		allIDs := sc.GetAllAssetGroupIDs()

		if len(allIDs) != 2 {
			t.Errorf("Expected 2 IDs, got %d", len(allIDs))
		}
	})

	t.Run("GetAllAssetGroupIDs_HandlesEmpty", func(t *testing.T) {
		targets := []string{"example.com"}
		sc, _ := scan.NewScanWithTargets(tenantID, "Scan", targets, scan.ScanTypeSingle)

		allIDs := sc.GetAllAssetGroupIDs()

		if len(allIDs) != 0 {
			t.Errorf("Expected 0 IDs, got %d", len(allIDs))
		}
	})
}

// TestScanValidation tests the Validate method with new target options.
//
// Run with: go test -v ./tests/unit -run TestScanValidation
func TestScanValidation(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("ValidWithAssetGroupID", func(t *testing.T) {
		assetGroupID := shared.NewID()
		sc, _ := scan.NewScan(tenantID, "Valid Scan", assetGroupID, scan.ScanTypeSingle)
		sc.ScannerName = "nuclei"

		err := sc.Validate()
		if err != nil {
			t.Errorf("Expected valid scan, got error: %v", err)
		}
	})

	t.Run("ValidWithAssetGroupIDs", func(t *testing.T) {
		targets := []string{"example.com"} // Need some target source
		sc, _ := scan.NewScanWithTargets(tenantID, "Valid Scan", targets, scan.ScanTypeSingle)
		sc.ScannerName = "nuclei"
		// Clear targets and use AssetGroupIDs instead
		sc.Targets = []string{}
		sc.AssetGroupIDs = []shared.ID{shared.NewID(), shared.NewID()}

		err := sc.Validate()
		if err != nil {
			t.Errorf("Expected valid scan with AssetGroupIDs, got error: %v", err)
		}
	})

	t.Run("ValidWithTargets", func(t *testing.T) {
		targets := []string{"example.com", "test.com"}
		sc, _ := scan.NewScanWithTargets(tenantID, "Valid Scan", targets, scan.ScanTypeSingle)
		sc.ScannerName = "nuclei"

		err := sc.Validate()
		if err != nil {
			t.Errorf("Expected valid scan with targets, got error: %v", err)
		}
	})

	t.Run("ValidWithBothAssetGroupAndTargets", func(t *testing.T) {
		assetGroupID := shared.NewID()
		sc, _ := scan.NewScan(tenantID, "Valid Scan", assetGroupID, scan.ScanTypeSingle)
		sc.Targets = []string{"extra.com"}
		sc.ScannerName = "nuclei"

		err := sc.Validate()
		if err != nil {
			t.Errorf("Expected valid scan with both, got error: %v", err)
		}
	})

	t.Run("InvalidWithoutAnyTargetSource", func(t *testing.T) {
		sc := &scan.Scan{
			ID:       shared.NewID(),
			TenantID: tenantID,
			Name:     "Invalid Scan",
			ScanType: scan.ScanTypeSingle,
			// No AssetGroupID, no AssetGroupIDs, no Targets
		}
		sc.ScannerName = "nuclei"

		err := sc.Validate()
		if err == nil {
			t.Error("Expected validation error for scan without targets")
		}
	})

	t.Run("InvalidWithoutName", func(t *testing.T) {
		sc := &scan.Scan{
			ID:           shared.NewID(),
			TenantID:     tenantID,
			Name:         "",
			AssetGroupID: shared.NewID(),
			ScanType:     scan.ScanTypeSingle,
			ScannerName:  "nuclei",
		}

		err := sc.Validate()
		if err == nil {
			t.Error("Expected validation error for scan without name")
		}
	})
}

// TestScanHasAssetGroup tests the HasAssetGroup method.
//
// Run with: go test -v ./tests/unit -run TestScanHasAssetGroup
func TestScanHasAssetGroup(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("TrueWithAssetGroupID", func(t *testing.T) {
		sc, _ := scan.NewScan(tenantID, "Scan", shared.NewID(), scan.ScanTypeSingle)

		if !sc.HasAssetGroup() {
			t.Error("Expected HasAssetGroup() to be true with AssetGroupID")
		}
	})

	t.Run("TrueWithAssetGroupIDs", func(t *testing.T) {
		targets := []string{"example.com"}
		sc, _ := scan.NewScanWithTargets(tenantID, "Scan", targets, scan.ScanTypeSingle)
		sc.AssetGroupIDs = []shared.ID{shared.NewID()}

		if !sc.HasAssetGroup() {
			t.Error("Expected HasAssetGroup() to be true with AssetGroupIDs")
		}
	})

	t.Run("FalseWithoutAssetGroups", func(t *testing.T) {
		targets := []string{"example.com"}
		sc, _ := scan.NewScanWithTargets(tenantID, "Scan", targets, scan.ScanTypeSingle)

		if sc.HasAssetGroup() {
			t.Error("Expected HasAssetGroup() to be false without asset groups")
		}
	})
}

// TestScanClone tests that Clone properly copies AssetGroupIDs.
//
// Run with: go test -v ./tests/unit -run TestScanClone
func TestScanClone(t *testing.T) {
	tenantID := shared.NewID()
	primaryGroup := shared.NewID()

	t.Run("CloneCopiesAssetGroupIDs", func(t *testing.T) {
		original, _ := scan.NewScan(tenantID, "Original", primaryGroup, scan.ScanTypeSingle)
		original.ScannerName = "nuclei"
		group1 := shared.NewID()
		group2 := shared.NewID()
		original.AssetGroupIDs = []shared.ID{group1, group2}

		clone := original.Clone("Cloned Scan")

		// Verify AssetGroupIDs copied
		if len(clone.AssetGroupIDs) != 2 {
			t.Errorf("Expected 2 AssetGroupIDs in clone, got %d", len(clone.AssetGroupIDs))
		}
		if clone.AssetGroupIDs[0] != group1 || clone.AssetGroupIDs[1] != group2 {
			t.Error("AssetGroupIDs not copied correctly")
		}
	})

	t.Run("CloneCopiesTargets", func(t *testing.T) {
		targets := []string{"example.com", "test.com"}
		original, _ := scan.NewScanWithTargets(tenantID, "Original", targets, scan.ScanTypeSingle)
		original.ScannerName = "nuclei"

		clone := original.Clone("Cloned Scan")

		if len(clone.Targets) != 2 {
			t.Errorf("Expected 2 Targets in clone, got %d", len(clone.Targets))
		}
		if clone.Targets[0] != "example.com" || clone.Targets[1] != "test.com" {
			t.Error("Targets not copied correctly")
		}
	})

	t.Run("CloneIsIndependent", func(t *testing.T) {
		original, _ := scan.NewScan(tenantID, "Original", primaryGroup, scan.ScanTypeSingle)
		original.ScannerName = "nuclei"
		original.AssetGroupIDs = []shared.ID{shared.NewID()}
		original.Targets = []string{"example.com"}

		clone := original.Clone("Cloned Scan")

		// Modify original
		original.AssetGroupIDs = append(original.AssetGroupIDs, shared.NewID())
		original.Targets = append(original.Targets, "new.com")

		// Clone should not be affected
		if len(clone.AssetGroupIDs) != 1 {
			t.Error("Clone AssetGroupIDs should be independent from original")
		}
		if len(clone.Targets) != 1 {
			t.Error("Clone Targets should be independent from original")
		}
	})
}
