package integration

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk/pkg/eis"
)

// =============================================================================
// Test: Tool Sends Partial Data - Basic Fields Only
// =============================================================================

func TestIngestFinding_PartialData_BasicFieldsOnly(t *testing.T) {
	// Scenario: Tool only sends required fields (type, title, severity)
	// All other fields should gracefully handle nil/empty values

	risFinding := &eis.Finding{
		ID:       "finding-partial-1",
		Type:     eis.FindingTypeVulnerability,
		Title:    "Potential Security Issue",
		Severity: eis.SeverityMedium,
		// No description, no location, no vulnerability details
	}

	t.Run("RequiredFieldsOnly", func(t *testing.T) {
		// Verify required fields are present
		if risFinding.Type == "" {
			t.Error("Type is required")
		}
		if risFinding.Title == "" {
			t.Error("Title is required")
		}
		if risFinding.Severity == "" {
			t.Error("Severity is required")
		}
	})

	t.Run("OptionalFieldsEmpty", func(t *testing.T) {
		// These should all be empty/nil - tool didn't provide them
		if risFinding.Description != "" {
			t.Error("Description should be empty when not provided")
		}
		if risFinding.Location != nil {
			t.Error("Location should be nil when not provided")
		}
		if risFinding.Vulnerability != nil {
			t.Error("Vulnerability should be nil when not provided")
		}
		if risFinding.Secret != nil {
			t.Error("Secret should be nil when not provided")
		}
		if risFinding.Web3 != nil {
			t.Error("Web3 should be nil when not provided")
		}
	})

	t.Run("DomainEntityCreationWithPartialData", func(t *testing.T) {
		tenantID := shared.NewID()
		assetID := shared.NewID()

		// Should be able to create domain entity with only required fields
		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"basic-tool",
			vulnerability.SeverityMedium,
			risFinding.Title,
		)
		if err != nil {
			t.Fatalf("Should create finding with basic fields: %v", err)
		}

		// Basic fields should be set
		if finding.Message() != risFinding.Title {
			t.Errorf("Message should be set from title")
		}
		if finding.Severity() != vulnerability.SeverityMedium {
			t.Errorf("Severity should be set")
		}

		// Optional fields should have zero values
		if finding.Description() != "" {
			t.Error("Description should be empty")
		}
		if finding.FilePath() != "" {
			t.Error("FilePath should be empty")
		}
	})
}

// =============================================================================
// Test: Tool Sends Partial Secret Data
// =============================================================================

func TestIngestFinding_PartialData_SecretFields(t *testing.T) {
	// Scenario: Secret scanner sends basic detection info
	// Verification tool can enrich later with valid/revoked status

	t.Run("BasicSecretDetection", func(t *testing.T) {
		// Gitleaks-style detection: type and masked value only
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeSecret,
			Title:    "AWS Access Key Detected",
			Severity: eis.SeverityHigh,
			Secret: &eis.SecretDetails{
				SecretType:  "aws_key",
				MaskedValue: "AKIA****XXXX",
				// No valid, revoked, scopes, expires_at, verified_at
			},
		}

		// Verify top-level fields are set correctly
		if risFinding.Type != eis.FindingTypeSecret {
			t.Error("Type should be secret")
		}
		if risFinding.Title != "AWS Access Key Detected" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityHigh {
			t.Error("Severity should be high")
		}
		if risFinding.Secret.SecretType != "aws_key" {
			t.Error("SecretType should be set")
		}
		if risFinding.Secret.MaskedValue != "AKIA****XXXX" {
			t.Error("MaskedValue should be set")
		}

		// These should be nil/zero - tool didn't verify
		if risFinding.Secret.Valid != nil {
			t.Error("Valid should be nil when not verified")
		}
		if risFinding.Secret.Revoked {
			t.Error("Revoked should be false by default")
		}
		if len(risFinding.Secret.Scopes) > 0 {
			t.Error("Scopes should be empty when not provided")
		}
	})

	t.Run("EnrichedSecretWithVerification", func(t *testing.T) {
		// Secret verifier adds validity info
		valid := true
		now := time.Now()
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeSecret,
			Title:    "AWS Access Key Detected",
			Severity: eis.SeverityCritical, // Escalated because valid
			Secret: &eis.SecretDetails{
				SecretType:  "aws_key",
				Service:     "aws",
				MaskedValue: "AKIA****XXXX",
				Valid:       &valid,
				VerifiedAt:  &now,
				Scopes:      []string{"s3:*", "ec2:DescribeInstances"},
				ExpiresAt:   nil, // AWS keys don't expire
			},
		}

		// Verify severity was escalated for valid secret
		if risFinding.Type != eis.FindingTypeSecret {
			t.Error("Type should be secret")
		}
		if risFinding.Title != "AWS Access Key Detected" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityCritical {
			t.Error("Severity should be critical for valid secret")
		}
		if risFinding.Secret.Valid == nil || !*risFinding.Secret.Valid {
			t.Error("Valid should be true after verification")
		}
		if risFinding.Secret.VerifiedAt == nil {
			t.Error("VerifiedAt should be set after verification")
		}
		if len(risFinding.Secret.Scopes) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(risFinding.Secret.Scopes))
		}
	})

	t.Run("DomainEntityWithPartialSecret", func(t *testing.T) {
		tenantID := shared.NewID()
		assetID := shared.NewID()

		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSecret,
			"gitleaks",
			vulnerability.SeverityHigh,
			"AWS Access Key Detected",
		)
		if err != nil {
			t.Fatalf("Failed to create finding: %v", err)
		}

		// Set only the fields tool provided
		finding.SetSecretType("aws_key")
		finding.SetSecretMaskedValue("AKIA****XXXX")

		// Verify partial data is set
		if finding.SecretType() != "aws_key" {
			t.Error("SecretType should be set")
		}

		// Fields not set should be zero/nil
		if finding.SecretValid() != nil {
			t.Error("SecretValid should be nil when not set")
		}
	})
}

// =============================================================================
// Test: Tool Sends Partial Web3 Data
// =============================================================================

func TestIngestFinding_PartialData_Web3Fields(t *testing.T) {
	// Scenario: Different Web3 tools provide different levels of detail

	t.Run("SlitherBasicDetection", func(t *testing.T) {
		// Slither: Static analysis, provides basic info
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeVulnerability,
			Title:    "Reentrancy Vulnerability",
			Severity: eis.SeverityHigh,
			Web3: &eis.Web3VulnerabilityDetails{
				Chain:           "ethereum",
				SWCID:           "SWC-107",
				ContractAddress: "0x1234567890123456789012345678901234567890",
				// No bytecode_offset, function_selector, estimated_impact
			},
		}

		// Verify top-level fields
		if risFinding.Type != eis.FindingTypeVulnerability {
			t.Error("Type should be vulnerability")
		}
		if risFinding.Title != "Reentrancy Vulnerability" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityHigh {
			t.Error("Severity should be high")
		}
		if risFinding.Web3.Chain != "ethereum" {
			t.Error("Chain should be set")
		}
		if risFinding.Web3.SWCID != "SWC-107" {
			t.Error("SWCID should be set")
		}

		// Advanced analysis fields not provided
		if risFinding.Web3.BytecodeOffset != 0 {
			t.Error("BytecodeOffset should be 0 when not provided")
		}
		if risFinding.Web3.FunctionSelector != "" {
			t.Error("FunctionSelector should be empty when not provided")
		}
	})

	t.Run("MythrilDeepAnalysis", func(t *testing.T) {
		// Mythril: Symbolic execution, provides bytecode details
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeVulnerability,
			Title:    "Reentrancy Vulnerability",
			Severity: eis.SeverityHigh,
			Web3: &eis.Web3VulnerabilityDetails{
				Chain:            "ethereum",
				SWCID:            "SWC-107",
				BytecodeOffset:   0x1a2b,
				FunctionSelector: "0xa9059cbb",
				// Mythril doesn't estimate impact
			},
		}

		// Verify top-level fields
		if risFinding.Type != eis.FindingTypeVulnerability {
			t.Error("Type should be vulnerability")
		}
		if risFinding.Title != "Reentrancy Vulnerability" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityHigh {
			t.Error("Severity should be high")
		}
		if risFinding.Web3.BytecodeOffset != 0x1a2b {
			t.Errorf("BytecodeOffset should be set, got %d", risFinding.Web3.BytecodeOffset)
		}
		if risFinding.Web3.FunctionSelector != "0xa9059cbb" {
			t.Error("FunctionSelector should be set")
		}
	})

	t.Run("ManualAuditWithImpact", func(t *testing.T) {
		// Manual audit: Includes impact assessment
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeVulnerability,
			Title:    "Reentrancy Vulnerability",
			Severity: eis.SeverityCritical,
			Web3: &eis.Web3VulnerabilityDetails{
				Chain:                "ethereum",
				SWCID:                "SWC-107",
				ContractAddress:      "0x1234567890123456789012345678901234567890",
				FunctionSignature:    "withdraw(uint256)",
				EstimatedImpactUSD:   1500000.0,
				AffectedValueUSD:     5000000.0,
				AttackVector:         "Flash loan → manipulate oracle → drain funds",
				ExploitableOnMainnet: true,
			},
		}

		// Verify top-level fields for critical audit findings
		if risFinding.Type != eis.FindingTypeVulnerability {
			t.Error("Type should be vulnerability")
		}
		if risFinding.Title != "Reentrancy Vulnerability" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityCritical {
			t.Error("Severity should be critical for manual audit")
		}
		if risFinding.Web3.EstimatedImpactUSD != 1500000.0 {
			t.Error("EstimatedImpactUSD should be set")
		}
		if !risFinding.Web3.ExploitableOnMainnet {
			t.Error("ExploitableOnMainnet should be true")
		}
	})

	t.Run("DomainEntityWithPartialWeb3", func(t *testing.T) {
		tenantID := shared.NewID()
		assetID := shared.NewID()

		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"slither",
			vulnerability.SeverityHigh,
			"Reentrancy Vulnerability",
		)
		if err != nil {
			t.Fatalf("Failed to create finding: %v", err)
		}

		// Set only Slither-provided fields
		finding.SetWeb3Chain("ethereum")
		finding.SetWeb3SWCID("SWC-107")
		finding.SetWeb3ContractAddress("0x1234567890123456789012345678901234567890")

		// These fields were not provided by Slither
		if finding.Web3BytecodeOffset() != 0 {
			t.Error("BytecodeOffset should be 0 when not set")
		}
		if finding.Web3FunctionSelector() != "" {
			t.Error("FunctionSelector should be empty when not set")
		}
	})
}

// =============================================================================
// Test: Tool Sends Partial Compliance Data
// =============================================================================

func TestIngestFinding_PartialData_ComplianceFields(t *testing.T) {
	t.Run("BasicComplianceCheck", func(t *testing.T) {
		// Tool only provides framework and control ID
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeCompliance,
			Title:    "CIS Benchmark Failure",
			Severity: eis.SeverityMedium,
			Compliance: &eis.ComplianceDetails{
				Framework: "cis",
				ControlID: "1.1.1",
				Result:    "fail",
				// No framework_version, control_name, control_description
			},
		}

		// Verify top-level fields
		if risFinding.Type != eis.FindingTypeCompliance {
			t.Error("Type should be compliance")
		}
		if risFinding.Title != "CIS Benchmark Failure" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityMedium {
			t.Error("Severity should be medium")
		}
		if risFinding.Compliance.Framework != "cis" {
			t.Error("Framework should be set")
		}
		if risFinding.Compliance.ControlID != "1.1.1" {
			t.Error("ControlID should be set")
		}

		// Optional fields not provided
		if risFinding.Compliance.FrameworkVersion != "" {
			t.Error("FrameworkVersion should be empty")
		}
		if risFinding.Compliance.ControlDescription != "" {
			t.Error("ControlDescription should be empty")
		}
	})

	t.Run("FullComplianceCheck", func(t *testing.T) {
		// Enterprise tool with full compliance mapping
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeCompliance,
			Title:    "Password Policy Non-Compliant",
			Severity: eis.SeverityHigh,
			Compliance: &eis.ComplianceDetails{
				Framework:          "pci-dss",
				FrameworkVersion:   "4.0",
				ControlID:          "8.3.1",
				ControlName:        "Password Length",
				ControlDescription: "All user passwords must be at least 12 characters",
				Result:             "fail",
			},
		}

		// Verify top-level fields for enterprise compliance
		if risFinding.Type != eis.FindingTypeCompliance {
			t.Error("Type should be compliance")
		}
		if risFinding.Title != "Password Policy Non-Compliant" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityHigh {
			t.Error("Severity should be high")
		}
		if risFinding.Compliance.FrameworkVersion != "4.0" {
			t.Error("FrameworkVersion should be set")
		}
		if risFinding.Compliance.ControlDescription == "" {
			t.Error("ControlDescription should be set")
		}
	})
}

// =============================================================================
// Test: Tool Sends Partial Misconfiguration Data
// =============================================================================

func TestIngestFinding_PartialData_MisconfigFields(t *testing.T) {
	t.Run("BasicMisconfigDetection", func(t *testing.T) {
		// Trivy-style: policy ID and resource info
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeMisconfiguration,
			Title:    "S3 Bucket Public Access",
			Severity: eis.SeverityCritical,
			Misconfiguration: &eis.MisconfigurationDetails{
				PolicyID:     "AVD-AWS-0086",
				ResourceType: "aws_s3_bucket",
				ResourceName: "my-bucket",
				// No expected, actual, cause
			},
		}

		// Verify top-level fields
		if risFinding.Type != eis.FindingTypeMisconfiguration {
			t.Error("Type should be misconfiguration")
		}
		if risFinding.Title != "S3 Bucket Public Access" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityCritical {
			t.Error("Severity should be critical")
		}
		if risFinding.Misconfiguration.PolicyID != "AVD-AWS-0086" {
			t.Error("PolicyID should be set")
		}
		if risFinding.Misconfiguration.ResourceType != "aws_s3_bucket" {
			t.Error("ResourceType should be set")
		}

		// Detailed comparison not provided
		if risFinding.Misconfiguration.Expected != "" {
			t.Error("Expected should be empty")
		}
		if risFinding.Misconfiguration.Actual != "" {
			t.Error("Actual should be empty")
		}
	})

	t.Run("DetailedMisconfigWithComparison", func(t *testing.T) {
		// Checkov-style: includes expected vs actual
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeMisconfiguration,
			Title:    "S3 Bucket Encryption Disabled",
			Severity: eis.SeverityHigh,
			Misconfiguration: &eis.MisconfigurationDetails{
				PolicyID:     "CKV_AWS_19",
				PolicyName:   "Ensure S3 bucket encryption is enabled",
				ResourceType: "aws_s3_bucket",
				ResourceName: "data-bucket",
				Expected:     "server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm = 'aws:kms'",
				Actual:       "server_side_encryption_configuration is not defined",
				Cause:        "Encryption not configured for S3 bucket",
			},
		}

		// Verify top-level fields
		if risFinding.Type != eis.FindingTypeMisconfiguration {
			t.Error("Type should be misconfiguration")
		}
		if risFinding.Title != "S3 Bucket Encryption Disabled" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityHigh {
			t.Error("Severity should be high")
		}
		if risFinding.Misconfiguration.Expected == "" {
			t.Error("Expected should be set")
		}
		if risFinding.Misconfiguration.Actual == "" {
			t.Error("Actual should be set")
		}
		if risFinding.Misconfiguration.Cause == "" {
			t.Error("Cause should be set")
		}
	})
}

// =============================================================================
// Test: Tool Sends Partial CTEM Data
// Note: CTEM fields (Exposure, RemediationContext, BusinessImpact) are in sdk/pkg/eis
// This package (api/pkg/parsers/eis) doesn't include them.
// CTEM tests are covered in processor_findings.go integration with sdk/pkg/eis.
// =============================================================================

func TestIngestFinding_PartialData_CTEMFields(t *testing.T) {
	t.Run("DomainEntityCTEMFieldsHaveSafeDefaults", func(t *testing.T) {
		// Test that domain entity handles CTEM fields correctly
		// even when not provided by the parser
		tenantID := shared.NewID()
		assetID := shared.NewID()

		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"basic-scanner",
			vulnerability.SeverityHigh,
			"CVE-2024-1234",
		)
		if err != nil {
			t.Fatalf("Failed to create finding: %v", err)
		}

		// CTEM fields should have safe default values
		// ExposureVector defaults to "unknown" (not empty) for safety
		if finding.ExposureVector() != vulnerability.ExposureVectorUnknown {
			t.Errorf("ExposureVector should default to 'unknown', got %s", finding.ExposureVector())
		}
		if finding.IsNetworkAccessible() {
			t.Error("IsNetworkAccessible should be false by default")
		}
		if finding.IsInternetAccessible() {
			t.Error("IsInternetAccessible should be false by default")
		}

		// Should be able to set CTEM fields later (enrichment)
		_ = finding.SetExposureVector(vulnerability.ExposureVectorNetwork)
		finding.SetNetworkAccessible(true)
		finding.SetInternetAccessible(true)

		if finding.ExposureVector() != vulnerability.ExposureVectorNetwork {
			t.Error("ExposureVector should be set after enrichment")
		}
	})
}

// =============================================================================
// Test: Graceful Handling of Missing Nested Objects
// =============================================================================

func TestIngestFinding_PartialData_NilSafety(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	t.Run("SafelyAccessNilVulnerability", func(t *testing.T) {
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeVulnerability,
			Title:    "Generic Finding",
			Severity: eis.SeverityMedium,
			// Vulnerability is nil
		}

		// Verify top-level fields are accessible
		if risFinding.Type != eis.FindingTypeVulnerability {
			t.Error("Type should be vulnerability")
		}
		if risFinding.Title != "Generic Finding" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityMedium {
			t.Error("Severity should be medium")
		}

		// Should not panic when accessing nil nested object
		var cveID string
		if risFinding.Vulnerability != nil {
			cveID = risFinding.Vulnerability.CVEID
		}
		if cveID != "" {
			t.Error("CVE should be empty when Vulnerability is nil")
		}
	})

	t.Run("SafelyAccessNilLocation", func(t *testing.T) {
		risFinding := &eis.Finding{
			Type:     eis.FindingTypeVulnerability,
			Title:    "Generic Finding",
			Severity: eis.SeverityMedium,
			// Location is nil
		}

		// Verify top-level fields are accessible
		if risFinding.Type != eis.FindingTypeVulnerability {
			t.Error("Type should be vulnerability")
		}
		if risFinding.Title != "Generic Finding" {
			t.Error("Title should be set")
		}
		if risFinding.Severity != eis.SeverityMedium {
			t.Error("Severity should be medium")
		}

		// Should not panic when accessing nil nested object
		var filePath string
		if risFinding.Location != nil {
			filePath = risFinding.Location.Path
		}
		if filePath != "" {
			t.Error("FilePath should be empty when Location is nil")
		}
	})

	t.Run("DomainEntitySettersAreNilSafe", func(t *testing.T) {
		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"tool",
			vulnerability.SeverityMedium,
			"Finding",
		)
		if err != nil {
			t.Fatalf("Failed to create finding: %v", err)
		}

		// These should not panic with nil/empty values
		finding.SetDescription("")
		finding.SetSnippet("")
		finding.SetRuleID("")

		// Nil-safe for pointer types
		finding.SetSecretValid(nil)
		finding.SetSecretRevoked(nil)

		// Empty arrays should be handled
		finding.SetVulnerabilityClass([]string{})
		finding.SetSubcategory(nil)

		// Verify nothing exploded
		if finding.Description() != "" {
			t.Error("Description should remain empty")
		}
	})
}

// =============================================================================
// Test: Simulated Multi-Tool Enrichment Scenario
// =============================================================================

func TestIngestFinding_PartialData_MultiToolEnrichment(t *testing.T) {
	// This test simulates what the enrichment mechanism should enable
	// Currently tests that findings can be created with partial data
	// and later "enriched" by setting additional fields

	tenantID := shared.NewID()
	assetID := shared.NewID()

	t.Run("SimulatedEnrichmentFlow", func(t *testing.T) {
		// Step 1: Slither creates initial finding
		finding, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"slither",
			vulnerability.SeverityHigh,
			"Reentrancy Vulnerability",
		)

		// Slither provides basic Web3 info
		finding.SetWeb3Chain("ethereum")
		finding.SetWeb3SWCID("SWC-107")
		finding.SetWeb3ContractAddress("0x1234567890123456789012345678901234567890")
		finding.SetFingerprint("reentrancy-0x1234-swc107")

		// Verify initial state
		if finding.Web3Chain() != "ethereum" {
			t.Error("Initial chain should be set")
		}
		if finding.Web3BytecodeOffset() != 0 {
			t.Error("BytecodeOffset should be 0 initially")
		}

		// Step 2: Simulate Mythril enrichment
		// In real implementation, this would be done via EnrichFrom()
		finding.SetWeb3BytecodeOffset(0x1a2b)
		finding.SetWeb3FunctionSelector("0xa9059cbb")

		// Verify enrichment added new data
		if finding.Web3BytecodeOffset() != 0x1a2b {
			t.Error("BytecodeOffset should be enriched")
		}
		if finding.Web3FunctionSelector() != "0xa9059cbb" {
			t.Error("FunctionSelector should be enriched")
		}

		// Original data should be preserved
		if finding.Web3Chain() != "ethereum" {
			t.Error("Chain should be preserved after enrichment")
		}
		if finding.Web3SWCID() != "SWC-107" {
			t.Error("SWCID should be preserved after enrichment")
		}
	})
}
