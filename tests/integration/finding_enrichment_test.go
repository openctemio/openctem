package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk/pkg/eis"
)

// =============================================================================
// Finding Enrichment Integration Tests
// Tests real-world scenarios for finding enrichment across multiple scans
// =============================================================================

// TestEnrichment_MultiToolSASTScenario simulates multiple SAST tools scanning
// the same codebase and enriching findings over time.
func TestEnrichment_MultiToolSASTScenario(t *testing.T) {
	ctx := context.Background()
	_ = ctx // For future DB integration

	tenantID := shared.NewID()
	assetID := shared.NewID()

	// ==========================================================================
	// Phase 1: Semgrep detects basic SQL injection
	// ==========================================================================
	t.Run("Phase1_SemgrepInitialDetection", func(t *testing.T) {
		finding, err := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"semgrep",
			vulnerability.SeverityHigh,
			"SQL Injection vulnerability",
		)
		if err != nil {
			t.Fatalf("Failed to create finding: %v", err)
		}

		// Set basic SAST fields
		finding.SetFindingType(vulnerability.FindingTypeVulnerability)
		finding.SetRuleID("go.lang.security.audit.sqli")
		finding.SetDescription("User input flows directly to SQL query")
		finding.SetLocation("/app/handlers/user.go", 142, 145, 1, 80)
		finding.SetSnippet(`db.Query("SELECT * FROM users WHERE id = " + id)`)
		finding.SetTags([]string{"sql", "injection", "sast"})

		// Set partial classification (Semgrep doesn't provide CVSS)
		err = finding.SetClassification("", nil, "", []string{"CWE-89"}, nil)
		if err != nil {
			t.Fatalf("Failed to set classification: %v", err)
		}

		// Generate fingerprint
		fp := vulnerability.GenerateFingerprintWithStrategy(finding)
		finding.SetFingerprint(fp)

		// Verify initial state
		if finding.Severity() != vulnerability.SeverityHigh {
			t.Errorf("Expected High severity, got %s", finding.Severity())
		}
		if finding.CVSSScore() != nil {
			t.Error("CVSS should be nil for initial Semgrep finding")
		}
		if len(finding.CWEIDs()) != 1 || finding.CWEIDs()[0] != "CWE-89" {
			t.Errorf("Expected CWE-89, got %v", finding.CWEIDs())
		}

		// ==========================================================================
		// Phase 2: CodeQL provides additional context
		// ==========================================================================
		codeqlFinding, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"codeql",
			vulnerability.SeverityCritical, // CodeQL rates it higher
			"Tainted SQL query execution",
		)

		codeqlFinding.SetDescription("User-controlled data flows to database query without validation")
		codeqlFinding.SetRuleID("codeql/go-sql-injection") // Different rule ID
		cvss92 := 9.2
		err = codeqlFinding.SetClassification(
			"",
			&cvss92,
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
			[]string{"CWE-89", "CWE-943"}, // CodeQL identifies additional CWE
			[]string{"A03:2021"},
		)
		if err != nil {
			t.Fatalf("Failed to set CodeQL classification: %v", err)
		}
		codeqlFinding.SetTags([]string{"codeql", "dataflow"})

		// Enrich original finding with CodeQL data
		finding.EnrichFrom(codeqlFinding)

		// Verify enrichment results
		if finding.Severity() != vulnerability.SeverityCritical {
			t.Errorf("Severity should upgrade to Critical, got %s", finding.Severity())
		}
		if finding.CVSSScore() == nil || *finding.CVSSScore() != 9.2 {
			t.Error("CVSS should be 9.2 from CodeQL")
		}
		if finding.RuleID() != "go.lang.security.audit.sqli" {
			t.Error("RuleID should be preserved from Semgrep (FirstWins)")
		}
		if finding.Description() != "User-controlled data flows to database query without validation" {
			t.Error("Description should be updated from CodeQL (LastWins)")
		}

		// CWE IDs should accumulate
		cweIDs := finding.CWEIDs()
		if len(cweIDs) != 2 {
			t.Errorf("Expected 2 CWE IDs, got %d: %v", len(cweIDs), cweIDs)
		}

		// Tags should accumulate
		tags := finding.Tags()
		if len(tags) < 4 {
			t.Errorf("Expected at least 4 tags, got %d: %v", len(tags), tags)
		}

		// ==========================================================================
		// Phase 3: Security team adds CTEM assessment
		// ==========================================================================
		ctemEnrichment, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceManual,
			"security-team",
			vulnerability.SeverityCritical,
			"Manual review",
		)

		_ = ctemEnrichment.SetExposureVector(vulnerability.ExposureVectorNetwork)
		ctemEnrichment.SetNetworkAccessible(true)
		ctemEnrichment.SetInternetAccessible(true)
		ctemEnrichment.SetAttackPrerequisites("None - publicly accessible endpoint")
		_ = ctemEnrichment.SetRemediationType(vulnerability.RemediationTypePatch)
		estimatedMinutes := 120
		ctemEnrichment.SetEstimatedFixTime(&estimatedMinutes)
		_ = ctemEnrichment.SetFixComplexity(vulnerability.FixComplexityModerate)
		ctemEnrichment.SetRemedyAvailable(true)
		_ = ctemEnrichment.SetDataExposureRisk(vulnerability.DataExposureRiskHigh)
		ctemEnrichment.SetReputationalImpact(true)
		ctemEnrichment.SetComplianceImpact([]string{"PCI-DSS", "GDPR"})

		finding.EnrichFrom(ctemEnrichment)

		// Verify CTEM enrichment
		if finding.ExposureVector() != vulnerability.ExposureVectorNetwork {
			t.Error("ExposureVector should be Network")
		}
		if !finding.IsInternetAccessible() {
			t.Error("IsInternetAccessible should be true")
		}
		if finding.RemediationType() != vulnerability.RemediationTypePatch {
			t.Error("RemediationType should be Patch")
		}
		if finding.EstimatedFixTime() == nil || *finding.EstimatedFixTime() != 120 {
			t.Error("EstimatedFixTime should be 120 minutes")
		}
		if finding.DataExposureRisk() != vulnerability.DataExposureRiskHigh {
			t.Error("DataExposureRisk should be PII")
		}

		complianceImpact := finding.ComplianceImpact()
		if len(complianceImpact) != 2 {
			t.Errorf("Expected 2 compliance frameworks, got %d", len(complianceImpact))
		}
	})
}

// TestEnrichment_SecretDetectionPipeline simulates secret detection and verification flow.
func TestEnrichment_SecretDetectionPipeline(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// ==========================================================================
	// Phase 1: Gitleaks detects AWS credential
	// ==========================================================================
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSecret,
		"gitleaks",
		vulnerability.SeverityCritical,
		"AWS Access Key detected",
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	finding.SetFindingType(vulnerability.FindingTypeSecret)
	finding.SetSecretType("aws-access-key")
	finding.SetSecretService("aws")
	finding.SetSecretMaskedValue("AKIA****XXXX5678")
	entropy := 4.5
	finding.SetSecretEntropy(&entropy)
	finding.SetLocation("/config/production.yaml", 15, 15, 1, 50)
	finding.SetSnippet("aws_access_key_id: AKIA...")

	// ==========================================================================
	// Phase 2: TruffleHog provides additional metadata
	// ==========================================================================
	trufflehogFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSecret,
		"trufflehog",
		vulnerability.SeverityCritical,
		"High entropy AWS credential",
	)

	trufflehogFinding.SetSecretType("github-token") // Should NOT overwrite
	trufflehogEntropy := 5.2                        // Higher entropy
	trufflehogFinding.SetSecretEntropy(&trufflehogEntropy)
	trufflehogFinding.SetSecretInHistoryOnly(false)
	trufflehogFinding.SetSecretCommitCount(3)

	finding.EnrichFrom(trufflehogFinding)

	// Verify secret enrichment
	if finding.SecretType() != "aws-access-key" {
		t.Error("SecretType should be preserved (FirstWins)")
	}
	if finding.SecretEntropy() == nil || *finding.SecretEntropy() != 4.5 {
		t.Error("SecretEntropy should be preserved from Gitleaks (FirstWins)")
	}

	// ==========================================================================
	// Phase 3: Secret verifier confirms validity
	// ==========================================================================
	verifierFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSecret,
		"secret-verifier",
		vulnerability.SeverityCritical,
		"Verified active credential",
	)

	validTrue := true
	verifierFinding.SetSecretValid(&validTrue)
	verifiedAt := time.Now().UTC()
	verifierFinding.SetSecretVerifiedAt(&verifiedAt)

	expiresAt := time.Now().Add(90 * 24 * time.Hour).UTC()
	verifierFinding.SetSecretExpiresAt(&expiresAt)

	finding.EnrichFrom(verifierFinding)

	// Verify verification enrichment
	if finding.SecretValid() == nil || !*finding.SecretValid() {
		t.Error("SecretValid should be true from verifier")
	}
	if finding.SecretVerifiedAt() == nil {
		t.Error("SecretVerifiedAt should be set")
	}
	if finding.SecretExpiresAt() == nil {
		t.Error("SecretExpiresAt should be set")
	}

	// ==========================================================================
	// Phase 4: Secret is revoked
	// ==========================================================================
	revocationFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSecret,
		"rotation-service",
		vulnerability.SeverityLow, // Lower severity after revocation
		"Credential revoked",
	)

	revokedTrue := true
	revocationFinding.SetSecretRevoked(&revokedTrue)

	finding.EnrichFrom(revocationFinding)

	// Severity should stay high (MaxValue)
	if finding.Severity() != vulnerability.SeverityCritical {
		t.Error("Severity should remain Critical (MaxValue)")
	}
	// Revoked should be set
	if finding.SecretRevoked() == nil || !*finding.SecretRevoked() {
		t.Error("SecretRevoked should be true")
	}
}

// TestEnrichment_Web3AuditWorkflow simulates smart contract audit workflow.
func TestEnrichment_Web3AuditWorkflow(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// ==========================================================================
	// Phase 1: Slither detects reentrancy
	// ==========================================================================
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"slither",
		vulnerability.SeverityHigh,
		"Reentrancy vulnerability in withdraw function",
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	finding.SetFindingType(vulnerability.FindingTypeWeb3)
	finding.SetWeb3Chain("ethereum")
	finding.SetWeb3ChainID(1)
	finding.SetWeb3ContractAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f3bE01")
	finding.SetWeb3SWCID("SWC-107")
	finding.SetWeb3FunctionSignature("withdraw(uint256)")
	finding.SetLocation("/contracts/Vault.sol", 45, 60, 1, 100)

	// ==========================================================================
	// Phase 2: Mythril provides bytecode-level analysis
	// ==========================================================================
	mythrilFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"mythril",
		vulnerability.SeverityCritical, // Mythril rates it higher
		"External call to user-specified address",
	)

	mythrilFinding.SetWeb3Chain("polygon") // Should NOT overwrite
	mythrilFinding.SetWeb3BytecodeOffset(0x1a2b)
	mythrilFinding.SetWeb3FunctionSelector("0x2e1a7d4d")
	mythrilFinding.SetWeb3TxHash("0xabc123...") // Example exploit tx
	mythrilFinding.SetDescription("Unchecked external call allows reentrancy attack pattern")

	finding.EnrichFrom(mythrilFinding)

	// Verify Web3 enrichment
	if finding.Web3Chain() != "ethereum" {
		t.Error("Chain should be preserved (FirstWins)")
	}
	if finding.Web3BytecodeOffset() != 0x1a2b {
		t.Error("BytecodeOffset should be enriched from Mythril")
	}
	if finding.Web3FunctionSelector() != "0x2e1a7d4d" {
		t.Error("FunctionSelector should be enriched from Mythril")
	}
	if finding.Severity() != vulnerability.SeverityCritical {
		t.Error("Severity should upgrade to Critical")
	}

	// ==========================================================================
	// Phase 3: Manual audit provides business impact
	// ==========================================================================
	auditFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceManual,
		"certik-auditor",
		vulnerability.SeverityCritical,
		"Critical reentrancy - $5M TVL at risk",
	)

	auditFinding.SetMetadata("estimated_impact_usd", 5000000.0)
	auditFinding.SetMetadata("tvl_at_risk_usd", 5000000.0)
	auditFinding.SetMetadata("attack_vector", "Flash loan → call withdraw → reenter")
	auditFinding.SetMetadata("exploitable_on_mainnet", true)
	_ = auditFinding.SetDataExposureRisk(vulnerability.DataExposureRiskCritical)

	finding.EnrichFrom(auditFinding)

	// Verify metadata enrichment
	metadata := finding.Metadata()
	if metadata["estimated_impact_usd"] != 5000000.0 {
		t.Error("Estimated impact should be set")
	}
	if finding.DataExposureRisk() != vulnerability.DataExposureRiskCritical {
		t.Error("DataExposureRisk should be Financial")
	}
}

// TestEnrichment_ComplianceWorkflow simulates compliance scanning workflow.
func TestEnrichment_ComplianceWorkflow(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// ==========================================================================
	// Phase 1: CIS benchmark scan
	// ==========================================================================
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceManual,
		"cis-scanner",
		vulnerability.SeverityMedium,
		"CIS Benchmark violation",
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	finding.SetFindingType(vulnerability.FindingTypeCompliance)
	finding.SetComplianceFramework("CIS")
	finding.SetComplianceControlID("2.1.1")
	finding.SetComplianceResult("fail")

	// ==========================================================================
	// Phase 2: Add framework version and detailed control info
	// ==========================================================================
	detailedFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceManual,
		"compliance-enricher",
		vulnerability.SeverityMedium,
		"Detailed compliance info",
	)

	detailedFinding.SetComplianceFramework("PCI-DSS") // Should NOT overwrite
	detailedFinding.SetComplianceFrameworkVersion("8.0")
	detailedFinding.SetComplianceControlName("Ensure MFA is enabled")
	detailedFinding.SetComplianceControlDescription("Multi-factor authentication must be enabled for all administrative access")
	detailedFinding.SetComplianceSection("Identity and Access Management")

	finding.EnrichFrom(detailedFinding)

	// Verify compliance enrichment
	if finding.ComplianceFramework() != "CIS" {
		t.Error("Framework should be preserved (FirstWins)")
	}
	if finding.ComplianceFrameworkVersion() != "8.0" {
		t.Error("FrameworkVersion should be enriched")
	}
	if finding.ComplianceControlName() != "Ensure MFA is enabled" {
		t.Error("ControlName should be enriched")
	}
}

// TestEnrichment_MisconfigurationWorkflow simulates IaC scanning workflow.
func TestEnrichment_MisconfigurationWorkflow(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// ==========================================================================
	// Phase 1: Trivy detects S3 misconfiguration
	// ==========================================================================
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceIaC,
		"trivy",
		vulnerability.SeverityCritical,
		"S3 bucket with public access",
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	finding.SetFindingType(vulnerability.FindingTypeMisconfiguration)
	finding.SetMisconfigPolicyID("AVD-AWS-0086")
	finding.SetMisconfigResourceType("aws_s3_bucket")
	finding.SetMisconfigResourceName("data-bucket")
	finding.SetLocation("/terraform/s3.tf", 10, 25, 1, 80)

	// ==========================================================================
	// Phase 2: Checkov provides remediation details
	// ==========================================================================
	checkovFinding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceIaC,
		"checkov",
		vulnerability.SeverityCritical,
		"S3 bucket allows public access",
	)

	checkovFinding.SetMisconfigPolicyID("CKV_AWS_20") // Should NOT overwrite
	checkovFinding.SetMisconfigPolicyName("Ensure S3 bucket has 'block public policy' enabled")
	checkovFinding.SetMisconfigExpected("block_public_policy = true")
	checkovFinding.SetMisconfigActual("block_public_policy = false")
	checkovFinding.SetMisconfigCause("Public access block not configured for S3 bucket")

	finding.EnrichFrom(checkovFinding)

	// Verify misconfiguration enrichment
	if finding.MisconfigPolicyID() != "AVD-AWS-0086" {
		t.Error("PolicyID should be preserved (FirstWins)")
	}
	if finding.MisconfigPolicyName() != "Ensure S3 bucket has 'block public policy' enabled" {
		t.Error("PolicyName should be enriched")
	}
	if finding.MisconfigExpected() != "block_public_policy = true" {
		t.Error("Expected should be enriched")
	}
	if finding.MisconfigActual() != "block_public_policy = false" {
		t.Error("Actual should be enriched")
	}
	if finding.MisconfigCause() == "" {
		t.Error("Cause should be enriched")
	}
}

// TestEnrichment_DeduplicationScenario tests finding deduplication via fingerprint.
func TestEnrichment_DeduplicationScenario(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Create two findings for the same vulnerability (different scans)
	finding1, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityHigh,
		"SQL Injection",
	)
	finding1.SetRuleID("sql-injection-001")
	finding1.SetLocation("/app/handler.go", 50, 55, 1, 80)
	finding1.SetSnippet("db.Query(userInput)")
	fp1 := vulnerability.GenerateFingerprintWithStrategy(finding1)
	finding1.SetFingerprint(fp1)

	finding2, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityHigh,
		"SQL Injection",
	)
	finding2.SetRuleID("sql-injection-001")
	finding2.SetLocation("/app/handler.go", 50, 55, 1, 80)
	finding2.SetSnippet("db.Query(userInput)")
	fp2 := vulnerability.GenerateFingerprintWithStrategy(finding2)
	finding2.SetFingerprint(fp2)

	// Fingerprints should match for deduplication
	if fp1 != fp2 {
		t.Errorf("Fingerprints should match for identical findings: %s != %s", fp1, fp2)
	}

	// Partial fingerprints should be stored
	pf1 := finding1.PartialFingerprints()
	pf2 := finding2.PartialFingerprints()
	if len(pf1) == 0 || len(pf2) == 0 {
		t.Error("Partial fingerprints should be populated")
	}
}

// TestEnrichment_EdgeCases tests various edge cases.
func TestEnrichment_EdgeCases(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	t.Run("EnrichWithNil", func(t *testing.T) {
		finding, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"test",
			vulnerability.SeverityHigh,
			"Test finding",
		)
		finding.SetDescription("Original")

		// Should not panic
		finding.EnrichFrom(nil)

		if finding.Description() != "Original" {
			t.Error("Description should be unchanged")
		}
	})

	t.Run("SelfEnrichment", func(t *testing.T) {
		finding, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"test",
			vulnerability.SeverityHigh,
			"Test finding",
		)
		finding.SetTags([]string{"tag1"})

		// Enriching from self should be safe
		finding.EnrichFrom(finding)

		if len(finding.Tags()) != 1 {
			t.Error("Tags should not duplicate on self-enrichment")
		}
	})

	t.Run("EmptyToFull", func(t *testing.T) {
		// Minimal finding
		minimal, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"test",
			vulnerability.SeverityLow,
			"Minimal",
		)

		// Full finding
		full, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"test",
			vulnerability.SeverityCritical,
			"Full finding",
		)
		full.SetDescription("Detailed description")
		full.SetLocation("/app/main.go", 100, 110, 1, 80)
		full.SetSnippet("vulnerable code")
		cvss := 9.5
		_ = full.SetClassification("CVE-2024-1234", &cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", []string{"CWE-79"}, nil)
		full.SetTags([]string{"critical", "priority"})
		full.SetMetadata("scanner", "advanced")

		minimal.EnrichFrom(full)

		// Verify all fields enriched
		if minimal.Severity() != vulnerability.SeverityCritical {
			t.Error("Severity should upgrade")
		}
		if minimal.Description() != "Detailed description" {
			t.Error("Description should be enriched")
		}
		if minimal.FilePath() != "/app/main.go" {
			t.Error("Location should be enriched")
		}
		if minimal.CVEID() != "CVE-2024-1234" {
			t.Error("CVE should be enriched")
		}
		if len(minimal.Tags()) != 2 {
			t.Errorf("Tags should be enriched, got %d", len(minimal.Tags()))
		}
	})

	t.Run("FullToEmpty", func(t *testing.T) {
		// Full finding
		full, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"test",
			vulnerability.SeverityCritical,
			"Full finding",
		)
		full.SetDescription("Original description")
		full.SetSecretType("aws-key")
		full.SetLocation("/app/main.go", 100, 110, 1, 80)

		// Empty finding
		empty, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"test",
			vulnerability.SeverityLow,
			"Empty",
		)

		full.EnrichFrom(empty)

		// Full finding should preserve its values (LastWins only for non-empty, FirstWins preserved)
		if full.Description() != "Original description" {
			t.Error("Description should be preserved when other is empty")
		}
		if full.SecretType() != "aws-key" {
			t.Error("SecretType should be preserved")
		}
		if full.FilePath() != "/app/main.go" {
			t.Error("Location should be preserved")
		}
		// But severity could downgrade... no, MaxValue keeps higher
		if full.Severity() != vulnerability.SeverityCritical {
			t.Error("Severity should remain Critical (MaxValue)")
		}
	})
}

// TestEnrichment_RISToFindingWorkflow tests the full EIS → Finding workflow.
func TestEnrichment_RISToFindingWorkflow(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Simulate EIS finding from scanner
	risFinding := &eis.Finding{
		ID:          "scan-001-finding-001",
		Type:        eis.FindingTypeVulnerability,
		Title:       "Command Injection in shell execution",
		Description: "User input passed directly to shell command",
		Severity:    eis.SeverityCritical,
		Confidence:  95,
		Impact:      "HIGH",
		Likelihood:  "HIGH",
		RuleID:      "go.lang.security.audit.command-injection",
		RuleName:    "Command Injection",
		Fingerprint: "unique-fp-001",
		Vulnerability: &eis.VulnerabilityDetails{
			CVSSScore:  9.8,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			CWEIDs:     []string{"CWE-78", "CWE-77"},
			OWASPIDs:   []string{"A03:2021"},
		},
		Location: &eis.FindingLocation{
			Path:        "/app/executor.go",
			StartLine:   88,
			EndLine:     92,
			StartColumn: 1,
			EndColumn:   60,
			Snippet:     `exec.Command("sh", "-c", userCommand)`,
		},
		Tags: []string{"command-injection", "shell", "critical"},
	}

	// Verify EIS fields are populated correctly
	if risFinding.ID != "scan-001-finding-001" {
		t.Error("EIS ID should be set")
	}
	if risFinding.Confidence != 95 {
		t.Error("EIS Confidence should be 95")
	}
	if risFinding.Impact != "HIGH" {
		t.Error("EIS Impact should be HIGH")
	}
	if risFinding.Likelihood != "HIGH" {
		t.Error("EIS Likelihood should be HIGH")
	}

	// Create domain finding from EIS
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.Severity(risFinding.Severity),
		risFinding.Title,
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	// Map EIS fields to domain
	finding.SetFindingType(vulnerability.FindingType(risFinding.Type))
	finding.SetRuleID(risFinding.RuleID)
	finding.SetRuleName(risFinding.RuleName)
	finding.SetDescription(risFinding.Description)
	finding.SetFingerprint(risFinding.Fingerprint)
	finding.SetTags(risFinding.Tags)

	if risFinding.Location != nil {
		finding.SetLocation(
			risFinding.Location.Path,
			risFinding.Location.StartLine,
			risFinding.Location.EndLine,
			risFinding.Location.StartColumn,
			risFinding.Location.EndColumn,
		)
		finding.SetSnippet(risFinding.Location.Snippet)
	}

	if risFinding.Vulnerability != nil {
		cvss := risFinding.Vulnerability.CVSSScore
		err = finding.SetClassification(
			risFinding.Vulnerability.CVEID,
			&cvss,
			risFinding.Vulnerability.CVSSVector,
			risFinding.Vulnerability.CWEIDs,
			risFinding.Vulnerability.OWASPIDs,
		)
		if err != nil {
			t.Fatalf("Failed to set classification: %v", err)
		}
	}

	// Verify mapping
	if finding.Severity() != vulnerability.SeverityCritical {
		t.Errorf("Expected Critical, got %s", finding.Severity())
	}
	if finding.RuleID() != "go.lang.security.audit.command-injection" {
		t.Error("RuleID mismatch")
	}
	if finding.FilePath() != "/app/executor.go" {
		t.Error("FilePath mismatch")
	}
	if finding.CVSSScore() == nil || *finding.CVSSScore() != 9.8 {
		t.Error("CVSS mismatch")
	}
	if len(finding.CWEIDs()) != 2 {
		t.Errorf("Expected 2 CWE IDs, got %d", len(finding.CWEIDs()))
	}
	if len(finding.OWASPIDs()) != 1 {
		t.Error("OWASP IDs mismatch")
	}
}
