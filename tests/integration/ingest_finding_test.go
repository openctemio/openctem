package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk/pkg/ctis"
)

// =============================================================================
// Mock Repositories for Integration Testing
// =============================================================================

// MockFindingRepositoryForIngest is a mock repository for testing finding ingestion.
type MockFindingRepositoryForIngest struct {
	findings     map[string]*vulnerability.Finding
	fingerprints map[string]bool
}

func NewMockFindingRepositoryForIngest() *MockFindingRepositoryForIngest {
	return &MockFindingRepositoryForIngest{
		findings:     make(map[string]*vulnerability.Finding),
		fingerprints: make(map[string]bool),
	}
}

func (m *MockFindingRepositoryForIngest) Create(_ context.Context, f *vulnerability.Finding) error {
	m.findings[f.ID().String()] = f
	m.fingerprints[f.Fingerprint()] = true
	return nil
}

func (m *MockFindingRepositoryForIngest) CreateBatch(_ context.Context, findings []*vulnerability.Finding) error {
	for _, f := range findings {
		m.findings[f.ID().String()] = f
		m.fingerprints[f.Fingerprint()] = true
	}
	return nil
}

func (m *MockFindingRepositoryForIngest) GetByID(_ context.Context, id shared.ID) (*vulnerability.Finding, error) {
	f, exists := m.findings[id.String()]
	if !exists {
		return nil, shared.ErrNotFound
	}
	return f, nil
}

func (m *MockFindingRepositoryForIngest) GetByFingerprint(_ context.Context, _ shared.ID, fingerprint string) (*vulnerability.Finding, error) {
	for _, f := range m.findings {
		if f.Fingerprint() == fingerprint {
			return f, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockFindingRepositoryForIngest) ExistsByFingerprint(_ context.Context, _ shared.ID, fingerprint string) (bool, error) {
	return m.fingerprints[fingerprint], nil
}

func (m *MockFindingRepositoryForIngest) ExistsByFingerprintBatch(_ context.Context, _ shared.ID, fingerprints []string) (map[string]bool, error) {
	result := make(map[string]bool)
	for _, fp := range fingerprints {
		result[fp] = m.fingerprints[fp]
	}
	return result, nil
}

func (m *MockFindingRepositoryForIngest) GetAll() []*vulnerability.Finding {
	result := make([]*vulnerability.Finding, 0, len(m.findings))
	for _, f := range m.findings {
		result = append(result, f)
	}
	return result
}

// =============================================================================
// Test: Semgrep Finding Parsing and Field Mapping
// =============================================================================

func TestIngestFinding_SemgrepFieldMapping(t *testing.T) {
	// Create a CTIS finding that simulates parsed semgrep output
	ctisFinding := &ctis.Finding{
		ID:                 "finding-1",
		Type:               ctis.FindingTypeVulnerability,
		Title:              "SQL Injection at /app/db.go:42",
		Description:        "User input flows directly to SQL query without sanitization",
		Severity:           ctis.SeverityCritical,
		Confidence:         90,
		Impact:             "HIGH",
		Likelihood:         "MEDIUM",
		Category:           "SQL Injection",
		VulnerabilityClass: []string{"SQL Injection"},
		Subcategory:        []string{"vuln"},
		RuleID:             "go.lang.security.audit.sqli.taint-sql-string-format",
		RuleName:           "Tainted SQL String Format",
		Fingerprint:        "abc123fingerprint",
		Vulnerability: &ctis.VulnerabilityDetails{
			CWEIDs:   []string{"CWE-89"},
			OWASPIDs: []string{"A01:2017 - Injection", "A03:2021 - Injection"},
		},
		Location: &ctis.FindingLocation{
			Path:        "/app/db.go",
			StartLine:   42,
			EndLine:     42,
			StartColumn: 10,
			EndColumn:   50,
			Snippet:     `db.Exec("SELECT * FROM users WHERE id = " + userInput)`,
		},
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
		Tags: []string{"sast", "sql", "injection"},
	}

	// Test field presence
	t.Run("AllFieldsPresent", func(t *testing.T) {
		if ctisFinding.Title == "" {
			t.Error("Title should not be empty")
		}
		if ctisFinding.Description == "" {
			t.Error("Description should not be empty")
		}
		if ctisFinding.Impact == "" {
			t.Error("Impact should not be empty")
		}
		if ctisFinding.Likelihood == "" {
			t.Error("Likelihood should not be empty")
		}
		if len(ctisFinding.VulnerabilityClass) == 0 {
			t.Error("VulnerabilityClass should not be empty")
		}
		if len(ctisFinding.Subcategory) == 0 {
			t.Error("Subcategory should not be empty")
		}
		if ctisFinding.Vulnerability == nil {
			t.Fatal("Vulnerability details should not be nil")
		}
		if len(ctisFinding.Vulnerability.CWEIDs) == 0 {
			t.Error("CWEIDs should not be empty")
		}
		if len(ctisFinding.Vulnerability.OWASPIDs) == 0 {
			t.Error("OWASPIDs should not be empty")
		}
	})

	// Test severity mapping
	t.Run("SeverityMapping", func(t *testing.T) {
		if ctisFinding.Severity != ctis.SeverityCritical {
			t.Errorf("Expected severity critical, got %s", ctisFinding.Severity)
		}
	})

	// Test location mapping
	t.Run("LocationMapping", func(t *testing.T) {
		if ctisFinding.Location == nil {
			t.Fatal("Location should not be nil")
		}
		if ctisFinding.Location.Path != "/app/db.go" {
			t.Errorf("Expected path /app/db.go, got %s", ctisFinding.Location.Path)
		}
		if ctisFinding.Location.StartLine != 42 {
			t.Errorf("Expected start line 42, got %d", ctisFinding.Location.StartLine)
		}
		if ctisFinding.Location.Snippet == "" {
			t.Error("Snippet should not be empty")
		}
	})
}

// =============================================================================
// Test: Domain Finding Entity Creation
// =============================================================================

func TestIngestFinding_DomainEntityCreation(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Create domain finding
	finding, err := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityCritical,
		"SQL Injection at /app/db.go:42",
	)
	if err != nil {
		t.Fatalf("Failed to create finding: %v", err)
	}

	// Set classification with CWE and OWASP
	err = finding.SetClassification(
		"",                 // No CVE for SAST findings
		nil,                // No CVSS score
		"",                 // No CVSS vector
		[]string{"CWE-89"}, // CWE IDs
		[]string{"A01:2017 - Injection", "A03:2021 - Injection"}, // OWASP IDs
	)
	if err != nil {
		t.Fatalf("Failed to set classification: %v", err)
	}

	// Set additional fields
	finding.SetDescription("User input flows directly to SQL query without sanitization")
	finding.SetRuleID("go.lang.security.audit.sqli.taint-sql-string-format")
	finding.SetRuleName("Tainted SQL String Format")
	finding.SetFingerprint("abc123fingerprint")
	finding.SetLocation("/app/db.go", 42, 42, 10, 50)
	finding.SetSnippet(`db.Exec("SELECT * FROM users WHERE id = " + userInput)`)

	// Verify fields
	t.Run("BasicFields", func(t *testing.T) {
		if finding.TenantID() != tenantID {
			t.Error("TenantID mismatch")
		}
		if finding.AssetID() != assetID {
			t.Error("AssetID mismatch")
		}
		if finding.Source() != vulnerability.FindingSourceSAST {
			t.Errorf("Expected source SAST, got %s", finding.Source())
		}
		if finding.ToolName() != "semgrep" {
			t.Errorf("Expected tool semgrep, got %s", finding.ToolName())
		}
	})

	t.Run("ClassificationFields", func(t *testing.T) {
		cweIDs := finding.CWEIDs()
		if len(cweIDs) != 1 || cweIDs[0] != "CWE-89" {
			t.Errorf("Expected CWE-89, got %v", cweIDs)
		}

		owaspIDs := finding.OWASPIDs()
		if len(owaspIDs) != 2 {
			t.Errorf("Expected 2 OWASP IDs, got %d", len(owaspIDs))
		}
	})

	t.Run("LocationFields", func(t *testing.T) {
		if finding.FilePath() != "/app/db.go" {
			t.Errorf("Expected path /app/db.go, got %s", finding.FilePath())
		}
		if finding.StartLine() != 42 {
			t.Errorf("Expected start line 42, got %d", finding.StartLine())
		}
	})
}

// =============================================================================
// Test: Finding Repository Operations
// =============================================================================

func TestIngestFinding_RepositoryOperations(t *testing.T) {
	ctx := context.Background()
	repo := NewMockFindingRepositoryForIngest()

	tenantID := shared.NewID()
	assetID := shared.NewID()

	// Create multiple findings
	findings := make([]*vulnerability.Finding, 0, 3)
	fingerprints := []string{"fp1", "fp2", "fp3"}

	for i, fp := range fingerprints {
		f, _ := vulnerability.NewFinding(
			tenantID,
			assetID,
			vulnerability.FindingSourceSAST,
			"semgrep",
			vulnerability.SeverityMedium,
			"Finding "+string(rune('A'+i)),
		)
		f.SetFingerprint(fp)
		findings = append(findings, f)
	}

	t.Run("BatchCreate", func(t *testing.T) {
		err := repo.CreateBatch(ctx, findings)
		if err != nil {
			t.Fatalf("Failed to create batch: %v", err)
		}

		stored := repo.GetAll()
		if len(stored) != 3 {
			t.Errorf("Expected 3 findings, got %d", len(stored))
		}
	})

	t.Run("FingerprintDeduplication", func(t *testing.T) {
		// Check existing fingerprints
		existsMap, err := repo.ExistsByFingerprintBatch(ctx, tenantID, fingerprints)
		if err != nil {
			t.Fatalf("Failed to check fingerprints: %v", err)
		}

		for _, fp := range fingerprints {
			if !existsMap[fp] {
				t.Errorf("Fingerprint %s should exist", fp)
			}
		}

		// Check non-existing fingerprint
		if existsMap["non-existing-fp"] {
			t.Error("Non-existing fingerprint should not exist")
		}
	})

	t.Run("GetByFingerprint", func(t *testing.T) {
		f, err := repo.GetByFingerprint(ctx, tenantID, "fp1")
		if err != nil {
			t.Fatalf("Failed to get by fingerprint: %v", err)
		}
		if f.Fingerprint() != "fp1" {
			t.Errorf("Expected fingerprint fp1, got %s", f.Fingerprint())
		}
	})
}

// =============================================================================
// Test: Branch-Aware Finding Lifecycle
// =============================================================================

func TestIngestFinding_BranchAwareLifecycle(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	repositoryID := shared.NewID()

	// Create a branch
	mainBranch, err := branch.NewBranch(repositoryID, "main", branch.TypeMain)
	if err != nil {
		t.Fatalf("Failed to create branch: %v", err)
	}

	// Create finding with branch
	finding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityHigh,
		"XSS in template",
	)
	finding.SetBranchID(mainBranch.ID())
	finding.SetBranchInfo("main", "abc123commit")

	t.Run("BranchAssociation", func(t *testing.T) {
		branchID := finding.BranchID()
		if branchID == nil {
			t.Fatal("BranchID should not be nil")
		}
		if *branchID != mainBranch.ID() {
			t.Error("BranchID mismatch")
		}
	})

	t.Run("BranchInfo", func(t *testing.T) {
		if finding.FirstDetectedBranch() != "main" {
			t.Errorf("Expected branch main, got %s", finding.FirstDetectedBranch())
		}
		if finding.FirstDetectedCommit() != "abc123commit" {
			t.Errorf("Expected commit abc123commit, got %s", finding.FirstDetectedCommit())
		}
	})
}

// =============================================================================
// Test: Full CTIS Report Processing
// =============================================================================

func TestIngestFinding_FullCTISReportProcessing(t *testing.T) {
	// Create a complete CTIS report
	report := &ctis.Report{
		Metadata: ctis.ReportMetadata{
			ID:         "scan-001",
			Timestamp:  time.Now(),
			SourceType: "scanner",
		},
		Tool: &ctis.Tool{
			Name:    "semgrep",
			Version: "1.50.0",
			Vendor:  "Semgrep Inc.",
		},
		Assets: []ctis.Asset{
			{
				ID:    "asset-1",
				Type:  ctis.AssetTypeRepository,
				Value: "github.com/example/repo",
				Name:  "example-repo",
			},
		},
		Findings: []ctis.Finding{
			{
				ID:                 "finding-1",
				Type:               ctis.FindingTypeVulnerability,
				Title:              "SQL Injection at db.go:42",
				Description:        "Tainted data flows to SQL query",
				Severity:           ctis.SeverityCritical,
				Confidence:         90,
				Impact:             "HIGH",
				Likelihood:         "MEDIUM",
				Category:           "SQL Injection",
				VulnerabilityClass: []string{"SQL Injection"},
				Subcategory:        []string{"vuln"},
				RuleID:             "go.sqli",
				RuleName:           "SQL Injection",
				AssetRef:           "asset-1",
				Fingerprint:        "fp-sqli-001",
				Vulnerability: &ctis.VulnerabilityDetails{
					CWEIDs:   []string{"CWE-89"},
					OWASPIDs: []string{"A03:2021"},
				},
				Location: &ctis.FindingLocation{
					Path:      "db.go",
					StartLine: 42,
					EndLine:   42,
				},
			},
			{
				ID:                 "finding-2",
				Type:               ctis.FindingTypeVulnerability,
				Title:              "XSS at template.go:100",
				Description:        "User input rendered without escaping",
				Severity:           ctis.SeverityHigh,
				Confidence:         85,
				Impact:             "MEDIUM",
				Likelihood:         "HIGH",
				Category:           "Cross-Site Scripting",
				VulnerabilityClass: []string{"Cross-Site-Scripting (XSS)"},
				Subcategory:        []string{"vuln"},
				RuleID:             "go.xss",
				RuleName:           "XSS",
				AssetRef:           "asset-1",
				Fingerprint:        "fp-xss-001",
				Vulnerability: &ctis.VulnerabilityDetails{
					CWEIDs:   []string{"CWE-79"},
					OWASPIDs: []string{"A03:2021", "A07:2017"},
				},
				Location: &ctis.FindingLocation{
					Path:      "template.go",
					StartLine: 100,
					EndLine:   100,
				},
			},
		},
	}

	t.Run("ReportMetadata", func(t *testing.T) {
		if report.Metadata.ID == "" {
			t.Error("Report ID should not be empty")
		}
		if report.Tool == nil {
			t.Fatal("Tool should not be nil")
		}
		if report.Tool.Name != "semgrep" {
			t.Errorf("Expected tool semgrep, got %s", report.Tool.Name)
		}
	})

	t.Run("FindingsCount", func(t *testing.T) {
		if len(report.Findings) != 2 {
			t.Errorf("Expected 2 findings, got %d", len(report.Findings))
		}
	})

	t.Run("FindingFieldsComplete", func(t *testing.T) {
		for i, f := range report.Findings {
			if f.Title == "" {
				t.Errorf("Finding %d: Title should not be empty", i)
			}
			if f.Description == "" {
				t.Errorf("Finding %d: Description should not be empty", i)
			}
			if f.Impact == "" {
				t.Errorf("Finding %d: Impact should not be empty", i)
			}
			if f.Likelihood == "" {
				t.Errorf("Finding %d: Likelihood should not be empty", i)
			}
			if len(f.VulnerabilityClass) == 0 {
				t.Errorf("Finding %d: VulnerabilityClass should not be empty", i)
			}
			if f.Vulnerability == nil {
				t.Errorf("Finding %d: Vulnerability details should not be nil", i)
				continue
			}
			if len(f.Vulnerability.CWEIDs) == 0 {
				t.Errorf("Finding %d: CWEIDs should not be empty", i)
			}
			if len(f.Vulnerability.OWASPIDs) == 0 {
				t.Errorf("Finding %d: OWASPIDs should not be empty", i)
			}
		}
	})

	t.Run("SeverityDistribution", func(t *testing.T) {
		severityCounts := make(map[ctis.Severity]int)
		for _, f := range report.Findings {
			severityCounts[f.Severity]++
		}

		if severityCounts[ctis.SeverityCritical] != 1 {
			t.Errorf("Expected 1 critical finding, got %d", severityCounts[ctis.SeverityCritical])
		}
		if severityCounts[ctis.SeverityHigh] != 1 {
			t.Errorf("Expected 1 high finding, got %d", severityCounts[ctis.SeverityHigh])
		}
	})
}

// =============================================================================
// Test: Status Transitions
// =============================================================================

func TestIngestFinding_StatusTransitions(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	actorID := shared.NewID()

	finding, _ := vulnerability.NewFinding(
		tenantID,
		assetID,
		vulnerability.FindingSourceSAST,
		"semgrep",
		vulnerability.SeverityMedium,
		"Test finding",
	)

	t.Run("InitialStatus", func(t *testing.T) {
		if finding.Status() != vulnerability.FindingStatusNew {
			t.Errorf("Expected status new, got %s", finding.Status())
		}
	})

	t.Run("TransitionToConfirmed", func(t *testing.T) {
		finding.UpdateStatus(vulnerability.FindingStatusConfirmed, "", nil)
		if finding.Status() != vulnerability.FindingStatusConfirmed {
			t.Errorf("Expected status confirmed, got %s", finding.Status())
		}
	})

	t.Run("TransitionToResolved", func(t *testing.T) {
		finding.UpdateStatus(vulnerability.FindingStatusResolved, "Fixed in commit abc123", &actorID)
		if finding.Status() != vulnerability.FindingStatusResolved {
			t.Errorf("Expected status resolved, got %s", finding.Status())
		}
		if finding.Resolution() != "Fixed in commit abc123" {
			t.Errorf("Expected resolution 'Fixed in commit abc123', got %s", finding.Resolution())
		}
		if finding.ResolvedBy() == nil || *finding.ResolvedBy() != actorID {
			t.Error("ResolvedBy should be set to actorID")
		}
	})
}
