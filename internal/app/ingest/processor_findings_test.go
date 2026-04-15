package ingest

import (
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// isValidFingerprint tests
// =============================================================================

func TestIsValidFingerprint_ValidHex16Chars(t *testing.T) {
	// Exactly 16 hex characters - minimum valid length
	assert.True(t, isValidFingerprint("0123456789abcdef"))
}

func TestIsValidFingerprint_ShortHex(t *testing.T) {
	// Less than 16 hex chars should be invalid
	assert.False(t, isValidFingerprint("0123456789abcde")) // 15 chars
	assert.False(t, isValidFingerprint("abcdef"))          // 6 chars
	assert.False(t, isValidFingerprint("0"))               // 1 char
}

func TestIsValidFingerprint_RequiresLogin(t *testing.T) {
	// Semgrep returns "requires login" when pro features are unavailable
	assert.False(t, isValidFingerprint("requires login"))
}

func TestIsValidFingerprint_EmptyString(t *testing.T) {
	assert.False(t, isValidFingerprint(""))
}

func TestIsValidFingerprint_ValidSHA256(t *testing.T) {
	// 64-char SHA-256 hex string
	sha256Hex := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	assert.True(t, isValidFingerprint(sha256Hex))
}

func TestIsValidFingerprint_MixedCaseHex(t *testing.T) {
	// Mixed case hex should be valid
	assert.True(t, isValidFingerprint("0123456789ABCDEFabcdef0123456789"))
}

func TestIsValidFingerprint_StringWithSpaces(t *testing.T) {
	assert.False(t, isValidFingerprint("0123456789 abcdef"))
}

func TestIsValidFingerprint_NonHexChars(t *testing.T) {
	// Contains 'g' which is not hex
	assert.False(t, isValidFingerprint("0123456789abcdeg"))
	// Contains special characters
	assert.False(t, isValidFingerprint("0123456789abcde!"))
	// Contains underscores
	assert.False(t, isValidFingerprint("0123456789_abcde"))
}

func TestIsValidFingerprint_AllUpperCase(t *testing.T) {
	assert.True(t, isValidFingerprint("ABCDEF0123456789"))
}

func TestIsValidFingerprint_AllLowerCase(t *testing.T) {
	assert.True(t, isValidFingerprint("abcdef0123456789"))
}

// =============================================================================
// generateFindingFingerprint tests
// =============================================================================

func TestGenerateFindingFingerprint_WithValidProvidedFingerprint(t *testing.T) {
	assetID := shared.NewID()
	validFP := "a1b2c3d4e5f60718293a4b5c6d7e8f90"

	finding := &ctis.Finding{
		Fingerprint: validFP,
		RuleID:      "test-rule",
		Title:       "Test Finding",
	}

	result := generateFindingFingerprint(assetID, finding, nil)

	// Should be a composite fingerprint (SHA-256 = 64 chars)
	assert.Len(t, result, 64)
	// Should use the provided fingerprint as base, combined with assetID
	expected := createCompositeFingerprint(assetID.String(), validFP)
	assert.Equal(t, expected, result)
}

func TestGenerateFindingFingerprint_WithInvalidProvidedFingerprint(t *testing.T) {
	assetID := shared.NewID()

	finding := &ctis.Finding{
		Fingerprint: "requires login", // Invalid - non-hex
		RuleID:      "test-rule",
		Title:       "Test Finding",
	}

	result := generateFindingFingerprint(assetID, finding, nil)

	// Should generate via SDK instead of using the invalid fingerprint
	assert.Len(t, result, 64)
	// Should NOT be based on "requires login"
	invalidComposite := createCompositeFingerprint(assetID.String(), "requires login")
	assert.NotEqual(t, invalidComposite, result)
}

func TestGenerateFindingFingerprint_WithNoProvidedFingerprint(t *testing.T) {
	assetID := shared.NewID()

	finding := &ctis.Finding{
		RuleID: "test-rule",
		Title:  "Test Finding Message",
	}

	result := generateFindingFingerprint(assetID, finding, nil)

	// Should generate via SDK using ruleID and title as message
	assert.Len(t, result, 64)
	assert.NotEmpty(t, result)
}

func TestGenerateFindingFingerprint_WithLocationInfo(t *testing.T) {
	assetID := shared.NewID()

	finding := &ctis.Finding{
		RuleID: "sql-injection",
		Title:  "SQL Injection",
		Location: &ctis.FindingLocation{
			Path:      "src/main.go",
			StartLine: 42,
			EndLine:   45,
		},
	}

	// Without location
	findingNoLoc := &ctis.Finding{
		RuleID: "sql-injection",
		Title:  "SQL Injection",
	}

	fpWithLoc := generateFindingFingerprint(assetID, finding, nil)
	fpNoLoc := generateFindingFingerprint(assetID, findingNoLoc, nil)

	// Location should affect the fingerprint
	assert.NotEqual(t, fpWithLoc, fpNoLoc)
}

func TestGenerateFindingFingerprint_WithCVEID(t *testing.T) {
	assetID := shared.NewID()

	// When CVE is present, the base fingerprint uses it in the Input
	// However, since the fingerprint.Input.Type is not explicitly set,
	// the SDK uses the "generic" type which only uses RuleID, FilePath,
	// StartLine, EndLine, and Message. VulnerabilityID is only used
	// when Type is "sca". So the composite fingerprints will be equal
	// in the generic case.
	finding := &ctis.Finding{
		RuleID: "sca-check",
		Title:  "Vulnerable Dependency",
		Vulnerability: &ctis.VulnerabilityDetails{
			CVEID: "CVE-2023-12345",
		},
	}

	findingNoCVE := &ctis.Finding{
		RuleID: "sca-check",
		Title:  "Vulnerable Dependency",
	}

	fpWithCVE := generateFindingFingerprint(assetID, finding, nil)
	fpNoCVE := generateFindingFingerprint(assetID, findingNoCVE, nil)

	// Both should produce valid fingerprints
	assert.Len(t, fpWithCVE, 64)
	assert.Len(t, fpNoCVE, 64)

	// In the generic fingerprint type, CVE is not used as an input field,
	// so the fingerprints are the same. This is expected behavior because
	// the generic fingerprint deduplicates by rule+location+message.
	assert.Equal(t, fpWithCVE, fpNoCVE,
		"generic fingerprint type does not use VulnerabilityID")
}

func TestGenerateFindingFingerprint_Deterministic(t *testing.T) {
	assetID := shared.NewID()

	finding := &ctis.Finding{
		RuleID: "test-rule",
		Title:  "Test Finding",
		Location: &ctis.FindingLocation{
			Path:      "src/main.go",
			StartLine: 10,
			EndLine:   15,
		},
	}

	fp1 := generateFindingFingerprint(assetID, finding, nil)
	fp2 := generateFindingFingerprint(assetID, finding, nil)

	assert.Equal(t, fp1, fp2, "same inputs must produce same fingerprint")
}

func TestGenerateFindingFingerprint_DifferentAssetsProduceDifferentFingerprints(t *testing.T) {
	assetID1 := shared.NewID()
	assetID2 := shared.NewID()

	finding := &ctis.Finding{
		RuleID: "test-rule",
		Title:  "Same Finding",
		Location: &ctis.FindingLocation{
			Path:      "src/main.go",
			StartLine: 10,
		},
	}

	fp1 := generateFindingFingerprint(assetID1, finding, nil)
	fp2 := generateFindingFingerprint(assetID2, finding, nil)

	assert.NotEqual(t, fp1, fp2, "different assets must produce different fingerprints even with same finding")
}

func TestGenerateFindingFingerprint_CompositeFormat(t *testing.T) {
	assetID := shared.NewID()

	finding := &ctis.Finding{
		RuleID: "test-rule",
		Title:  "Test Finding",
	}

	result := generateFindingFingerprint(assetID, finding, nil)

	// Result should be a SHA-256 hex hash (64 chars, all hex)
	assert.Len(t, result, 64)
	assert.True(t, isValidFingerprint(result), "result should be a valid hex fingerprint")
}

func TestGenerateFindingFingerprint_ShortProvidedFingerprintFallsBackToSDK(t *testing.T) {
	assetID := shared.NewID()

	// Short hex string (< 16 chars) - invalid
	finding := &ctis.Finding{
		Fingerprint: "abcdef",
		RuleID:      "test-rule",
		Title:       "Test Finding",
	}

	result := generateFindingFingerprint(assetID, finding, nil)

	// Should not use the short fingerprint as base
	shortComposite := createCompositeFingerprint(assetID.String(), "abcdef")
	assert.NotEqual(t, shortComposite, result)
	assert.Len(t, result, 64)
}

// =============================================================================
// inferFindingType tests
// =============================================================================

func TestInferFindingType_ExplicitVulnerability(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{Type: ctis.FindingTypeVulnerability}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestInferFindingType_ExplicitSecret(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{Type: ctis.FindingTypeSecret}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeSecret, result)
}

func TestInferFindingType_ExplicitMisconfiguration(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{Type: ctis.FindingTypeMisconfiguration}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeMisconfiguration, result)
}

func TestInferFindingType_ExplicitCompliance(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{Type: ctis.FindingTypeCompliance}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeCompliance, result)
}

func TestInferFindingType_ExplicitTypeOverridesSource(t *testing.T) {
	p := &FindingProcessor{}
	// Explicit type "vulnerability" should override source "secret"
	finding := &ctis.Finding{Type: ctis.FindingTypeVulnerability}

	result := p.inferFindingType(vulnerability.FindingSourceSecret, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestInferFindingType_SourceSecret(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{} // No explicit type

	result := p.inferFindingType(vulnerability.FindingSourceSecret, finding)
	assert.Equal(t, vulnerability.FindingTypeSecret, result)
}

func TestInferFindingType_SourceIaC(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{} // No explicit type

	result := p.inferFindingType(vulnerability.FindingSourceIaC, finding)
	assert.Equal(t, vulnerability.FindingTypeMisconfiguration, result)
}

func TestInferFindingType_ComplianceDataPresent(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Compliance: &ctis.ComplianceDetails{
			Framework: "pci-dss",
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeCompliance, result)
}

func TestInferFindingType_ComplianceDataWithEmptyFramework(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Compliance: &ctis.ComplianceDetails{
			Framework: "", // Empty framework - should not match
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	// Empty framework means compliance check fails, falls through to default
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestInferFindingType_Web3DataChain(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Web3: &ctis.Web3VulnerabilityDetails{
			Chain: "ethereum",
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeWeb3, result)
}

func TestInferFindingType_Web3DataSWCID(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Web3: &ctis.Web3VulnerabilityDetails{
			SWCID: "SWC-107",
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeWeb3, result)
}

func TestInferFindingType_Web3DataEmptyFields(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Web3: &ctis.Web3VulnerabilityDetails{
			// Both Chain and SWCID empty - should not match
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestInferFindingType_MisconfigDataPolicyID(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Misconfiguration: &ctis.MisconfigurationDetails{
			PolicyID: "AVD-AWS-0001",
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeMisconfiguration, result)
}

func TestInferFindingType_MisconfigDataEmptyPolicyID(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Misconfiguration: &ctis.MisconfigurationDetails{
			PolicyID: "", // Empty - should not match
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestInferFindingType_DefaultVulnerability(t *testing.T) {
	p := &FindingProcessor{}
	finding := &ctis.Finding{} // No type, no special data

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestInferFindingType_PriorityOrder(t *testing.T) {
	p := &FindingProcessor{}

	// When explicit type AND compliance data are both present, explicit type wins
	finding := &ctis.Finding{
		Type: ctis.FindingTypeVulnerability,
		Compliance: &ctis.ComplianceDetails{
			Framework: "cis",
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result,
		"explicit type should take priority over inferred type")
}

func TestInferFindingType_SourcePriorityOverData(t *testing.T) {
	p := &FindingProcessor{}

	// Source "secret" should match before compliance data check
	finding := &ctis.Finding{
		Compliance: &ctis.ComplianceDetails{
			Framework: "pci-dss",
		},
	}

	result := p.inferFindingType(vulnerability.FindingSourceSecret, finding)
	assert.Equal(t, vulnerability.FindingTypeSecret, result,
		"source-based inference should take priority over data-based inference")
}

// =============================================================================
// mapCTISLocationToDomain tests
// =============================================================================

func TestMapCTISLocationToDomain_NilLocation(t *testing.T) {
	result := mapCTISLocationToDomain(nil)
	assert.Equal(t, vulnerability.FindingLocation{}, result)
}

func TestMapCTISLocationToDomain_AllFieldsMapped(t *testing.T) {
	loc := &ctis.FindingLocation{
		Path:           "src/main.go",
		StartLine:      10,
		EndLine:        15,
		StartColumn:    5,
		EndColumn:      30,
		Snippet:        "password = 'secret'",
		ContextSnippet: "func main() {\n  password = 'secret'\n}",
		Branch:         "main",
		CommitSHA:      "abc123def456",
	}

	result := mapCTISLocationToDomain(loc)

	assert.Equal(t, "src/main.go", result.Path)
	assert.Equal(t, 10, result.StartLine)
	assert.Equal(t, 15, result.EndLine)
	assert.Equal(t, 5, result.StartColumn)
	assert.Equal(t, 30, result.EndColumn)
	assert.Equal(t, "password = 'secret'", result.Snippet)
	assert.Equal(t, "func main() {\n  password = 'secret'\n}", result.ContextSnippet)
	assert.Equal(t, "main", result.Branch)
	assert.Equal(t, "abc123def456", result.CommitSHA)
	assert.Nil(t, result.LogicalLocation)
}

func TestMapCTISLocationToDomain_WithLogicalLocation(t *testing.T) {
	loc := &ctis.FindingLocation{
		Path:      "src/auth/handler.go",
		StartLine: 42,
		LogicalLocation: &ctis.LogicalLocation{
			Name:               "handleLogin",
			Kind:               "function",
			FullyQualifiedName: "auth.Handler.handleLogin",
		},
	}

	result := mapCTISLocationToDomain(loc)

	require.NotNil(t, result.LogicalLocation)
	assert.Equal(t, "handleLogin", result.LogicalLocation.Name)
	assert.Equal(t, "function", result.LogicalLocation.Kind)
	assert.Equal(t, "auth.Handler.handleLogin", result.LogicalLocation.FullyQualifiedName)
}

func TestMapCTISLocationToDomain_WithoutLogicalLocation(t *testing.T) {
	loc := &ctis.FindingLocation{
		Path:      "src/main.go",
		StartLine: 1,
	}

	result := mapCTISLocationToDomain(loc)

	assert.Nil(t, result.LogicalLocation)
	assert.Equal(t, "src/main.go", result.Path)
	assert.Equal(t, 1, result.StartLine)
}

func TestMapCTISLocationToDomain_EmptyLocation(t *testing.T) {
	loc := &ctis.FindingLocation{}

	result := mapCTISLocationToDomain(loc)

	assert.Equal(t, "", result.Path)
	assert.Equal(t, 0, result.StartLine)
	assert.Equal(t, 0, result.EndLine)
	assert.Nil(t, result.LogicalLocation)
}

// =============================================================================
// mapCTISStackTraceToDomain tests
// =============================================================================

func TestMapCTISStackTraceToDomain_Nil(t *testing.T) {
	result := mapCTISStackTraceToDomain(nil)
	assert.Equal(t, vulnerability.StackTrace{}, result)
}

func TestMapCTISStackTraceToDomain_WithMessageAndFrames(t *testing.T) {
	st := &ctis.StackTrace{
		Message: "Call stack at error point",
		Frames: []*ctis.StackFrame{
			{
				Module:     "auth",
				ThreadID:   1,
				Parameters: []string{"username", "password"},
			},
			{
				Module:   "http",
				ThreadID: 1,
			},
		},
	}

	result := mapCTISStackTraceToDomain(st)

	assert.Equal(t, "Call stack at error point", result.Message)
	require.Len(t, result.Frames, 2)
	assert.Equal(t, "auth", result.Frames[0].Module)
	assert.Equal(t, 1, result.Frames[0].ThreadID)
	assert.Equal(t, []string{"username", "password"}, result.Frames[0].Parameters)
	assert.Nil(t, result.Frames[0].Location)
	assert.Equal(t, "http", result.Frames[1].Module)
}

func TestMapCTISStackTraceToDomain_FramesWithLocations(t *testing.T) {
	st := &ctis.StackTrace{
		Message: "Stack trace",
		Frames: []*ctis.StackFrame{
			{
				Module: "main",
				Location: &ctis.FindingLocation{
					Path:      "src/main.go",
					StartLine: 42,
					EndLine:   42,
					Snippet:   "err = doSomething()",
				},
			},
		},
	}

	result := mapCTISStackTraceToDomain(st)

	require.Len(t, result.Frames, 1)
	require.NotNil(t, result.Frames[0].Location)
	assert.Equal(t, "src/main.go", result.Frames[0].Location.Path)
	assert.Equal(t, 42, result.Frames[0].Location.StartLine)
	assert.Equal(t, "err = doSomething()", result.Frames[0].Location.Snippet)
}

func TestMapCTISStackTraceToDomain_EmptyFrames(t *testing.T) {
	st := &ctis.StackTrace{
		Message: "Empty stack",
		Frames:  []*ctis.StackFrame{},
	}

	result := mapCTISStackTraceToDomain(st)

	assert.Equal(t, "Empty stack", result.Message)
	assert.Nil(t, result.Frames)
}

func TestMapCTISStackTraceToDomain_NilFrames(t *testing.T) {
	st := &ctis.StackTrace{
		Message: "No frames",
	}

	result := mapCTISStackTraceToDomain(st)

	assert.Equal(t, "No frames", result.Message)
	assert.Nil(t, result.Frames)
}

func TestMapCTISStackTraceToDomain_FrameWithLogicalLocation(t *testing.T) {
	st := &ctis.StackTrace{
		Frames: []*ctis.StackFrame{
			{
				Location: &ctis.FindingLocation{
					Path:      "src/handler.go",
					StartLine: 55,
					LogicalLocation: &ctis.LogicalLocation{
						Name:               "processRequest",
						Kind:               "function",
						FullyQualifiedName: "handler.processRequest",
					},
				},
			},
		},
	}

	result := mapCTISStackTraceToDomain(st)

	require.Len(t, result.Frames, 1)
	require.NotNil(t, result.Frames[0].Location)
	require.NotNil(t, result.Frames[0].Location.LogicalLocation)
	assert.Equal(t, "processRequest", result.Frames[0].Location.LogicalLocation.Name)
}

// =============================================================================
// mapCTISAttachmentToDomain tests
// =============================================================================

func TestMapCTISAttachmentToDomain_Nil(t *testing.T) {
	result := mapCTISAttachmentToDomain(nil)
	assert.Equal(t, vulnerability.Attachment{}, result)
}

func TestMapCTISAttachmentToDomain_WithArtifactLocation(t *testing.T) {
	att := &ctis.Attachment{
		Description: "Screenshot of vulnerability",
		ArtifactLocation: &ctis.ArtifactLocation{
			URI:       "file:///screenshots/vuln-001.png",
			URIBaseID: "%SRCROOT%",
		},
	}

	result := mapCTISAttachmentToDomain(att)

	assert.Equal(t, "Screenshot of vulnerability", result.Description)
	require.NotNil(t, result.ArtifactLocation)
	assert.Equal(t, "file:///screenshots/vuln-001.png", result.ArtifactLocation.URI)
	assert.Equal(t, "%SRCROOT%", result.ArtifactLocation.URIBaseID)
	assert.Nil(t, result.Regions)
}

func TestMapCTISAttachmentToDomain_WithRegions(t *testing.T) {
	att := &ctis.Attachment{
		Description: "Code evidence",
		Regions: []*ctis.FindingLocation{
			{
				Path:      "src/auth.go",
				StartLine: 10,
				EndLine:   20,
				Snippet:   "vulnerable code block",
			},
			{
				Path:      "src/auth.go",
				StartLine: 50,
				EndLine:   55,
			},
		},
	}

	result := mapCTISAttachmentToDomain(att)

	assert.Equal(t, "Code evidence", result.Description)
	assert.Nil(t, result.ArtifactLocation)
	require.Len(t, result.Regions, 2)
	assert.Equal(t, "src/auth.go", result.Regions[0].Path)
	assert.Equal(t, 10, result.Regions[0].StartLine)
	assert.Equal(t, 20, result.Regions[0].EndLine)
	assert.Equal(t, "vulnerable code block", result.Regions[0].Snippet)
	assert.Equal(t, 50, result.Regions[1].StartLine)
}

func TestMapCTISAttachmentToDomain_WithArtifactAndRegions(t *testing.T) {
	att := &ctis.Attachment{
		Description: "Full evidence",
		ArtifactLocation: &ctis.ArtifactLocation{
			URI: "file:///src/main.go",
		},
		Regions: []*ctis.FindingLocation{
			{
				Path:      "src/main.go",
				StartLine: 5,
				EndLine:   10,
			},
		},
	}

	result := mapCTISAttachmentToDomain(att)

	require.NotNil(t, result.ArtifactLocation)
	assert.Equal(t, "file:///src/main.go", result.ArtifactLocation.URI)
	require.Len(t, result.Regions, 1)
	assert.Equal(t, 5, result.Regions[0].StartLine)
}

func TestMapCTISAttachmentToDomain_EmptyAttachment(t *testing.T) {
	att := &ctis.Attachment{}

	result := mapCTISAttachmentToDomain(att)

	assert.Equal(t, "", result.Description)
	assert.Nil(t, result.ArtifactLocation)
	assert.Nil(t, result.Regions)
}

func TestMapCTISAttachmentToDomain_EmptyRegions(t *testing.T) {
	att := &ctis.Attachment{
		Description: "No regions",
		Regions:     []*ctis.FindingLocation{},
	}

	result := mapCTISAttachmentToDomain(att)

	assert.Equal(t, "No regions", result.Description)
	assert.Nil(t, result.Regions)
}

// =============================================================================
// mapCTISDataFlowToDomain tests
// =============================================================================

func TestMapCTISDataFlowToDomain_Nil(t *testing.T) {
	result := mapCTISDataFlowToDomain(nil)
	assert.Equal(t, vulnerability.DataFlow{}, result)
}

func TestMapCTISDataFlowToDomain_SourcesOnly(t *testing.T) {
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{
				Path:    "src/input.go",
				Line:    10,
				Content: "userInput := r.FormValue(\"name\")",
				Label:   "userInput",
			},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	require.Len(t, result.Steps, 1)
	assert.Equal(t, 0, result.Steps[0].Index)
	assert.Equal(t, vulnerability.LocationTypeSource, result.Steps[0].LocationType)
	assert.Equal(t, "userInput", result.Steps[0].Label)
	require.NotNil(t, result.Steps[0].Location)
	assert.Equal(t, "src/input.go", result.Steps[0].Location.Path)
	assert.Equal(t, 10, result.Steps[0].Location.StartLine)
	assert.Equal(t, "userInput := r.FormValue(\"name\")", result.Steps[0].Location.Snippet)
}

func TestMapCTISDataFlowToDomain_IntermediatesOnly(t *testing.T) {
	df := &ctis.DataFlow{
		Intermediates: []ctis.DataFlowLocation{
			{
				Path:    "src/process.go",
				Line:    20,
				Content: "processed := transform(data)",
				Label:   "processed",
			},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	require.Len(t, result.Steps, 1)
	assert.Equal(t, 0, result.Steps[0].Index)
	assert.Equal(t, vulnerability.LocationTypeIntermediate, result.Steps[0].LocationType)
}

func TestMapCTISDataFlowToDomain_SinksOnly(t *testing.T) {
	df := &ctis.DataFlow{
		Sinks: []ctis.DataFlowLocation{
			{
				Path:    "src/db.go",
				Line:    30,
				Content: "db.Query(sql)",
				Label:   "sql",
			},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	require.Len(t, result.Steps, 1)
	assert.Equal(t, 0, result.Steps[0].Index)
	assert.Equal(t, vulnerability.LocationTypeSink, result.Steps[0].LocationType)
}

func TestMapCTISDataFlowToDomain_SequentialStepIndices(t *testing.T) {
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "src/a.go", Line: 1, Label: "source1"},
			{Path: "src/a.go", Line: 2, Label: "source2"},
		},
		Intermediates: []ctis.DataFlowLocation{
			{Path: "src/b.go", Line: 10, Label: "inter1"},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "src/c.go", Line: 20, Label: "sink1"},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	require.Len(t, result.Steps, 4)

	// Check sequential indices
	for i, step := range result.Steps {
		assert.Equal(t, i, step.Index, "step %d should have index %d", i, i)
	}
}

func TestMapCTISDataFlowToDomain_MixedSourcesIntermediatesSinks(t *testing.T) {
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "src/input.go", Line: 5, Label: "userInput"},
		},
		Intermediates: []ctis.DataFlowLocation{
			{Path: "src/transform.go", Line: 15, Label: "transformed"},
			{Path: "src/validate.go", Line: 25, Label: "validated"},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "src/query.go", Line: 35, Label: "sqlQuery"},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	require.Len(t, result.Steps, 4)

	// Step 0: source
	assert.Equal(t, 0, result.Steps[0].Index)
	assert.Equal(t, vulnerability.LocationTypeSource, result.Steps[0].LocationType)
	assert.Equal(t, "userInput", result.Steps[0].Label)

	// Step 1: intermediate
	assert.Equal(t, 1, result.Steps[1].Index)
	assert.Equal(t, vulnerability.LocationTypeIntermediate, result.Steps[1].LocationType)
	assert.Equal(t, "transformed", result.Steps[1].Label)

	// Step 2: intermediate
	assert.Equal(t, 2, result.Steps[2].Index)
	assert.Equal(t, vulnerability.LocationTypeIntermediate, result.Steps[2].LocationType)
	assert.Equal(t, "validated", result.Steps[2].Label)

	// Step 3: sink
	assert.Equal(t, 3, result.Steps[3].Index)
	assert.Equal(t, vulnerability.LocationTypeSink, result.Steps[3].LocationType)
	assert.Equal(t, "sqlQuery", result.Steps[3].Label)

	// Check metadata
	assert.Equal(t, 0, result.Index)
	assert.Equal(t, "essential", result.Importance)
}

func TestMapCTISDataFlowToDomain_EmptyDataFlow(t *testing.T) {
	df := &ctis.DataFlow{}

	result := mapCTISDataFlowToDomain(df)

	assert.Empty(t, result.Steps)
	assert.Equal(t, 0, result.Index)
	assert.Equal(t, "essential", result.Importance)
}

// =============================================================================
// mapCTISDataFlowLocationToStep tests
// =============================================================================

func TestMapCTISDataFlowLocationToStep_BasicConversion(t *testing.T) {
	loc := ctis.DataFlowLocation{
		Path:    "src/handler.go",
		Line:    42,
		Column:  10,
		Content: "password := r.FormValue(\"password\")",
		Label:   "password",
	}

	result := mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeSource, 0)

	assert.Equal(t, 0, result.Index)
	assert.Equal(t, vulnerability.LocationTypeSource, result.LocationType)
	assert.Equal(t, "password", result.Label)
	assert.Equal(t, "essential", result.Importance)

	require.NotNil(t, result.Location)
	assert.Equal(t, "src/handler.go", result.Location.Path)
	assert.Equal(t, 42, result.Location.StartLine)
	assert.Equal(t, 10, result.Location.StartColumn)
	assert.Equal(t, "password := r.FormValue(\"password\")", result.Location.Snippet)
}

func TestMapCTISDataFlowLocationToStep_PathLineColumnMapped(t *testing.T) {
	loc := ctis.DataFlowLocation{
		Path:   "src/db/query.go",
		Line:   100,
		Column: 5,
	}

	result := mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeSink, 3)

	assert.Equal(t, 3, result.Index)
	assert.Equal(t, vulnerability.LocationTypeSink, result.LocationType)

	require.NotNil(t, result.Location)
	assert.Equal(t, "src/db/query.go", result.Location.Path)
	assert.Equal(t, 100, result.Location.StartLine)
	assert.Equal(t, 5, result.Location.StartColumn)
}

func TestMapCTISDataFlowLocationToStep_EmptyLocation(t *testing.T) {
	loc := ctis.DataFlowLocation{}

	result := mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeIntermediate, 1)

	assert.Equal(t, 1, result.Index)
	assert.Equal(t, vulnerability.LocationTypeIntermediate, result.LocationType)
	assert.Equal(t, "", result.Label)
	assert.Equal(t, "essential", result.Importance)

	require.NotNil(t, result.Location)
	assert.Equal(t, "", result.Location.Path)
	assert.Equal(t, 0, result.Location.StartLine)
}

func TestMapCTISDataFlowLocationToStep_AllLocationTypes(t *testing.T) {
	loc := ctis.DataFlowLocation{Path: "test.go", Line: 1}

	tests := []struct {
		name         string
		locationType string
	}{
		{"source", vulnerability.LocationTypeSource},
		{"intermediate", vulnerability.LocationTypeIntermediate},
		{"sink", vulnerability.LocationTypeSink},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapCTISDataFlowLocationToStep(loc, tt.locationType, 0)
			assert.Equal(t, tt.locationType, result.LocationType)
		})
	}
}

// =============================================================================
// Integration / Edge Case Tests
// =============================================================================

func TestGenerateFindingFingerprint_EmptyFinding(t *testing.T) {
	assetID := shared.NewID()
	finding := &ctis.Finding{}

	result := generateFindingFingerprint(assetID, finding, nil)

	// Should still produce a valid fingerprint even with empty finding
	assert.Len(t, result, 64)
	assert.True(t, isValidFingerprint(result))
}

func TestGenerateFindingFingerprint_WithToolContext(t *testing.T) {
	assetID := shared.NewID()
	finding := &ctis.Finding{
		RuleID: "test-rule",
		Title:  "Test",
	}
	tool := &ctis.Tool{
		Name:    "semgrep",
		Version: "1.0.0",
	}

	// Tool is passed but the current implementation doesn't use it
	// in fingerprint generation. Verify it doesn't cause panic.
	result := generateFindingFingerprint(assetID, finding, tool)
	assert.Len(t, result, 64)
}

func TestIsValidFingerprint_LongHexString(t *testing.T) {
	// Very long hex string should still be valid (no max length check)
	longHex := strings.Repeat("abcdef0123456789", 10) // 160 chars
	assert.True(t, isValidFingerprint(longHex))
}

func TestMapCTISLocationToDomain_PreservesAllFields(t *testing.T) {
	// Verify no field is lost during mapping
	loc := &ctis.FindingLocation{
		Path:           "/path/to/file.go",
		StartLine:      100,
		EndLine:        200,
		StartColumn:    1,
		EndColumn:      80,
		Snippet:        "code here",
		ContextSnippet: "context here",
		Branch:         "feature-branch",
		CommitSHA:      "deadbeef12345678",
		LogicalLocation: &ctis.LogicalLocation{
			Name:               "myFunc",
			Kind:               "method",
			FullyQualifiedName: "pkg.Class.myFunc",
		},
	}

	result := mapCTISLocationToDomain(loc)

	// Verify every field is mapped
	assert.Equal(t, loc.Path, result.Path)
	assert.Equal(t, loc.StartLine, result.StartLine)
	assert.Equal(t, loc.EndLine, result.EndLine)
	assert.Equal(t, loc.StartColumn, result.StartColumn)
	assert.Equal(t, loc.EndColumn, result.EndColumn)
	assert.Equal(t, loc.Snippet, result.Snippet)
	assert.Equal(t, loc.ContextSnippet, result.ContextSnippet)
	assert.Equal(t, loc.Branch, result.Branch)
	assert.Equal(t, loc.CommitSHA, result.CommitSHA)
	require.NotNil(t, result.LogicalLocation)
	assert.Equal(t, loc.LogicalLocation.Name, result.LogicalLocation.Name)
	assert.Equal(t, loc.LogicalLocation.Kind, result.LogicalLocation.Kind)
	assert.Equal(t, loc.LogicalLocation.FullyQualifiedName, result.LogicalLocation.FullyQualifiedName)
}

func TestMapCTISDataFlowToDomain_OnlySanitizersIgnored(t *testing.T) {
	// Sanitizers are in the CTIS DataFlow but not mapped to steps
	// (only Sources, Intermediates, Sinks are mapped)
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "src/a.go", Line: 1},
		},
		Sanitizers: []ctis.DataFlowLocation{
			{Path: "src/sanitize.go", Line: 50}, // This is NOT mapped
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "src/b.go", Line: 100},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	// Only sources and sinks should be present (sanitizers are ignored)
	require.Len(t, result.Steps, 2)
	assert.Equal(t, vulnerability.LocationTypeSource, result.Steps[0].LocationType)
	assert.Equal(t, vulnerability.LocationTypeSink, result.Steps[1].LocationType)
}

func TestMapCTISAttachmentToDomain_RegionsWithLogicalLocations(t *testing.T) {
	att := &ctis.Attachment{
		Description: "Evidence with logical locations",
		Regions: []*ctis.FindingLocation{
			{
				Path:      "src/main.go",
				StartLine: 10,
				LogicalLocation: &ctis.LogicalLocation{
					Name: "main",
					Kind: "function",
				},
			},
		},
	}

	result := mapCTISAttachmentToDomain(att)

	require.Len(t, result.Regions, 1)
	require.NotNil(t, result.Regions[0].LogicalLocation)
	assert.Equal(t, "main", result.Regions[0].LogicalLocation.Name)
}

func TestInferFindingType_NilSubStructs(t *testing.T) {
	// All sub-structs are nil - should default to vulnerability
	p := &FindingProcessor{}
	finding := &ctis.Finding{
		Compliance:       nil,
		Web3:             nil,
		Misconfiguration: nil,
	}

	result := p.inferFindingType(vulnerability.FindingSourceSAST, finding)
	assert.Equal(t, vulnerability.FindingTypeVulnerability, result)
}

func TestMapCTISDataFlowLocationToStep_ContentMapsToSnippet(t *testing.T) {
	// Verify that DataFlowLocation.Content maps to FindingLocation.Snippet
	loc := ctis.DataFlowLocation{
		Path:    "test.go",
		Line:    5,
		Content: "x = getUserInput()",
	}

	result := mapCTISDataFlowLocationToStep(loc, vulnerability.LocationTypeSource, 0)

	require.NotNil(t, result.Location)
	assert.Equal(t, "x = getUserInput()", result.Location.Snippet,
		"DataFlowLocation.Content should map to FindingLocation.Snippet")
}

func TestMapCTISDataFlowToDomain_MultipleSources(t *testing.T) {
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "src/input1.go", Line: 10, Label: "input1"},
			{Path: "src/input2.go", Line: 20, Label: "input2"},
			{Path: "src/input3.go", Line: 30, Label: "input3"},
		},
	}

	result := mapCTISDataFlowToDomain(df)

	require.Len(t, result.Steps, 3)
	for i, step := range result.Steps {
		assert.Equal(t, i, step.Index)
		assert.Equal(t, vulnerability.LocationTypeSource, step.LocationType)
	}
	assert.Equal(t, "input1", result.Steps[0].Label)
	assert.Equal(t, "input2", result.Steps[1].Label)
	assert.Equal(t, "input3", result.Steps[2].Label)
}
