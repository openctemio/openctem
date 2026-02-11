package ingest

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateAssetFromMetadata_Priority1_BranchInfo tests Priority 1: BranchInfo.RepositoryURL
func TestCreateAssetFromMetadata_Priority1_BranchInfo(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Metadata: ctis.ReportMetadata{
			Branch: &ctis.BranchInfo{
				RepositoryURL:   "github.com/org/repo",
				Name:            "main",
				CommitSHA:       "abc123",
				IsDefaultBranch: true,
			},
		},
		Findings: []ctis.Finding{
			{Title: "test finding"},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	assert.Equal(t, "github.com/org/repo", asset.Value)
	assert.Equal(t, ctis.AssetTypeRepository, asset.Type)
	assert.Equal(t, "branch_info", asset.Properties["source"])
	assert.Equal(t, true, asset.Properties["auto_created"])
	assert.Equal(t, "main", asset.Properties["branch"])
	assert.Equal(t, "abc123", asset.Properties["commit_sha"])
	assert.Equal(t, true, asset.Properties["default_branch"])
}

// TestCreateAssetFromMetadata_Priority2_UniqueFindingValue tests Priority 2: Unique AssetValue from findings
func TestCreateAssetFromMetadata_Priority2_UniqueFindingValue(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Title: "finding 1", AssetValue: "github.com/myorg/myrepo"},
			{Title: "finding 2", AssetValue: "github.com/myorg/myrepo"},
			{Title: "finding 3", AssetValue: "github.com/myorg/myrepo"},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	assert.Equal(t, "github.com/myorg/myrepo", asset.Value)
	assert.Equal(t, ctis.AssetTypeRepository, asset.Type)
	assert.Equal(t, "finding_asset_value", asset.Properties["source"])
	assert.Equal(t, 3, asset.Properties["finding_count"])
}

// TestCreateAssetFromMetadata_Priority2_MultipleDifferentValues tests that multiple different AssetValues don't create asset
func TestCreateAssetFromMetadata_Priority2_MultipleDifferentValues(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Title: "finding 1", AssetValue: "github.com/org1/repo1"},
			{Title: "finding 2", AssetValue: "github.com/org2/repo2"},
		},
	}

	// Should fall through to other priorities (scope, path, fallback)
	// Since no other context available, falls through to emergency fallback
	asset := p.createAssetFromMetadata(report)

	// With no tool/scan_id, still creates emergency fallback to prevent orphaned findings
	require.NotNil(t, asset)
	assert.Equal(t, ctis.AssetTypeUnclassified, asset.Type)
	assert.Equal(t, "emergency_fallback", asset.Properties["source"])
}

// TestCreateAssetFromMetadata_Priority2_WithExplicitType tests AssetType from finding
func TestCreateAssetFromMetadata_Priority2_WithExplicitType(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Findings: []ctis.Finding{
			{
				Title:      "finding 1",
				AssetValue: "api.example.com",
				AssetType:  ctis.AssetTypeDomain,
			},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	assert.Equal(t, "api.example.com", asset.Value)
	assert.Equal(t, ctis.AssetTypeDomain, asset.Type)
}

// TestCreateAssetFromMetadata_Priority3_Scope tests Priority 3: Scope information
func TestCreateAssetFromMetadata_Priority3_Scope(t *testing.T) {
	p := &AssetProcessor{}

	testCases := []struct {
		name         string
		scopeType    string
		expectedType ctis.AssetType
	}{
		{"repository", "repository", ctis.AssetTypeRepository},
		{"domain", "domain", ctis.AssetTypeDomain},
		{"ip_address", "ip_address", ctis.AssetTypeIPAddress},
		{"container", "container", ctis.AssetTypeContainer},
		{"cloud_account", "cloud_account", ctis.AssetTypeCloudAccount},
		{"unknown", "unknown_type", ctis.AssetTypeUnclassified},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report := &ctis.Report{
				Metadata: ctis.ReportMetadata{
					Scope: &ctis.Scope{
						Name: "test-scope",
						Type: tc.scopeType,
					},
				},
				Findings: []ctis.Finding{{Title: "test"}},
			}

			asset := p.createAssetFromMetadata(report)

			require.NotNil(t, asset)
			assert.Equal(t, "test-scope", asset.Value)
			assert.Equal(t, tc.expectedType, asset.Type)
			assert.Equal(t, "scope", asset.Properties["source"])
		})
	}
}

// TestCreateAssetFromMetadata_Priority4_PathInference_GitHost tests Priority 4: Git host URL patterns
func TestCreateAssetFromMetadata_Priority4_PathInference_GitHost(t *testing.T) {
	p := &AssetProcessor{}

	testCases := []struct {
		name        string
		path        string
		expectedURL string
	}{
		{
			name:        "github path",
			path:        "github.com/myorg/myrepo/pkg/handler.go",
			expectedURL: "https://github.com/myorg/myrepo",
		},
		{
			name:        "gitlab path",
			path:        "gitlab.com/company/project/src/main.py",
			expectedURL: "https://gitlab.com/company/project",
		},
		{
			name:        "bitbucket path",
			path:        "bitbucket.org/team/service/lib/utils.js",
			expectedURL: "https://bitbucket.org/team/service",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report := &ctis.Report{
				Findings: []ctis.Finding{
					{
						Title: "test finding",
						Location: &ctis.FindingLocation{
							Path: tc.path,
						},
					},
				},
			}

			asset := p.createAssetFromMetadata(report)

			require.NotNil(t, asset)
			assert.Equal(t, tc.expectedURL, asset.Value)
			assert.Equal(t, ctis.AssetTypeRepository, asset.Type)
			assert.Equal(t, "path_inference", asset.Properties["source"])
			assert.Equal(t, "git_host_url", asset.Properties["pattern"])
		})
	}
}

// TestCreateAssetFromMetadata_Priority4_PathInference_CommonPrefix tests common path prefix detection
func TestCreateAssetFromMetadata_Priority4_PathInference_CommonPrefix(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Title: "finding 1", Location: &ctis.FindingLocation{Path: "/home/user/myproject/src/main.go"}},
			{Title: "finding 2", Location: &ctis.FindingLocation{Path: "/home/user/myproject/pkg/utils.go"}},
			{Title: "finding 3", Location: &ctis.FindingLocation{Path: "/home/user/myproject/internal/handler.go"}},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	assert.Equal(t, "myproject", asset.Value)
	assert.Equal(t, ctis.AssetTypeRepository, asset.Type)
	assert.Equal(t, "path_inference", asset.Properties["source"])
	assert.Equal(t, "common_prefix", asset.Properties["pattern"])
}

// TestCreateAssetFromMetadata_Priority5_ToolFallback tests Priority 5: Tool+ScanID fallback
func TestCreateAssetFromMetadata_Priority5_ToolFallback(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Metadata: ctis.ReportMetadata{
			ID: "scan-123",
		},
		Tool: &ctis.Tool{
			Name:    "semgrep",
			Version: "1.50.0",
		},
		Findings: []ctis.Finding{
			{Title: "test finding"},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	assert.Equal(t, "scan:semgrep:scan-123", asset.Value)
	assert.Equal(t, ctis.AssetTypeUnclassified, asset.Type)
	assert.Equal(t, "tool_fallback", asset.Properties["source"])
	assert.Equal(t, "semgrep", asset.Properties["tool_name"])
	assert.Equal(t, "scan-123", asset.Properties["scan_id"])
}

// TestCreateAssetFromMetadata_Priority5_ToolFallback_NoScanID tests fallback with unknown scan_id
func TestCreateAssetFromMetadata_Priority5_ToolFallback_NoScanID(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Tool: &ctis.Tool{
			Name: "codeql",
		},
		Findings: []ctis.Finding{
			{Title: "test finding"},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	assert.Equal(t, "scan:codeql:unknown", asset.Value)
	assert.Equal(t, "tool_fallback", asset.Properties["source"])
}

// TestCreateAssetFromMetadata_NoContext tests when no context is available
func TestCreateAssetFromMetadata_NoContext(t *testing.T) {
	p := &AssetProcessor{}

	report := &ctis.Report{
		Findings: []ctis.Finding{
			{Title: "test finding"},
		},
	}

	asset := p.createAssetFromMetadata(report)

	// No tool means emergency fallback is used to prevent orphaned findings
	require.NotNil(t, asset)
	assert.Equal(t, ctis.AssetTypeUnclassified, asset.Type)
	assert.Equal(t, "emergency_fallback", asset.Properties["source"])
}

// TestCreateAssetFromMetadata_PriorityOrder tests that higher priorities take precedence
func TestCreateAssetFromMetadata_PriorityOrder(t *testing.T) {
	p := &AssetProcessor{}

	// Report with all priorities available
	report := &ctis.Report{
		Metadata: ctis.ReportMetadata{
			ID: "scan-123",
			Branch: &ctis.BranchInfo{
				RepositoryURL: "github.com/priority1/repo",
				Name:          "main",
			},
			Scope: &ctis.Scope{
				Name: "priority3-scope",
				Type: "repository",
			},
		},
		Tool: &ctis.Tool{
			Name: "semgrep",
		},
		Findings: []ctis.Finding{
			{
				Title:      "finding",
				AssetValue: "github.com/priority2/repo",
				Location: &ctis.FindingLocation{
					Path: "github.com/priority4/repo/src/main.go",
				},
			},
		},
	}

	asset := p.createAssetFromMetadata(report)

	require.NotNil(t, asset)
	// Priority 1 (BranchInfo) should win
	assert.Equal(t, "github.com/priority1/repo", asset.Value)
	assert.Equal(t, "branch_info", asset.Properties["source"])
}

// TestFindCommonPathPrefix tests the common path prefix finder
func TestFindCommonPathPrefix(t *testing.T) {
	testCases := []struct {
		name     string
		paths    []string
		expected string
	}{
		{
			name:     "common prefix",
			paths:    []string{"/a/b/c/file1.go", "/a/b/c/file2.go", "/a/b/c/d/file3.go"},
			expected: "/a/b/c",
		},
		{
			name:     "no common prefix",
			paths:    []string{"/a/file1.go", "/b/file2.go"},
			expected: "",
		},
		{
			name:     "single path",
			paths:    []string{"/a/b/c/file.go"},
			expected: "/a/b/c",
		},
		{
			name:     "empty paths",
			paths:    []string{},
			expected: "",
		},
		{
			name:     "relative paths",
			paths:    []string{"src/pkg/a.go", "src/pkg/b.go", "src/lib/c.go"},
			expected: "src",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := findCommonPathPrefix(tc.paths)
			assert.Equal(t, tc.expected, result)
		})
	}
}
