package ingest

import (
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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

func TestInferAssetExposure(t *testing.T) {
	mk := func(name string, typ asset.AssetType, props map[string]any) *asset.Asset {
		a, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
		if err != nil {
			t.Fatalf("NewAsset: %v", err)
		}
		if props != nil {
			a.SetProperties(props)
		}
		return a
	}
	cases := []struct {
		name string
		a    *asset.Asset
		want asset.Exposure
	}{
		{"domain is internet-facing", mk("example.com", asset.AssetTypeDomain, nil), asset.ExposurePublic},
		{"legacy ip string (public)", mk("web-1", asset.AssetTypeHost, map[string]any{"ip": "8.8.8.8"}), asset.ExposurePublic},
		{"legacy ip string (private)", mk("db-1", asset.AssetTypeHost, map[string]any{"ip": "10.0.0.5"}), asset.ExposureUnknown},
		// The shapes normalised host properties really have: []string right
		// after ingest, []any once read back from JSONB.
		{"ip_addresses []string (public)", mk("web-2", asset.AssetTypeHost, map[string]any{"ip_addresses": []string{"10.0.0.7", "8.8.4.4"}}), asset.ExposurePublic},
		{"ip_addresses []any (public)", mk("web-3", asset.AssetTypeHost, map[string]any{"ip_addresses": []any{"1.1.1.1"}}), asset.ExposurePublic},
		{"ip_addresses (private only)", mk("db-2", asset.AssetTypeHost, map[string]any{"ip_addresses": []any{"10.0.0.5", "192.168.1.4"}}), asset.ExposureUnknown},
		{"ip_address.address (public)", mk("web-4", asset.AssetTypeHost, map[string]any{"ip_address": map[string]any{"address": "9.9.9.9"}}), asset.ExposurePublic},
		{"host with no IP stays unknown", mk("worker-1", asset.AssetTypeHost, nil), asset.ExposureUnknown},
		{"ip_address (public) via name", mk("203.0.113.9", asset.AssetTypeIPAddress, nil), asset.ExposurePublic},
		{"ip_address (private) via name", mk("192.168.1.10", asset.AssetTypeIPAddress, nil), asset.ExposureUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := inferAssetExposure(c.a); got != c.want {
				t.Fatalf("inferAssetExposure = %q, want %q", got, c.want)
			}
		})
	}
}

// The address must land in ip_addresses (what IP correlation searches) for
// the host shapes sdk-go's scanners emit, or a renamed host is never matched.
func TestBuildPropertiesFromCTIS_KeepsAddressForCorrelation(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())

	t.Run("nessus: ip_address as a string", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{
			Type: ctis.AssetTypeHost, Value: "web-01.corp.example", Name: "web-01.corp.example",
			Properties: ctis.Properties{"ip_address": "10.0.0.9"},
		})
		assert.ElementsMatch(t, []string{"10.0.0.9"}, props["ip_addresses"])
		assert.Equal(t, "10.0.0.9", props["ip_address"], "the scanner's own key is left in place")
	})

	t.Run("vuls: hostname as name, address as value", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{
			Type: ctis.AssetTypeIPAddress, Value: "10.0.0.10", Name: "web-02",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: 4, Hostname: "web-02"}},
		})
		assert.ElementsMatch(t, []string{"10.0.0.10"}, props["ip_addresses"])
	})

	t.Run("host named by hostname, value is its address", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{
			Type: ctis.AssetTypeHost, Value: "10.0.0.11", Name: "web-03",
			Properties: ctis.Properties{"ip": "10.0.0.11"},
		})
		assert.ElementsMatch(t, []string{"10.0.0.11"}, props["ip_addresses"], "no duplicate entry")
	})

	t.Run("value equal to name adds nothing", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: "10.0.0.12", Name: "10.0.0.12"})
		assert.NotContains(t, props, "ip_addresses")
	})
}

// TestCreateAssetFromCTIS_HostExposure goes through the real ingest mapping:
// host normalisation moves properties.ip into ip_addresses and deletes ip,
// which is why exposure inference never fired for hosts before.
func TestCreateAssetFromCTIS_HostExposure(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	tenantID := shared.NewID()
	cases := []struct {
		name string
		in   ctis.Asset
		want asset.Exposure
	}{
		{"public IP in properties.ip", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-1.corp", Properties: ctis.Properties{"ip": "8.8.8.8"}}, asset.ExposurePublic},
		{"private IP in properties.ip", ctis.Asset{Type: ctis.AssetTypeHost, Value: "db-1.corp", Properties: ctis.Properties{"ip": "10.0.0.5"}}, asset.ExposureUnknown},
		{"public IP in properties.ip_addresses", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-2.corp", Properties: ctis.Properties{"ip_addresses": []any{"10.1.1.1", "1.1.1.1"}}}, asset.ExposurePublic},
		{"private IPs in properties.ip_addresses", ctis.Asset{Type: ctis.AssetTypeHost, Value: "db-2.corp", Properties: ctis.Properties{"ip_addresses": []any{"172.16.3.4"}}}, asset.ExposureUnknown},
		{"public IP as an ip_address string (nessus)", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-3.corp", Properties: ctis.Properties{"ip_address": "9.9.9.9"}}, asset.ExposurePublic},
		{"private IP as an ip_address string (nessus)", ctis.Asset{Type: ctis.AssetTypeHost, Value: "db-3.corp", Properties: ctis.Properties{"ip_address": "10.9.9.9"}}, asset.ExposureUnknown},
		{"host named by its public IP", ctis.Asset{Type: ctis.AssetTypeHost, Value: "8.8.4.4"}, asset.ExposurePublic},
		{"host named by its private IP", ctis.Asset{Type: ctis.AssetTypeHost, Value: "192.168.10.20"}, asset.ExposureUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			a, err := p.createAssetFromCTIS(tenantID, &in, nil)
			require.NoError(t, err)
			_, hasLegacy := a.Properties()["ip"]
			assert.False(t, hasLegacy, "host normalisation should have removed properties.ip")
			assert.Equal(t, c.want, a.Exposure())
		})
	}
}
