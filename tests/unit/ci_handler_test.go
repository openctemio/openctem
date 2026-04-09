package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scansvc "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Minimal mock implementations for CIHandler tests
// =============================================================================

// ciMockScanRepository implements scan.Repository for CI handler testing.
type ciMockScanRepository struct {
	scans map[string]*scan.Scan
}

func newCIMockScanRepository() *ciMockScanRepository {
	return &ciMockScanRepository{
		scans: make(map[string]*scan.Scan),
	}
}

func (m *ciMockScanRepository) Create(_ context.Context, s *scan.Scan) error {
	m.scans[s.ID.String()] = s
	return nil
}

func (m *ciMockScanRepository) GetByID(_ context.Context, id shared.ID) (*scan.Scan, error) {
	s, ok := m.scans[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *ciMockScanRepository) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scan.Scan, error) {
	s, ok := m.scans[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *ciMockScanRepository) GetByName(_ context.Context, tenantID shared.ID, name string) (*scan.Scan, error) {
	for _, s := range m.scans {
		if s.TenantID == tenantID && s.Name == name {
			return s, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *ciMockScanRepository) List(_ context.Context, _ scan.Filter, _ pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	return pagination.Result[*scan.Scan]{}, nil
}

func (m *ciMockScanRepository) Update(_ context.Context, s *scan.Scan) error {
	m.scans[s.ID.String()] = s
	return nil
}

func (m *ciMockScanRepository) Delete(_ context.Context, id shared.ID) error {
	delete(m.scans, id.String())
	return nil
}

func (m *ciMockScanRepository) ListDueForExecution(_ context.Context, _ time.Time) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *ciMockScanRepository) UpdateNextRunAt(_ context.Context, _ shared.ID, _ *time.Time) error {
	return nil
}

func (m *ciMockScanRepository) RecordRun(_ context.Context, _ shared.ID, _ shared.ID, _ string) error {
	return nil
}

func (m *ciMockScanRepository) GetStats(_ context.Context, _ shared.ID) (*scan.Stats, error) {
	return &scan.Stats{}, nil
}

func (m *ciMockScanRepository) Count(_ context.Context, _ scan.Filter) (int64, error) {
	return int64(len(m.scans)), nil
}

func (m *ciMockScanRepository) ListByAssetGroupID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *ciMockScanRepository) ListByPipelineID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *ciMockScanRepository) UpdateStatusByAssetGroupID(_ context.Context, _ shared.ID, _ scan.Status) error {
	return nil
}

func (m *ciMockScanRepository) TryLockScanForScheduler(_ context.Context, _ shared.ID) (bool, error) {
	return true, nil
}

func (m *ciMockScanRepository) UnlockScanForScheduler(_ context.Context, _ shared.ID) error {
	return nil
}

func (m *ciMockScanRepository) addScan(s *scan.Scan) {
	m.scans[s.ID.String()] = s
}

// ciMockAgentSelector implements scansvc.AgentSelector.
type ciMockAgentSelector struct{}

func (m *ciMockAgentSelector) CheckAgentAvailability(_ context.Context, _ shared.ID, _ string, _ bool) *scansvc.AgentAvailability {
	return &scansvc.AgentAvailability{Available: true}
}

func (m *ciMockAgentSelector) CanUsePlatformAgents(_ context.Context, _ shared.ID) (bool, string) {
	return true, ""
}

func (m *ciMockAgentSelector) SelectAgent(_ context.Context, _ scansvc.SelectAgentRequest) (*scansvc.SelectAgentResult, error) {
	return nil, nil
}

// ciMockSecurityValidator implements scansvc.SecurityValidator.
type ciMockSecurityValidator struct{}

func (m *ciMockSecurityValidator) ValidateIdentifier(_ string, _ int, _ string) *scansvc.ValidationResult {
	return &scansvc.ValidationResult{Valid: true}
}

func (m *ciMockSecurityValidator) ValidateIdentifiers(_ []string, _ int, _ string) *scansvc.ValidationResult {
	return &scansvc.ValidationResult{Valid: true}
}

func (m *ciMockSecurityValidator) ValidateScannerConfig(_ context.Context, _ shared.ID, _ map[string]any) *scansvc.ValidationResult {
	return &scansvc.ValidationResult{Valid: true}
}

func (m *ciMockSecurityValidator) ValidateCronExpression(_ string) error {
	return nil
}

// =============================================================================
// Test Setup Helpers
// =============================================================================

// newTestCIHandler creates a CIHandler with mocked dependencies.
func newTestCIHandler(repo *ciMockScanRepository) *handler.CIHandler {
	log := logger.NewDevelopment()
	svc := scansvc.NewService(
		repo,
		nil, // templateRepo
		nil, // assetGroupRepo
		nil, // runRepo
		nil, // stepRepo
		nil, // stepRunRepo
		nil, // commandRepo
		nil, // scannerTemplateRepo
		nil, // templateSourceRepo
		nil, // toolRepo
		nil, // templateSyncer
		&ciMockAgentSelector{},
		&ciMockSecurityValidator{},
		log,
	)
	return handler.NewCIHandler(svc, log)
}

// createTestScan creates a test scan in the repo and returns it.
func createTestScan(t *testing.T, repo *ciMockScanRepository, tenantID shared.ID, name, scannerName string) *scan.Scan {
	t.Helper()
	sc, err := scan.NewScan(tenantID, name, shared.NewID(), scan.ScanTypeSingle)
	require.NoError(t, err)
	sc.ScannerName = scannerName
	repo.addScan(sc)
	return sc
}

// buildCIRequest creates an HTTP request with chi URL params and tenant context.
func buildCIRequest(scanID, tenantID, platform string) *http.Request {
	url := "/api/v1/scans/" + scanID + "/ci-snippet"
	if platform != "" {
		url += "?platform=" + platform
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Set chi URL params
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", scanID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	// Set tenant ID in context
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
	req = req.WithContext(ctx)

	return req
}

// =============================================================================
// GenerateSnippet Tests
// =============================================================================

func TestGenerateSnippet_GitHubPlatform(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "GitHub Test Scan", "nuclei")

	req := buildCIRequest(sc.ID.String(), tenantID.String(), "github")
	rr := httptest.NewRecorder()

	h.GenerateSnippet(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	body := rr.Body.String()
	// Verify YAML structure for GitHub Actions
	assert.Contains(t, body, "name: OpenCTEM Security Scan")
	assert.Contains(t, body, "on:")
	assert.Contains(t, body, "push:")
	assert.Contains(t, body, "jobs:")
	assert.Contains(t, body, "security-scan:")
	assert.Contains(t, body, "runs-on: ubuntu-latest")
	assert.Contains(t, body, "steps:")
	assert.Contains(t, body, "actions/checkout@v4")
	assert.Contains(t, body, sc.ID.String(), "should contain the scan ID")
	assert.Contains(t, body, "OPENCTEM_API_KEY")
	assert.Contains(t, body, "OPENCTEM_API_URL")

	// Content-Type should be YAML for GitHub
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/yaml")
}

func TestGenerateSnippet_GitLabPlatform(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "GitLab Test Scan", "nuclei")

	req := buildCIRequest(sc.ID.String(), tenantID.String(), "gitlab")
	rr := httptest.NewRecorder()

	h.GenerateSnippet(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	body := rr.Body.String()
	// Verify GitLab CI YAML structure
	assert.Contains(t, body, "stages:")
	assert.Contains(t, body, "- security")
	assert.Contains(t, body, "openctem-scan:")
	assert.Contains(t, body, "stage: security")
	assert.Contains(t, body, "image: curlimages/curl")
	assert.Contains(t, body, "script:")
	assert.Contains(t, body, sc.ID.String(), "should contain the scan ID")
	assert.Contains(t, body, "OPENCTEM_API_KEY")
	assert.Contains(t, body, "rules:")
	assert.Contains(t, body, "allow_failure: true")

	// Content-Type should be YAML for GitLab
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/yaml")
}

func TestGenerateSnippet_JenkinsPlatform(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "Jenkins Test Scan", "nuclei")

	req := buildCIRequest(sc.ID.String(), tenantID.String(), "jenkins")
	rr := httptest.NewRecorder()

	h.GenerateSnippet(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	body := rr.Body.String()
	// Verify Jenkinsfile pipeline structure
	assert.Contains(t, body, "pipeline {")
	assert.Contains(t, body, "agent any")
	assert.Contains(t, body, "environment {")
	assert.Contains(t, body, "stages {")
	assert.Contains(t, body, "stage('Security Scan')")
	assert.Contains(t, body, "steps {")
	assert.Contains(t, body, "httpRequest(")
	assert.Contains(t, body, sc.ID.String(), "should contain the scan ID")
	assert.Contains(t, body, "openctem-api-key")
	assert.Contains(t, body, "post {")

	// Content-Type should be text/plain for Jenkins (not YAML)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/plain")
}

func TestGenerateSnippet_InvalidPlatform(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "Invalid Platform Scan", "nuclei")

	invalidPlatforms := []string{"azure", "circleci", "bitbucket", "travis", "drone", "invalid"}

	for _, platform := range invalidPlatforms {
		t.Run(platform, func(t *testing.T) {
			req := buildCIRequest(sc.ID.String(), tenantID.String(), platform)
			rr := httptest.NewRecorder()

			h.GenerateSnippet(rr, req)

			assert.Equal(t, http.StatusBadRequest, rr.Code)

			// Verify error response is JSON
			var errorResp map[string]any
			err := json.NewDecoder(rr.Body).Decode(&errorResp)
			require.NoError(t, err)
			assert.Contains(t, errorResp["message"], "unsupported platform")
		})
	}
}

func TestGenerateSnippet_MissingPlatformParam(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "Missing Platform Scan", "nuclei")

	// Request without platform query param
	req := buildCIRequest(sc.ID.String(), tenantID.String(), "")
	rr := httptest.NewRecorder()

	h.GenerateSnippet(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errorResp map[string]any
	err := json.NewDecoder(rr.Body).Decode(&errorResp)
	require.NoError(t, err)
	assert.Contains(t, errorResp["message"], "platform query parameter is required")
}

func TestGenerateSnippet_ScanNotFound(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	nonExistentID := shared.NewID()

	req := buildCIRequest(nonExistentID.String(), tenantID.String(), "github")
	rr := httptest.NewRecorder()

	h.GenerateSnippet(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)

	var errorResp map[string]any
	err := json.NewDecoder(rr.Body).Decode(&errorResp)
	require.NoError(t, err)
	assert.Contains(t, errorResp["message"], "not found")
}

func TestGenerateSnippet_PlatformCaseInsensitive(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "Case Insensitive Test", "nuclei")

	// Test uppercase
	testCases := []struct {
		name     string
		platform string
	}{
		{"uppercase GITHUB", "GITHUB"},
		{"mixed case GitHub", "GitHub"},
		{"uppercase GITLAB", "GITLAB"},
		{"mixed case GitLab", "GitLab"},
		{"uppercase JENKINS", "JENKINS"},
		{"mixed case Jenkins", "Jenkins"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := buildCIRequest(sc.ID.String(), tenantID.String(), tc.platform)
			rr := httptest.NewRecorder()

			h.GenerateSnippet(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code,
				"platform %s should be accepted (case insensitive)", tc.platform)
			assert.NotEmpty(t, rr.Body.String())
		})
	}
}

func TestGenerateSnippet_ContentDispositionHeader(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "Header Test Scan", "nuclei")

	platforms := []string{"github", "gitlab", "jenkins"}

	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			req := buildCIRequest(sc.ID.String(), tenantID.String(), platform)
			rr := httptest.NewRecorder()

			h.GenerateSnippet(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)

			// Verify Content-Disposition header
			disposition := rr.Header().Get("Content-Disposition")
			assert.Contains(t, disposition, "inline")
			assert.Contains(t, disposition, "openctem-"+platform)
			assert.Contains(t, disposition, sc.ID.String())
		})
	}
}

func TestGenerateSnippet_SnippetContainsScanName(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	scanName := "Production DAST Scan"
	sc := createTestScan(t, repo, tenantID, scanName, "nuclei")

	platforms := []string{"github", "gitlab", "jenkins"}

	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			req := buildCIRequest(sc.ID.String(), tenantID.String(), platform)
			rr := httptest.NewRecorder()

			h.GenerateSnippet(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Contains(t, rr.Body.String(), scanName,
				"snippet should contain the scan name")
		})
	}
}

func TestGenerateSnippet_WrongTenant(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	sc := createTestScan(t, repo, tenantA, "Tenant A Scan", "nuclei")

	// Try to access with tenant B
	req := buildCIRequest(sc.ID.String(), tenantB.String(), "github")
	rr := httptest.NewRecorder()

	h.GenerateSnippet(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestGenerateSnippet_AllPlatformsContainTriggerEndpoint(t *testing.T) {
	repo := newCIMockScanRepository()
	h := newTestCIHandler(repo)

	tenantID := shared.NewID()
	sc := createTestScan(t, repo, tenantID, "Trigger Endpoint Scan", "nuclei")

	testCases := []struct {
		platform string
		// GitHub embeds scan ID directly; GitLab/Jenkins use ${SCAN_ID} variable
		triggerPattern string
	}{
		{"github", "/api/v1/scans/" + sc.ID.String() + "/trigger"},
		{"gitlab", "/api/v1/scans/${SCAN_ID}/trigger"},
		{"jenkins", "/api/v1/scans/${SCAN_ID}/trigger"},
	}

	for _, tc := range testCases {
		t.Run(tc.platform, func(t *testing.T) {
			req := buildCIRequest(sc.ID.String(), tenantID.String(), tc.platform)
			rr := httptest.NewRecorder()

			h.GenerateSnippet(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			body := rr.Body.String()
			assert.Contains(t, body, tc.triggerPattern,
				"snippet should contain the scan trigger endpoint")
			// All platforms should reference the scan ID somewhere
			assert.Contains(t, body, sc.ID.String(),
				"snippet should contain the scan ID")
		})
	}
}
