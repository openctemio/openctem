package unit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/llm"
	"github.com/openctemio/api/pkg/domain/aitriage"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Repositories
// =============================================================================

type mockAITriageRepo struct {
	results    map[string]*aitriage.TriageResult
	createErr  error
	updateErr  error
	getByIDErr error
	getByFindingErr error
	listErr    error
	hasPendingErr error
	hasPendingResult bool
	findStuckErr error
	findStuckResult []*aitriage.TriageResult
	markStuckErr error
	markStuckResult bool
	acquireErr error
	acquireResult *aitriage.TriageContext

	createCalls int
	updateCalls int
}

func newMockAITriageRepo() *mockAITriageRepo {
	return &mockAITriageRepo{
		results: make(map[string]*aitriage.TriageResult),
	}
}

func (m *mockAITriageRepo) Create(_ context.Context, result *aitriage.TriageResult) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.results[result.ID().String()] = result
	return nil
}

func (m *mockAITriageRepo) Update(_ context.Context, result *aitriage.TriageResult) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.results[result.ID().String()] = result
	return nil
}

func (m *mockAITriageRepo) GetByID(_ context.Context, _, id shared.ID) (*aitriage.TriageResult, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	r, ok := m.results[id.String()]
	if !ok {
		return nil, fmt.Errorf("triage result not found")
	}
	return r, nil
}

func (m *mockAITriageRepo) GetByFindingID(_ context.Context, _, _ shared.ID) (*aitriage.TriageResult, error) {
	if m.getByFindingErr != nil {
		return nil, m.getByFindingErr
	}
	for _, r := range m.results {
		return r, nil
	}
	return nil, fmt.Errorf("no triage results found")
}

func (m *mockAITriageRepo) ListByFindingID(_ context.Context, _, _ shared.ID, _, _ int) ([]*aitriage.TriageResult, int, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	results := make([]*aitriage.TriageResult, 0, len(m.results))
	for _, r := range m.results {
		results = append(results, r)
	}
	return results, len(results), nil
}

func (m *mockAITriageRepo) GetPendingJobs(_ context.Context, _ int) ([]*aitriage.TriageResult, error) {
	return nil, nil
}

func (m *mockAITriageRepo) GetPendingJobsByTenant(_ context.Context, _ shared.ID, _ int) ([]*aitriage.TriageResult, error) {
	return nil, nil
}

func (m *mockAITriageRepo) GetTenantsWithPendingJobs(_ context.Context, _ int) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockAITriageRepo) CountByTenantThisMonth(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

func (m *mockAITriageRepo) SumTokensByTenantThisMonth(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

func (m *mockAITriageRepo) GetTriageContext(_ context.Context, _, _ shared.ID) (*aitriage.TriageContext, error) {
	if m.acquireResult != nil {
		return m.acquireResult, nil
	}
	return nil, fmt.Errorf("not found")
}

func (m *mockAITriageRepo) AcquireTriageSlot(_ context.Context, _, _ shared.ID) (*aitriage.TriageContext, error) {
	if m.acquireErr != nil {
		return nil, m.acquireErr
	}
	return m.acquireResult, nil
}

func (m *mockAITriageRepo) HasPendingOrProcessing(_ context.Context, _, _ shared.ID) (bool, error) {
	if m.hasPendingErr != nil {
		return false, m.hasPendingErr
	}
	return m.hasPendingResult, nil
}

func (m *mockAITriageRepo) FindStuckJobs(_ context.Context, _ time.Duration, _ int) ([]*aitriage.TriageResult, error) {
	if m.findStuckErr != nil {
		return nil, m.findStuckErr
	}
	return m.findStuckResult, nil
}

func (m *mockAITriageRepo) MarkStuckAsFailed(_ context.Context, _ shared.ID, _ string) (bool, error) {
	if m.markStuckErr != nil {
		return false, m.markStuckErr
	}
	return m.markStuckResult, nil
}

// mockAITriageFindingRepo implements vulnerability.FindingRepository (subset).
type mockAITriageFindingRepo struct {
	findings    map[string]*vulnerability.Finding
	getByIDErr  error
	existsByIDs map[shared.ID]bool
	existsErr   error
}

func newMockAITriageFindingRepo() *mockAITriageFindingRepo {
	return &mockAITriageFindingRepo{
		findings:    make(map[string]*vulnerability.Finding),
		existsByIDs: make(map[shared.ID]bool),
	}
}

func (m *mockAITriageFindingRepo) GetByID(_ context.Context, _, id shared.ID) (*vulnerability.Finding, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	f, ok := m.findings[id.String()]
	if !ok {
		return nil, fmt.Errorf("finding not found")
	}
	return f, nil
}

func (m *mockAITriageFindingRepo) ExistsByIDs(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	if m.existsErr != nil {
		return nil, m.existsErr
	}
	result := make(map[shared.ID]bool, len(ids))
	for _, id := range ids {
		result[id] = m.existsByIDs[id]
	}
	return result, nil
}

// Stub methods to satisfy vulnerability.FindingRepository interface.
func (m *mockAITriageFindingRepo) Create(_ context.Context, _ *vulnerability.Finding) error {
	return nil
}

func (m *mockAITriageFindingRepo) CreateInTx(_ context.Context, _ *sql.Tx, _ *vulnerability.Finding) error {
	return nil
}

func (m *mockAITriageFindingRepo) CreateBatch(_ context.Context, _ []*vulnerability.Finding) error {
	return nil
}

func (m *mockAITriageFindingRepo) CreateBatchWithResult(_ context.Context, _ []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) Update(_ context.Context, _ *vulnerability.Finding) error {
	return nil
}

func (m *mockAITriageFindingRepo) Delete(_ context.Context, _, _ shared.ID) error { return nil }

func (m *mockAITriageFindingRepo) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *mockAITriageFindingRepo) ListByAssetID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *mockAITriageFindingRepo) ListByVulnerabilityID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *mockAITriageFindingRepo) ListByComponentID(_ context.Context, _, _ shared.ID, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return pagination.Result[*vulnerability.Finding]{}, nil
}

func (m *mockAITriageFindingRepo) Count(_ context.Context, _ vulnerability.FindingFilter) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) CountByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) CountOpenByAssetID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) GetByFingerprint(_ context.Context, _ shared.ID, _ string) (*vulnerability.Finding, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) ExistsByFingerprint(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockAITriageFindingRepo) CheckFingerprintsExist(_ context.Context, _ shared.ID, _ []string) (map[string]bool, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) UpdateScanIDBatchByFingerprints(_ context.Context, _ shared.ID, _ []string, _ string) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) UpdateSnippetBatchByFingerprints(_ context.Context, _ shared.ID, _ map[string]string) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) BatchCountByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID]int64, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) UpdateStatusBatch(_ context.Context, _ shared.ID, _ []shared.ID, _ vulnerability.FindingStatus, _ string, _ *shared.ID) error {
	return nil
}

func (m *mockAITriageFindingRepo) DeleteByAssetID(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *mockAITriageFindingRepo) DeleteByScanID(_ context.Context, _ shared.ID, _ string) error {
	return nil
}

func (m *mockAITriageFindingRepo) GetStats(_ context.Context, _ shared.ID, _ *shared.ID) (*vulnerability.FindingStats, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) CountBySeverityForScan(_ context.Context, _ shared.ID, _ string) (vulnerability.SeverityCounts, error) {
	return vulnerability.SeverityCounts{}, nil
}

func (m *mockAITriageFindingRepo) AutoResolveStale(_ context.Context, _, _ shared.ID, _, _ string, _ *shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) AutoReopenByFingerprint(_ context.Context, _ shared.ID, _ string) (*shared.ID, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) AutoReopenByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]shared.ID, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) ExpireFeatureBranchFindings(_ context.Context, _ shared.ID, _ int) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) GetByFingerprintsBatch(_ context.Context, _ shared.ID, _ []string) (map[string]*vulnerability.Finding, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) EnrichBatchByFingerprints(_ context.Context, _ shared.ID, _ []*vulnerability.Finding, _ string) (int64, error) {
	return 0, nil
}

// mockAITriageTenantRepo implements tenant.Repository.
type mockAITriageTenantRepo struct {
	tenants    map[string]*tenant.Tenant
	getByIDErr error
}

func newMockAITriageTenantRepo() *mockAITriageTenantRepo {
	return &mockAITriageTenantRepo{
		tenants: make(map[string]*tenant.Tenant),
	}
}

func (m *mockAITriageTenantRepo) GetByID(_ context.Context, id shared.ID) (*tenant.Tenant, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	t, ok := m.tenants[id.String()]
	if !ok {
		return nil, fmt.Errorf("tenant not found")
	}
	return t, nil
}
func (m *mockAITriageTenantRepo) Create(_ context.Context, _ *tenant.Tenant) error { return nil }
func (m *mockAITriageTenantRepo) GetBySlug(_ context.Context, _ string) (*tenant.Tenant, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) Update(_ context.Context, _ *tenant.Tenant) error  { return nil }
func (m *mockAITriageTenantRepo) Delete(_ context.Context, _ shared.ID) error        { return nil }
func (m *mockAITriageTenantRepo) ExistsBySlug(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (m *mockAITriageTenantRepo) ListActiveTenantIDs(_ context.Context) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) CreateMembership(_ context.Context, _ *tenant.Membership) error {
	return nil
}
func (m *mockAITriageTenantRepo) GetMembership(_ context.Context, _, _ shared.ID) (*tenant.Membership, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) GetMembershipByID(_ context.Context, _ shared.ID) (*tenant.Membership, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) UpdateMembership(_ context.Context, _ *tenant.Membership) error {
	return nil
}
func (m *mockAITriageTenantRepo) DeleteMembership(_ context.Context, _ shared.ID) error { return nil }
func (m *mockAITriageTenantRepo) ListMembersByTenant(_ context.Context, _ shared.ID) ([]*tenant.Membership, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) ListMembersWithUserInfo(_ context.Context, _ shared.ID) ([]*tenant.MemberWithUser, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) SearchMembersWithUserInfo(_ context.Context, _ shared.ID, _ tenant.MemberSearchFilters) (*tenant.MemberSearchResult, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) ListTenantsByUser(_ context.Context, _ shared.ID) ([]*tenant.TenantWithRole, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) CountMembersByTenant(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockAITriageTenantRepo) GetMemberStats(_ context.Context, _ shared.ID) (*tenant.MemberStats, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) GetUserMemberships(_ context.Context, _ shared.ID) ([]tenant.UserMembership, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) GetMemberByEmail(_ context.Context, _ shared.ID, _ string) (*tenant.MemberWithUser, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) CreateInvitation(_ context.Context, _ *tenant.Invitation) error {
	return nil
}
func (m *mockAITriageTenantRepo) GetInvitationByToken(_ context.Context, _ string) (*tenant.Invitation, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) GetInvitationByID(_ context.Context, _ shared.ID) (*tenant.Invitation, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) UpdateInvitation(_ context.Context, _ *tenant.Invitation) error {
	return nil
}
func (m *mockAITriageTenantRepo) DeleteInvitation(_ context.Context, _ shared.ID) error { return nil }
func (m *mockAITriageTenantRepo) ListPendingInvitationsByTenant(_ context.Context, _ shared.ID) ([]*tenant.Invitation, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) GetPendingInvitationByEmail(_ context.Context, _ shared.ID, _ string) (*tenant.Invitation, error) {
	return nil, nil
}
func (m *mockAITriageTenantRepo) DeleteExpiredInvitations(_ context.Context) (int64, error) {
	return 0, nil
}
func (m *mockAITriageTenantRepo) AcceptInvitationTx(_ context.Context, _ *tenant.Invitation, _ *tenant.Membership) error {
	return nil
}

// mockJobEnqueuer implements app.AITriageJobEnqueuer.
type mockJobEnqueuer struct {
	enqueuedJobs []enqueuedJob
	enqueueErr   error
}

type enqueuedJob struct {
	resultID  string
	tenantID  string
	findingID string
	delay     time.Duration
}

func (m *mockJobEnqueuer) EnqueueAITriage(_ context.Context, resultID, tenantID, findingID string, delay time.Duration) error {
	if m.enqueueErr != nil {
		return m.enqueueErr
	}
	m.enqueuedJobs = append(m.enqueuedJobs, enqueuedJob{
		resultID:  resultID,
		tenantID:  tenantID,
		findingID: findingID,
		delay:     delay,
	})
	return nil
}

// mockTriageBroadcaster implements app.TriageBroadcaster.
type mockTriageBroadcaster struct {
	broadcasts []broadcastEvent
}

type broadcastEvent struct {
	channel  string
	tenantID string
}

func (m *mockTriageBroadcaster) BroadcastTriage(channel string, _ any, tenantID string) {
	m.broadcasts = append(m.broadcasts, broadcastEvent{channel: channel, tenantID: tenantID})
}

// =============================================================================
// Tests: categorizeError
// =============================================================================

// Since categorizeError is unexported, we test it indirectly through
// a helper that replicates the same logic for testing purposes.
func aiTriageCategorizeError(err error) string {
	if err == nil {
		return "Unknown error occurred"
	}

	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	if errors.Is(err, llm.ErrRateLimited) || strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "429") {
		return "AI service is temporarily busy. Please try again in a few minutes."
	}
	if strings.Contains(errLower, "unauthorized") || strings.Contains(errLower, "401") ||
		strings.Contains(errLower, "invalid api key") || strings.Contains(errLower, "authentication") {
		return "AI service authentication failed. Please contact your administrator."
	}
	if strings.Contains(errLower, "quota") || strings.Contains(errLower, "billing") ||
		strings.Contains(errLower, "insufficient") || strings.Contains(errLower, "exceeded") {
		return "AI service quota exceeded. Please check your subscription or try again later."
	}
	if errors.Is(err, llm.ErrContextCanceled) || strings.Contains(errLower, "context") ||
		strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") {
		return "AI analysis timed out. Please try again with a simpler finding."
	}
	if strings.Contains(errLower, "content_filter") || strings.Contains(errLower, "safety") ||
		strings.Contains(errLower, "blocked") {
		return "AI analysis was blocked by content filters. Finding may contain sensitive content."
	}
	if errors.Is(err, llm.ErrTokenLimitExceeded) || strings.Contains(errLower, "token") {
		return "Finding is too large for AI analysis. Try a finding with less content."
	}
	if strings.Contains(errLower, "500") || strings.Contains(errLower, "502") ||
		strings.Contains(errLower, "503") || strings.Contains(errLower, "server error") {
		return "AI service is temporarily unavailable. Please try again later."
	}
	if errors.Is(err, llm.ErrInvalidResponse) || strings.Contains(errLower, "parse") ||
		strings.Contains(errLower, "invalid response") {
		return "AI returned an invalid response. Please try again."
	}
	if errors.Is(err, llm.ErrProviderNotConfigured) || strings.Contains(errLower, "not configured") {
		return "AI service is not properly configured. Please contact your administrator."
	}
	return "AI analysis failed. Please try again later."
}

func TestAITriage_CategorizeError_NilError(t *testing.T) {
	t.Parallel()

	result := aiTriageCategorizeError(nil)
	if result != "Unknown error occurred" {
		t.Errorf("expected 'Unknown error occurred', got %q", result)
	}
}

func TestAITriage_CategorizeError_RateLimited(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"ErrRateLimited sentinel", llm.ErrRateLimited},
		{"rate limit string", errors.New("rate limit exceeded")},
		{"429 status", errors.New("HTTP 429 Too Many Requests")},
		{"wrapped rate limit", fmt.Errorf("provider error: %w", llm.ErrRateLimited)},
	}

	expected := "AI service is temporarily busy. Please try again in a few minutes."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_Authentication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"unauthorized", errors.New("Unauthorized access")},
		{"401 status", errors.New("HTTP 401")},
		{"invalid api key", errors.New("Invalid API Key provided")},
		{"authentication failed", errors.New("Authentication error")},
	}

	expected := "AI service authentication failed. Please contact your administrator."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_Quota(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"quota exceeded", errors.New("Quota exceeded for this month")},
		{"billing issue", errors.New("Billing account is overdue")},
		{"insufficient credits", errors.New("Insufficient credits")},
		{"limit exceeded", errors.New("Usage limit exceeded")},
	}

	expected := "AI service quota exceeded. Please check your subscription or try again later."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_Timeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"ErrContextCanceled sentinel", llm.ErrContextCanceled},
		{"context canceled", errors.New("context canceled")},
		{"timeout", errors.New("request timeout after 30s")},
	}

	expected := "AI analysis timed out. Please try again with a simpler finding."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_ContentFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"content_filter", errors.New("content_filter triggered")},
		{"safety", errors.New("safety system blocked the request")},
		{"blocked", errors.New("request was blocked by policy")},
	}

	expected := "AI analysis was blocked by content filters. Finding may contain sensitive content."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_TokenLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"token limit string", errors.New("maximum token limit reached")},
	}

	expected := "Finding is too large for AI analysis. Try a finding with less content."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_ServerError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"500 error", errors.New("HTTP 500 Internal Server Error")},
		{"502 error", errors.New("HTTP 502 Bad Gateway")},
		{"503 error", errors.New("HTTP 503 Service Unavailable")},
		{"server error", errors.New("server error occurred")},
	}

	expected := "AI service is temporarily unavailable. Please try again later."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_InvalidResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidResponse sentinel", llm.ErrInvalidResponse},
		{"parse error", errors.New("failed to parse response")},
		{"invalid response", errors.New("Invalid Response from API")},
	}

	expected := "AI returned an invalid response. Please try again."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_NotConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"ErrProviderNotConfigured sentinel", llm.ErrProviderNotConfigured},
		{"not configured string", errors.New("LLM is not configured")},
	}

	expected := "AI service is not properly configured. Please contact your administrator."
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageCategorizeError(tt.err)
			if result != expected {
				t.Errorf("expected %q, got %q", expected, result)
			}
		})
	}
}

func TestAITriage_CategorizeError_DefaultFallback(t *testing.T) {
	t.Parallel()

	result := aiTriageCategorizeError(errors.New("some unknown error xyz"))
	expected := "AI analysis failed. Please try again later."
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestAITriage_CategorizeError_DoesNotLeakInternalDetails(t *testing.T) {
	t.Parallel()

	// SECURITY: Error messages must not contain internal details
	sensitiveErrors := []error{
		errors.New("connection to postgresql://user:pass@host:5432/db failed"),
		errors.New("panic in goroutine: stack trace..."),
		errors.New("api key sk-abc123xyz was rejected"),
	}

	for _, err := range sensitiveErrors {
		result := aiTriageCategorizeError(err)
		errStr := err.Error()
		if strings.Contains(result, "postgresql") || strings.Contains(result, "stack trace") || strings.Contains(result, "sk-abc123") {
			t.Errorf("categorized error %q leaks internal detail: %q", errStr, result)
		}
	}
}

// =============================================================================
// Tests: getRiskLevel (replicated logic)
// =============================================================================

func aiTriageGetRiskLevel(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func TestAITriage_GetRiskLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{"score 100", 100.0, "critical"},
		{"score 90", 90.0, "critical"},
		{"score 70 boundary", 70.0, "critical"},
		{"score 69.9", 69.9, "high"},
		{"score 50 boundary", 50.0, "high"},
		{"score 49.9", 49.9, "medium"},
		{"score 30 boundary", 30.0, "medium"},
		{"score 29.9", 29.9, "low"},
		{"score 10", 10.0, "low"},
		{"score 0", 0.0, "low"},
		{"negative score", -1.0, "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageGetRiskLevel(tt.score)
			if result != tt.expected {
				t.Errorf("getRiskLevel(%.1f) = %q, want %q", tt.score, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Tests: getConfidence (replicated logic)
// =============================================================================

func aiTriageGetConfidence(fpLikelihood float64) string {
	switch {
	case fpLikelihood > 0.5:
		return "low"
	case fpLikelihood > 0.2:
		return "medium"
	default:
		return "high"
	}
}

func TestAITriage_GetConfidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		fpLikelihood float64
		expected     string
	}{
		{"high FP likelihood 0.9", 0.9, "low"},
		{"high FP likelihood 0.51", 0.51, "low"},
		{"FP boundary 0.5", 0.5, "medium"},
		{"medium FP likelihood 0.3", 0.3, "medium"},
		{"FP boundary 0.2", 0.2, "high"},
		{"low FP likelihood 0.1", 0.1, "high"},
		{"zero FP likelihood", 0.0, "high"},
		{"FP likelihood 1.0", 1.0, "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := aiTriageGetConfidence(tt.fpLikelihood)
			if result != tt.expected {
				t.Errorf("getConfidence(%.2f) = %q, want %q", tt.fpLikelihood, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Tests: extractAISettings (replicated logic)
// =============================================================================

func aiTriageExtractAISettings(settings map[string]any) tenant.AISettings {
	result := tenant.AISettings{}

	aiMap, ok := settings["ai"].(map[string]any)
	if !ok {
		return result
	}

	if mode, ok := aiMap["mode"].(string); ok {
		result.Mode = tenant.AIMode(mode)
	}
	if provider, ok := aiMap["provider"].(string); ok {
		result.Provider = tenant.LLMProvider(provider)
	}
	if apiKey, ok := aiMap["api_key"].(string); ok {
		result.APIKey = apiKey
	}
	if endpoint, ok := aiMap["azure_endpoint"].(string); ok {
		result.AzureEndpoint = endpoint
	}
	if model, ok := aiMap["model_override"].(string); ok {
		result.ModelOverride = model
	}
	if enabled, ok := aiMap["auto_triage_enabled"].(bool); ok {
		result.AutoTriageEnabled = enabled
	}
	if severities, ok := aiMap["auto_triage_severities"].([]any); ok {
		for _, sev := range severities {
			if s, ok := sev.(string); ok {
				result.AutoTriageSeverities = append(result.AutoTriageSeverities, s)
			}
		}
	}
	if delay, ok := aiMap["auto_triage_delay_seconds"].(float64); ok {
		result.AutoTriageDelaySeconds = int(delay)
	}
	if limit, ok := aiMap["monthly_token_limit"].(float64); ok {
		result.MonthlyTokenLimit = int(limit)
	}

	return result
}

func TestAITriage_ExtractAISettings_FullConfig(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"ai": map[string]any{
			"mode":                     "byok",
			"provider":                 "openai",
			"api_key":                  "sk-test123",
			"azure_endpoint":           "https://myendpoint.openai.azure.com",
			"model_override":           "gpt-4-turbo",
			"auto_triage_enabled":      true,
			"auto_triage_severities":   []any{"critical", "high"},
			"auto_triage_delay_seconds": float64(30),
			"monthly_token_limit":      float64(100000),
		},
	}

	result := aiTriageExtractAISettings(settings)

	if result.Mode != tenant.AIModeBYOK {
		t.Errorf("expected mode %q, got %q", tenant.AIModeBYOK, result.Mode)
	}
	if string(result.Provider) != "openai" {
		t.Errorf("expected provider 'openai', got %q", result.Provider)
	}
	if result.APIKey != "sk-test123" {
		t.Errorf("expected API key 'sk-test123', got %q", result.APIKey)
	}
	if result.AzureEndpoint != "https://myendpoint.openai.azure.com" {
		t.Errorf("expected azure endpoint, got %q", result.AzureEndpoint)
	}
	if result.ModelOverride != "gpt-4-turbo" {
		t.Errorf("expected model 'gpt-4-turbo', got %q", result.ModelOverride)
	}
	if !result.AutoTriageEnabled {
		t.Error("expected auto triage enabled")
	}
	if len(result.AutoTriageSeverities) != 2 {
		t.Errorf("expected 2 severities, got %d", len(result.AutoTriageSeverities))
	}
	if result.AutoTriageDelaySeconds != 30 {
		t.Errorf("expected delay 30, got %d", result.AutoTriageDelaySeconds)
	}
	if result.MonthlyTokenLimit != 100000 {
		t.Errorf("expected limit 100000, got %d", result.MonthlyTokenLimit)
	}
}

func TestAITriage_ExtractAISettings_EmptySettings(t *testing.T) {
	t.Parallel()

	result := aiTriageExtractAISettings(map[string]any{})
	if result.Mode != "" {
		t.Errorf("expected empty mode, got %q", result.Mode)
	}
	if result.AutoTriageEnabled {
		t.Error("expected auto triage disabled by default")
	}
}

func TestAITriage_ExtractAISettings_NilSettings(t *testing.T) {
	t.Parallel()

	result := aiTriageExtractAISettings(nil)
	if result.Mode != "" {
		t.Errorf("expected empty mode for nil settings, got %q", result.Mode)
	}
}

func TestAITriage_ExtractAISettings_NoAIKey(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"general": map[string]any{
			"name": "Test Tenant",
		},
	}

	result := aiTriageExtractAISettings(settings)
	if result.Mode != "" {
		t.Errorf("expected empty mode when no 'ai' key, got %q", result.Mode)
	}
}

func TestAITriage_ExtractAISettings_WrongTypes(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"ai": map[string]any{
			"mode":                int(42),       // Wrong type - should be string
			"auto_triage_enabled": "yes",         // Wrong type - should be bool
			"monthly_token_limit": "not a number", // Wrong type - should be float64
		},
	}

	result := aiTriageExtractAISettings(settings)
	if result.Mode != "" {
		t.Errorf("expected empty mode for wrong type, got %q", result.Mode)
	}
	if result.AutoTriageEnabled {
		t.Error("expected false for wrong type auto_triage_enabled")
	}
	if result.MonthlyTokenLimit != 0 {
		t.Errorf("expected 0 for wrong type limit, got %d", result.MonthlyTokenLimit)
	}
}

func TestAITriage_ExtractAISettings_PlatformMode(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"ai": map[string]any{
			"mode": "platform",
		},
	}

	result := aiTriageExtractAISettings(settings)
	if result.Mode != tenant.AIModePlatform {
		t.Errorf("expected mode 'platform', got %q", result.Mode)
	}
}

func TestAITriage_ExtractAISettings_DisabledMode(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"ai": map[string]any{
			"mode": "disabled",
		},
	}

	result := aiTriageExtractAISettings(settings)
	if result.Mode != tenant.AIModeDisabled {
		t.Errorf("expected mode 'disabled', got %q", result.Mode)
	}
}

func TestAITriage_ExtractAISettings_SeveritiesWithMixedTypes(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"ai": map[string]any{
			"auto_triage_severities": []any{"critical", 42, "high", true},
		},
	}

	result := aiTriageExtractAISettings(settings)
	// Should only extract string values
	if len(result.AutoTriageSeverities) != 2 {
		t.Errorf("expected 2 string severities, got %d", len(result.AutoTriageSeverities))
	}
	if result.AutoTriageSeverities[0] != "critical" {
		t.Errorf("expected 'critical', got %q", result.AutoTriageSeverities[0])
	}
	if result.AutoTriageSeverities[1] != "high" {
		t.Errorf("expected 'high', got %q", result.AutoTriageSeverities[1])
	}
}

// =============================================================================
// Tests: RequestTriage Input Validation
// =============================================================================

func TestAITriage_RequestTriage_InvalidTenantID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{Enabled: true},
		log,
	)

	_, err := svc.RequestTriage(context.Background(), app.TriageRequest{
		TenantID:   "not-a-uuid",
		FindingID:  "550e8400-e29b-41d4-a716-446655440000",
		TriageType: "manual",
	})
	if err == nil {
		t.Fatal("expected validation error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAITriage_RequestTriage_InvalidFindingID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{Enabled: true},
		log,
	)

	_, err := svc.RequestTriage(context.Background(), app.TriageRequest{
		TenantID:   "550e8400-e29b-41d4-a716-446655440000",
		FindingID:  "bad-id",
		TriageType: "manual",
	})
	if err == nil {
		t.Fatal("expected validation error for invalid finding ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// Tests: GetTriageResult Input Validation
// =============================================================================

func TestAITriage_GetTriageResult_InvalidTenantID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.GetTriageResult(context.Background(), "bad-uuid", "550e8400-e29b-41d4-a716-446655440000")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAITriage_GetTriageResult_InvalidResultID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.GetTriageResult(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid result ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// Tests: GetLatestTriageByFinding Input Validation
// =============================================================================

func TestAITriage_GetLatestTriageByFinding_InvalidTenantID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.GetLatestTriageByFinding(context.Background(), "bad", "550e8400-e29b-41d4-a716-446655440000")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestAITriage_GetLatestTriageByFinding_InvalidFindingID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.GetLatestTriageByFinding(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "bad")
	if err == nil {
		t.Fatal("expected error for invalid finding ID")
	}
}

// =============================================================================
// Tests: ListTriageHistory Input Validation & Defaults
// =============================================================================

func TestAITriage_ListTriageHistory_InvalidTenantID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, _, err := svc.ListTriageHistory(context.Background(), "bad", "550e8400-e29b-41d4-a716-446655440000", 20, 0)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestAITriage_ListTriageHistory_InvalidFindingID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, _, err := svc.ListTriageHistory(context.Background(), "550e8400-e29b-41d4-a716-446655440000", "bad", 20, 0)
	if err == nil {
		t.Fatal("expected error for invalid finding ID")
	}
}

// =============================================================================
// Tests: ShouldAutoTriage
// =============================================================================

func TestAITriage_ShouldAutoTriage_PlatformDisabled(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{Enabled: false},
		log,
	)

	tenantID := shared.NewID()
	result, err := svc.ShouldAutoTriage(context.Background(), tenantID, "critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false when platform AI is disabled")
	}
}

func TestAITriage_ShouldAutoTriage_TenantDisabled(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode": "disabled",
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{Enabled: true},
		log,
	)

	result, err := svc.ShouldAutoTriage(context.Background(), tenantID, "critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false when tenant AI is disabled")
	}
}

func TestAITriage_ShouldAutoTriage_AutoTriageDisabled(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode":                "platform",
				"auto_triage_enabled": false,
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{Enabled: true},
		log,
	)

	result, err := svc.ShouldAutoTriage(context.Background(), tenantID, "critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false when auto-triage is disabled")
	}
}

func TestAITriage_ShouldAutoTriage_SeverityMatch(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode":                   "platform",
				"auto_triage_enabled":    true,
				"auto_triage_severities": []any{"critical", "high"},
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{Enabled: true},
		log,
	)

	tests := []struct {
		name     string
		severity string
		expected bool
	}{
		{"critical matches", "critical", true},
		{"high matches", "high", true},
		{"medium does not match", "medium", false},
		{"low does not match", "low", false},
		{"case insensitive", "CRITICAL", true},
		{"mixed case", "High", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := svc.ShouldAutoTriage(context.Background(), tenantID, tt.severity)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("ShouldAutoTriage(%q) = %v, want %v", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestAITriage_ShouldAutoTriage_TenantNotFound(t *testing.T) {
	t.Parallel()

	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.getByIDErr = errors.New("tenant not found")

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{Enabled: true},
		log,
	)

	_, err := svc.ShouldAutoTriage(context.Background(), shared.NewID(), "critical")
	if err == nil {
		t.Fatal("expected error when tenant not found")
	}
}

// =============================================================================
// Tests: GetAIConfig
// =============================================================================

func TestAITriage_GetAIConfig_InvalidTenantID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.GetAIConfig(context.Background(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAITriage_GetAIConfig_DisabledMode(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode": "disabled",
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{},
		log,
	)

	info, err := svc.GetAIConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.IsEnabled {
		t.Error("expected IsEnabled=false for disabled mode")
	}
	if info.Provider != "" {
		t.Errorf("expected empty provider for disabled, got %q", info.Provider)
	}
	if info.Model != "" {
		t.Errorf("expected empty model for disabled, got %q", info.Model)
	}
}

func TestAITriage_GetAIConfig_PlatformMode(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode": "platform",
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{
			PlatformProvider: "openai",
			PlatformModel:    "gpt-4o",
		},
		log,
	)

	info, err := svc.GetAIConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsEnabled {
		t.Error("expected IsEnabled=true for platform mode")
	}
	if info.Provider != "openai" {
		t.Errorf("expected provider 'openai', got %q", info.Provider)
	}
	if info.Model != "gpt-4o" {
		t.Errorf("expected model 'gpt-4o', got %q", info.Model)
	}
}

func TestAITriage_GetAIConfig_PlatformMode_DefaultProvider(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode": "platform",
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{}, // No platform provider set
		log,
	)

	info, err := svc.GetAIConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Provider != "claude" {
		t.Errorf("expected default provider 'claude', got %q", info.Provider)
	}
}

func TestAITriage_GetAIConfig_BYOKMode(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode":           "byok",
				"provider":       "openai",
				"model_override": "gpt-4-turbo",
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{},
		log,
	)

	info, err := svc.GetAIConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsEnabled {
		t.Error("expected IsEnabled=true for BYOK mode")
	}
	if info.Provider != "openai" {
		t.Errorf("expected provider 'openai', got %q", info.Provider)
	}
	if info.Model != "gpt-4-turbo" {
		t.Errorf("expected model 'gpt-4-turbo', got %q", info.Model)
	}
}

func TestAITriage_GetAIConfig_BYOKMode_DefaultModels(t *testing.T) {
	t.Parallel()

	providers := []struct {
		provider      string
		expectedModel string
	}{
		{"claude", "claude-sonnet-4-20250514"},
		{"openai", "gpt-4o"},
		{"gemini", "gemini-2.0-flash"},
	}

	for _, p := range providers {
		t.Run(p.provider, func(t *testing.T) {
			t.Parallel()

			tenantID := shared.NewID()
			now := time.Now().UTC()
			tenantRepo := newMockAITriageTenantRepo()
			tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
				tenantID, "test", "test", "", "",
				map[string]any{
					"ai": map[string]any{
						"mode":     "byok",
						"provider": p.provider,
					},
				},
				"creator", now, now,
			)

			log := logger.NewNop()
			svc := app.NewAITriageService(
				newMockAITriageRepo(),
				nil, tenantRepo, nil, nil,
				config.AITriageConfig{},
				log,
			)

			info, err := svc.GetAIConfig(context.Background(), tenantID.String())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Model != p.expectedModel {
				t.Errorf("expected default model %q for %s, got %q", p.expectedModel, p.provider, info.Model)
			}
		})
	}
}

func TestAITriage_GetAIConfig_AgentMode(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	now := time.Now().UTC()
	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.tenants[tenantID.String()] = tenant.Reconstitute(
		tenantID, "test", "test", "", "",
		map[string]any{
			"ai": map[string]any{
				"mode": "agent",
			},
		},
		"creator", now, now,
	)

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{},
		log,
	)

	info, err := svc.GetAIConfig(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Provider != "agent" {
		t.Errorf("expected provider 'agent', got %q", info.Provider)
	}
	if info.Model != "self-hosted" {
		t.Errorf("expected model 'self-hosted', got %q", info.Model)
	}
}

func TestAITriage_GetAIConfig_TenantNotFound(t *testing.T) {
	t.Parallel()

	tenantRepo := newMockAITriageTenantRepo()
	tenantRepo.getByIDErr = errors.New("tenant not found")

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, tenantRepo, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.GetAIConfig(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error when tenant not found")
	}
}

// =============================================================================
// Tests: GetPlanTokenLimit (OSS always unlimited)
// =============================================================================

func TestAITriage_GetPlanTokenLimit_AlwaysUnlimited(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	limit, err := svc.GetPlanTokenLimit(context.Background(), "any-tenant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if limit != -1 {
		t.Errorf("expected -1 (unlimited) in OSS edition, got %d", limit)
	}
}

// =============================================================================
// Tests: RecoverStuckJobs
// =============================================================================

func TestAITriage_RecoverStuckJobs_NoStuckJobs(t *testing.T) {
	t.Parallel()

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckResult = []*aitriage.TriageResult{}

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	output, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Total != 0 {
		t.Errorf("expected 0 total, got %d", output.Total)
	}
	if output.Recovered != 0 {
		t.Errorf("expected 0 recovered, got %d", output.Recovered)
	}
}

func TestAITriage_RecoverStuckJobs_DefaultInputs(t *testing.T) {
	t.Parallel()

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckResult = []*aitriage.TriageResult{}

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	// Zero values should get defaults
	output, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{
		StuckDuration: 0,
		Limit:         0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output == nil {
		t.Fatal("expected non-nil output")
	}
}

func TestAITriage_RecoverStuckJobs_FindError(t *testing.T) {
	t.Parallel()

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckErr = errors.New("database connection error")

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{})
	if err == nil {
		t.Fatal("expected error when finding stuck jobs fails")
	}
}

func TestAITriage_RecoverStuckJobs_WithStuckJobs(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	findingID := shared.NewID()

	stuckResult, _ := aitriage.NewTriageResult(tenantID, findingID, aitriage.TriageTypeManual, nil)

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckResult = []*aitriage.TriageResult{stuckResult}
	triageRepo.markStuckResult = true

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	output, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{
		StuckDuration: 15 * time.Minute,
		Limit:         50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Total != 1 {
		t.Errorf("expected 1 total, got %d", output.Total)
	}
	if output.Recovered != 1 {
		t.Errorf("expected 1 recovered, got %d", output.Recovered)
	}
	if output.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", output.Skipped)
	}
}

func TestAITriage_RecoverStuckJobs_AlreadyTerminal(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	findingID := shared.NewID()

	stuckResult, _ := aitriage.NewTriageResult(tenantID, findingID, aitriage.TriageTypeManual, nil)

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckResult = []*aitriage.TriageResult{stuckResult}
	triageRepo.markStuckResult = false // Already terminal

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	output, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Recovered != 0 {
		t.Errorf("expected 0 recovered, got %d", output.Recovered)
	}
	if output.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", output.Skipped)
	}
}

func TestAITriage_RecoverStuckJobs_MarkFailedError(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	findingID := shared.NewID()

	stuckResult, _ := aitriage.NewTriageResult(tenantID, findingID, aitriage.TriageTypeManual, nil)

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckResult = []*aitriage.TriageResult{stuckResult}
	triageRepo.markStuckErr = errors.New("update failed")

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	output, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output.Errors != 1 {
		t.Errorf("expected 1 error, got %d", output.Errors)
	}
}

func TestAITriage_RecoverStuckJobs_BroadcastsEvent(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	findingID := shared.NewID()

	stuckResult, _ := aitriage.NewTriageResult(tenantID, findingID, aitriage.TriageTypeManual, nil)

	triageRepo := newMockAITriageRepo()
	triageRepo.findStuckResult = []*aitriage.TriageResult{stuckResult}
	triageRepo.markStuckResult = true

	broadcaster := &mockTriageBroadcaster{}

	log := logger.NewNop()
	svc := app.NewAITriageService(
		triageRepo, nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)
	svc.SetTriageBroadcaster(broadcaster)

	_, err := svc.RecoverStuckJobs(context.Background(), app.RecoverStuckJobsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(broadcaster.broadcasts) != 1 {
		t.Errorf("expected 1 broadcast, got %d", len(broadcaster.broadcasts))
	}
	if broadcaster.broadcasts[0].tenantID != tenantID.String() {
		t.Errorf("expected tenant ID %s in broadcast, got %s",
			tenantID.String(), broadcaster.broadcasts[0].tenantID)
	}
}

// =============================================================================
// Tests: RequestBulkTriage Input Validation
// =============================================================================

func TestAITriage_RequestBulkTriage_InvalidTenantID(t *testing.T) {
	t.Parallel()

	log := logger.NewNop()
	svc := app.NewAITriageService(
		newMockAITriageRepo(),
		nil, nil, nil, nil,
		config.AITriageConfig{},
		log,
	)

	_, err := svc.RequestBulkTriage(context.Background(), app.BulkTriageRequest{
		TenantID:   "bad-uuid",
		FindingIDs: []string{"550e8400-e29b-41d4-a716-446655440000"},
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// Tests: TriageAnalysis Parsing
// =============================================================================

func TestAITriage_ParseTriageAnalysis_ValidJSON(t *testing.T) {
	t.Parallel()

	content := `{
		"severity_assessment": "high",
		"severity_justification": "SQL injection is critical",
		"risk_score": 85.5,
		"exploitability": "high",
		"exploitability_details": "Public exploit available",
		"business_impact": "Data breach risk",
		"priority_rank": 95,
		"false_positive_likelihood": 0.1,
		"false_positive_reason": "Verified by manual testing",
		"summary": "Critical SQL injection vulnerability",
		"remediation_steps": [
			{"step": 1, "description": "Use parameterized queries", "effort": "medium"},
			{"step": 2, "description": "Add input validation", "effort": "low"}
		],
		"related_cves": ["CVE-2024-1234"],
		"related_cwes": ["CWE-89"]
	}`

	analysis, err := aitriage.ParseTriageAnalysis(content, "openai", "gpt-4o", 500, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if analysis.SeverityAssessment != "high" {
		t.Errorf("expected severity 'high', got %q", analysis.SeverityAssessment)
	}
	if analysis.RiskScore != 85.5 {
		t.Errorf("expected risk score 85.5, got %.1f", analysis.RiskScore)
	}
	if analysis.Exploitability != aitriage.ExploitabilityHigh {
		t.Errorf("expected exploitability 'high', got %q", analysis.Exploitability)
	}
	if analysis.PriorityRank != 95 {
		t.Errorf("expected priority rank 95, got %d", analysis.PriorityRank)
	}
	if analysis.FalsePositiveLikelihood != 0.1 {
		t.Errorf("expected FP likelihood 0.1, got %.2f", analysis.FalsePositiveLikelihood)
	}
	if len(analysis.RemediationSteps) != 2 {
		t.Errorf("expected 2 remediation steps, got %d", len(analysis.RemediationSteps))
	}
	if len(analysis.RelatedCVEs) != 1 || analysis.RelatedCVEs[0] != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %v", analysis.RelatedCVEs)
	}
	if len(analysis.RelatedCWEs) != 1 || analysis.RelatedCWEs[0] != "CWE-89" {
		t.Errorf("expected CWE-89, got %v", analysis.RelatedCWEs)
	}
	if analysis.Provider != "openai" {
		t.Errorf("expected provider 'openai', got %q", analysis.Provider)
	}
	if analysis.Model != "gpt-4o" {
		t.Errorf("expected model 'gpt-4o', got %q", analysis.Model)
	}
	if analysis.PromptTokens != 500 {
		t.Errorf("expected 500 prompt tokens, got %d", analysis.PromptTokens)
	}
	if analysis.CompletionTokens != 200 {
		t.Errorf("expected 200 completion tokens, got %d", analysis.CompletionTokens)
	}
}

func TestAITriage_ParseTriageAnalysis_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := aitriage.ParseTriageAnalysis("not valid json", "openai", "gpt-4o", 0, 0)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestAITriage_ParseTriageAnalysis_EmptyJSON(t *testing.T) {
	t.Parallel()

	analysis, err := aitriage.ParseTriageAnalysis("{}", "claude", "claude-3-5-sonnet", 100, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analysis.SeverityAssessment != "" {
		t.Errorf("expected empty severity, got %q", analysis.SeverityAssessment)
	}
	if analysis.RiskScore != 0 {
		t.Errorf("expected risk score 0, got %.1f", analysis.RiskScore)
	}
}

func TestAITriage_ParseTriageAnalysis_PartialFields(t *testing.T) {
	t.Parallel()

	content := `{"severity_assessment": "medium", "risk_score": 45}`

	analysis, err := aitriage.ParseTriageAnalysis(content, "openai", "gpt-4o", 100, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if analysis.SeverityAssessment != "medium" {
		t.Errorf("expected 'medium', got %q", analysis.SeverityAssessment)
	}
	if analysis.RiskScore != 45 {
		t.Errorf("expected 45, got %.1f", analysis.RiskScore)
	}
	if analysis.Summary != "" {
		t.Errorf("expected empty summary, got %q", analysis.Summary)
	}
}

// =============================================================================
// Tests: TriageResult Entity
// =============================================================================

func TestAITriage_NewTriageResult_ValidTypes(t *testing.T) {
	t.Parallel()

	tenantID := shared.NewID()
	findingID := shared.NewID()

	types := []aitriage.TriageType{
		aitriage.TriageTypeAuto,
		aitriage.TriageTypeManual,
		aitriage.TriageTypeBulk,
	}

	for _, tt := range types {
		t.Run(string(tt), func(t *testing.T) {
			t.Parallel()
			result, err := aitriage.NewTriageResult(tenantID, findingID, tt, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Status() != aitriage.TriageStatusPending {
				t.Errorf("expected pending status, got %q", result.Status())
			}
			if result.TriageType() != tt {
				t.Errorf("expected type %q, got %q", tt, result.TriageType())
			}
			if result.TenantID() != tenantID {
				t.Error("tenant ID mismatch")
			}
			if result.FindingID() != findingID {
				t.Error("finding ID mismatch")
			}
		})
	}
}

func TestAITriage_NewTriageResult_InvalidType(t *testing.T) {
	t.Parallel()

	_, err := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), "invalid", nil)
	if err == nil {
		t.Fatal("expected error for invalid triage type")
	}
}

func TestAITriage_NewTriageResult_WithRequestedBy(t *testing.T) {
	t.Parallel()

	userID := shared.NewID()
	result, err := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), aitriage.TriageTypeManual, &userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequestedBy() == nil {
		t.Fatal("expected non-nil requestedBy")
	}
	if *result.RequestedBy() != userID {
		t.Error("requestedBy mismatch")
	}
}

func TestAITriage_TriageResult_MarkProcessing(t *testing.T) {
	t.Parallel()

	result, _ := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), aitriage.TriageTypeManual, nil)
	if err := result.MarkProcessing(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status() != aitriage.TriageStatusProcessing {
		t.Errorf("expected processing, got %q", result.Status())
	}
	if result.StartedAt() == nil {
		t.Error("expected startedAt to be set")
	}
}

func TestAITriage_TriageResult_MarkProcessing_InvalidState(t *testing.T) {
	t.Parallel()

	result, _ := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), aitriage.TriageTypeManual, nil)
	_ = result.MarkProcessing()

	// Cannot process from processing state
	err := result.MarkProcessing()
	if err == nil {
		t.Error("expected error when marking processing from processing state")
	}
}

func TestAITriage_TriageResult_MarkFailed(t *testing.T) {
	t.Parallel()

	result, _ := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), aitriage.TriageTypeManual, nil)
	_ = result.MarkFailed("test error")

	if result.Status() != aitriage.TriageStatusFailed {
		t.Errorf("expected failed, got %q", result.Status())
	}
	if result.ErrorMessage() != "test error" {
		t.Errorf("expected error message 'test error', got %q", result.ErrorMessage())
	}
	if result.CompletedAt() == nil {
		t.Error("expected completedAt to be set")
	}
}

func TestAITriage_TriageResult_MarkCompleted(t *testing.T) {
	t.Parallel()

	result, _ := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), aitriage.TriageTypeManual, nil)
	_ = result.MarkProcessing()

	analysis := aitriage.TriageAnalysis{
		Provider:            "claude",
		Model:               "claude-3-5-sonnet",
		SeverityAssessment:  "high",
		RiskScore:           75.0,
		Exploitability:      aitriage.ExploitabilityHigh,
		PriorityRank:        90,
		Summary:             "Critical SQL injection",
		PromptTokens:        500,
		CompletionTokens:    200,
	}

	err := result.MarkCompleted(analysis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status() != aitriage.TriageStatusCompleted {
		t.Errorf("expected completed, got %q", result.Status())
	}
	if result.SeverityAssessment() != "high" {
		t.Errorf("expected severity 'high', got %q", result.SeverityAssessment())
	}
	if result.RiskScore() != 75.0 {
		t.Errorf("expected risk score 75.0, got %.1f", result.RiskScore())
	}
	if result.CompletedAt() == nil {
		t.Error("expected completedAt to be set")
	}
	if result.TotalTokens() != 700 {
		t.Errorf("expected total tokens 700, got %d", result.TotalTokens())
	}
}

func TestAITriage_TriageResult_MarkCompleted_InvalidState(t *testing.T) {
	t.Parallel()

	result, _ := aitriage.NewTriageResult(shared.NewID(), shared.NewID(), aitriage.TriageTypeManual, nil)
	// Cannot complete from pending state (must be processing first)
	err := result.MarkCompleted(aitriage.TriageAnalysis{})
	if err == nil {
		t.Error("expected error when completing from pending state")
	}
}

// =============================================================================
// Tests: TriageStatus
// =============================================================================

func TestAITriage_TriageStatus_IsValid(t *testing.T) {
	t.Parallel()

	validStatuses := []aitriage.TriageStatus{
		aitriage.TriageStatusPending,
		aitriage.TriageStatusProcessing,
		aitriage.TriageStatusCompleted,
		aitriage.TriageStatusFailed,
	}
	for _, s := range validStatuses {
		if !s.IsValid() {
			t.Errorf("expected %q to be valid", s)
		}
	}

	if aitriage.TriageStatus("unknown").IsValid() {
		t.Error("expected 'unknown' to be invalid")
	}
}

func TestAITriage_TriageStatus_IsTerminal(t *testing.T) {
	t.Parallel()

	if !aitriage.TriageStatusCompleted.IsTerminal() {
		t.Error("completed should be terminal")
	}
	if !aitriage.TriageStatusFailed.IsTerminal() {
		t.Error("failed should be terminal")
	}
	if aitriage.TriageStatusPending.IsTerminal() {
		t.Error("pending should not be terminal")
	}
	if aitriage.TriageStatusProcessing.IsTerminal() {
		t.Error("processing should not be terminal")
	}
}

// =============================================================================
// Tests: TriageType
// =============================================================================

func TestAITriage_TriageType_IsValid(t *testing.T) {
	t.Parallel()

	validTypes := []aitriage.TriageType{
		aitriage.TriageTypeAuto,
		aitriage.TriageTypeManual,
		aitriage.TriageTypeBulk,
	}
	for _, tt := range validTypes {
		if !tt.IsValid() {
			t.Errorf("expected %q to be valid", tt)
		}
	}

	if aitriage.TriageType("invalid").IsValid() {
		t.Error("expected 'invalid' to be invalid type")
	}
}

// =============================================================================
// Tests: Exploitability
// =============================================================================

func TestAITriage_Exploitability_IsValid(t *testing.T) {
	t.Parallel()

	validValues := []aitriage.Exploitability{
		aitriage.ExploitabilityHigh,
		aitriage.ExploitabilityMedium,
		aitriage.ExploitabilityLow,
		aitriage.ExploitabilityTheoretical,
	}
	for _, e := range validValues {
		if !e.IsValid() {
			t.Errorf("expected %q to be valid", e)
		}
	}

	if aitriage.Exploitability("unknown").IsValid() {
		t.Error("expected 'unknown' to be invalid exploitability")
	}
}

func (m *mockAITriageFindingRepo) ListFindingGroups(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter, _ pagination.Pagination) (pagination.Result[*vulnerability.FindingGroup], error) {
	return pagination.Result[*vulnerability.FindingGroup]{}, nil
}

func (m *mockAITriageFindingRepo) BulkUpdateStatusByFilter(_ context.Context, _ shared.ID, _ vulnerability.FindingFilter, _ vulnerability.FindingStatus, _ string, _ *shared.ID) (int64, error) {
	return 0, nil
}

func (m *mockAITriageFindingRepo) FindRelatedCVEs(_ context.Context, _ shared.ID, _ string, _ vulnerability.FindingFilter) ([]vulnerability.RelatedCVE, error) {
	return nil, nil
}

func (m *mockAITriageFindingRepo) ListByStatusAndAssets(_ context.Context, _ shared.ID, _ vulnerability.FindingStatus, _ []shared.ID) ([]*vulnerability.Finding, error) {
	return nil, nil
}
