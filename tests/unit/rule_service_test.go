package unit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/rule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repositories
// ============================================================================

// --- Source Repository ---

type ruleSvcMockSourceRepo struct {
	mu      sync.Mutex
	sources map[string]*rule.Source
	createErr error
	updateErr error
	deleteErr error
	listErr   error
	needingSyncSources []*rule.Source
}

func newRuleSvcMockSourceRepo() *ruleSvcMockSourceRepo {
	return &ruleSvcMockSourceRepo{
		sources: make(map[string]*rule.Source),
	}
}

func (m *ruleSvcMockSourceRepo) Create(_ context.Context, source *rule.Source) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.sources[source.ID.String()] = source
	return nil
}

func (m *ruleSvcMockSourceRepo) GetByID(_ context.Context, id shared.ID) (*rule.Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sources[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *ruleSvcMockSourceRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*rule.Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sources[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *ruleSvcMockSourceRepo) List(_ context.Context, _ rule.SourceFilter, page pagination.Pagination) (pagination.Result[*rule.Source], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return pagination.Result[*rule.Source]{}, m.listErr
	}
	result := make([]*rule.Source, 0, len(m.sources))
	for _, s := range m.sources {
		result = append(result, s)
	}
	total := int64(len(result))
	return pagination.Result[*rule.Source]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *ruleSvcMockSourceRepo) ListByTenantAndTool(_ context.Context, tenantID shared.ID, _ *shared.ID) ([]*rule.Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*rule.Source, 0)
	for _, s := range m.sources {
		if s.TenantID == tenantID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *ruleSvcMockSourceRepo) ListNeedingSync(_ context.Context, limit int) ([]*rule.Source, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.needingSyncSources != nil {
		if limit > len(m.needingSyncSources) {
			limit = len(m.needingSyncSources)
		}
		return m.needingSyncSources[:limit], nil
	}
	return []*rule.Source{}, nil
}

func (m *ruleSvcMockSourceRepo) Update(_ context.Context, source *rule.Source) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sources[source.ID.String()] = source
	return nil
}

func (m *ruleSvcMockSourceRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sources, id.String())
	return nil
}

// --- Rule Repository ---

type ruleSvcMockRuleRepo struct {
	mu    sync.Mutex
	rules map[string]*rule.Rule
	listErr     error
	upsertErr   error
	deleteBySourceErr error
}

func newRuleSvcMockRuleRepo() *ruleSvcMockRuleRepo {
	return &ruleSvcMockRuleRepo{
		rules: make(map[string]*rule.Rule),
	}
}

func (m *ruleSvcMockRuleRepo) Create(_ context.Context, r *rule.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[r.ID.String()] = r
	return nil
}

func (m *ruleSvcMockRuleRepo) CreateBatch(_ context.Context, rules []*rule.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rules {
		m.rules[r.ID.String()] = r
	}
	return nil
}

func (m *ruleSvcMockRuleRepo) GetByID(_ context.Context, id shared.ID) (*rule.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return r, nil
}

func (m *ruleSvcMockRuleRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*rule.Rule, error) {
	return nil, nil
}

func (m *ruleSvcMockRuleRepo) GetBySourceAndRuleID(_ context.Context, sourceID shared.ID, ruleID string) (*rule.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rules {
		if r.SourceID == sourceID && r.RuleID == ruleID {
			return r, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *ruleSvcMockRuleRepo) List(_ context.Context, _ rule.RuleFilter, page pagination.Pagination) (pagination.Result[*rule.Rule], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return pagination.Result[*rule.Rule]{}, m.listErr
	}
	result := make([]*rule.Rule, 0, len(m.rules))
	for _, r := range m.rules {
		result = append(result, r)
	}
	total := int64(len(result))
	return pagination.Result[*rule.Rule]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *ruleSvcMockRuleRepo) ListBySource(_ context.Context, sourceID shared.ID) ([]*rule.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*rule.Rule, 0)
	for _, r := range m.rules {
		if r.SourceID == sourceID {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *ruleSvcMockRuleRepo) Update(_ context.Context, r *rule.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[r.ID.String()] = r
	return nil
}

func (m *ruleSvcMockRuleRepo) UpsertBatch(_ context.Context, rules []*rule.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.upsertErr != nil {
		return m.upsertErr
	}
	for _, r := range rules {
		m.rules[r.ID.String()] = r
	}
	return nil
}

func (m *ruleSvcMockRuleRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rules, id.String())
	return nil
}

func (m *ruleSvcMockRuleRepo) DeleteBySource(_ context.Context, sourceID shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteBySourceErr != nil {
		return m.deleteBySourceErr
	}
	for k, r := range m.rules {
		if r.SourceID == sourceID {
			delete(m.rules, k)
		}
	}
	return nil
}

func (m *ruleSvcMockRuleRepo) CountBySource(_ context.Context, sourceID shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, r := range m.rules {
		if r.SourceID == sourceID {
			count++
		}
	}
	return count, nil
}

func (m *ruleSvcMockRuleRepo) CountByTenantAndTool(_ context.Context, _ shared.ID, _ *shared.ID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rules), nil
}

// --- Bundle Repository ---

type ruleSvcMockBundleRepo struct {
	mu      sync.Mutex
	bundles map[string]*rule.Bundle
	createErr     error
	updateErr     error
	deleteErr     error
	deleteExpired int64
}

func newRuleSvcMockBundleRepo() *ruleSvcMockBundleRepo {
	return &ruleSvcMockBundleRepo{
		bundles: make(map[string]*rule.Bundle),
	}
}

func (m *ruleSvcMockBundleRepo) Create(_ context.Context, bundle *rule.Bundle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.bundles[bundle.ID.String()] = bundle
	return nil
}

func (m *ruleSvcMockBundleRepo) GetByID(_ context.Context, id shared.ID) (*rule.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bundles[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return b, nil
}

func (m *ruleSvcMockBundleRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*rule.Bundle, error) {
	return nil, nil
}

func (m *ruleSvcMockBundleRepo) GetLatest(_ context.Context, tenantID, toolID shared.ID) (*rule.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *rule.Bundle
	for _, b := range m.bundles {
		if b.TenantID == tenantID && b.ToolID == toolID && b.Status == rule.BundleStatusReady {
			if latest == nil || b.CreatedAt.After(latest.CreatedAt) {
				latest = b
			}
		}
	}
	if latest == nil {
		return nil, shared.ErrNotFound
	}
	return latest, nil
}

func (m *ruleSvcMockBundleRepo) GetByContentHash(_ context.Context, hash string) (*rule.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.bundles {
		if b.ContentHash == hash {
			return b, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *ruleSvcMockBundleRepo) List(_ context.Context, _ rule.BundleFilter) ([]*rule.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*rule.Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		result = append(result, b)
	}
	return result, nil
}

func (m *ruleSvcMockBundleRepo) Update(_ context.Context, bundle *rule.Bundle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	m.bundles[bundle.ID.String()] = bundle
	return nil
}

func (m *ruleSvcMockBundleRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.bundles, id.String())
	return nil
}

func (m *ruleSvcMockBundleRepo) DeleteExpired(_ context.Context) (int64, error) {
	return m.deleteExpired, nil
}

// --- Override Repository ---

type ruleSvcMockOverrideRepo struct {
	mu        sync.Mutex
	overrides map[string]*rule.Override
	createErr error
	updateErr error
	deleteErr error
}

func newRuleSvcMockOverrideRepo() *ruleSvcMockOverrideRepo {
	return &ruleSvcMockOverrideRepo{
		overrides: make(map[string]*rule.Override),
	}
}

func (m *ruleSvcMockOverrideRepo) Create(_ context.Context, override *rule.Override) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.overrides[override.ID.String()] = override
	return nil
}

func (m *ruleSvcMockOverrideRepo) GetByID(_ context.Context, id shared.ID) (*rule.Override, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.overrides[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return o, nil
}

func (m *ruleSvcMockOverrideRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*rule.Override, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.overrides[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if o.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return o, nil
}

func (m *ruleSvcMockOverrideRepo) List(_ context.Context, _ rule.OverrideFilter, page pagination.Pagination) (pagination.Result[*rule.Override], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*rule.Override, 0, len(m.overrides))
	for _, o := range m.overrides {
		result = append(result, o)
	}
	total := int64(len(result))
	return pagination.Result[*rule.Override]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *ruleSvcMockOverrideRepo) ListByTenantAndTool(_ context.Context, tenantID shared.ID, toolID *shared.ID) ([]*rule.Override, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*rule.Override, 0)
	for _, o := range m.overrides {
		if o.TenantID != tenantID {
			continue
		}
		if toolID != nil && (o.ToolID == nil || *o.ToolID != *toolID) {
			continue
		}
		result = append(result, o)
	}
	return result, nil
}

func (m *ruleSvcMockOverrideRepo) Update(_ context.Context, override *rule.Override) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	m.overrides[override.ID.String()] = override
	return nil
}

func (m *ruleSvcMockOverrideRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.overrides, id.String())
	return nil
}

func (m *ruleSvcMockOverrideRepo) DeleteExpired(_ context.Context) (int64, error) {
	return 0, nil
}

// --- Sync History Repository ---

type ruleSvcMockSyncHistoryRepo struct {
	mu      sync.Mutex
	entries []*rule.SyncHistory
	createErr error
}

func newRuleSvcMockSyncHistoryRepo() *ruleSvcMockSyncHistoryRepo {
	return &ruleSvcMockSyncHistoryRepo{
		entries: make([]*rule.SyncHistory, 0),
	}
}

func (m *ruleSvcMockSyncHistoryRepo) Create(_ context.Context, history *rule.SyncHistory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	m.entries = append(m.entries, history)
	return nil
}

func (m *ruleSvcMockSyncHistoryRepo) ListBySource(_ context.Context, sourceID shared.ID, limit int) ([]*rule.SyncHistory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*rule.SyncHistory, 0)
	for _, e := range m.entries {
		if e.SourceID == sourceID {
			result = append(result, e)
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// --- Audit Repository (minimal) ---

type ruleSvcMockAuditRepo struct {
	mu   sync.Mutex
	logs []*audit.AuditLog
}

func newRuleSvcMockAuditRepo() *ruleSvcMockAuditRepo {
	return &ruleSvcMockAuditRepo{
		logs: make([]*audit.AuditLog, 0),
	}
}

func (m *ruleSvcMockAuditRepo) Create(_ context.Context, log *audit.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, log)
	return nil
}

func (m *ruleSvcMockAuditRepo) CreateBatch(_ context.Context, logs []*audit.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, logs...)
	return nil
}

func (m *ruleSvcMockAuditRepo) GetByID(_ context.Context, _ shared.ID) (*audit.AuditLog, error) {
	return nil, errors.New("not implemented")
}

func (m *ruleSvcMockAuditRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*audit.AuditLog, error) {
	return nil, nil
}

func (m *ruleSvcMockAuditRepo) List(_ context.Context, _ audit.Filter, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *ruleSvcMockAuditRepo) Count(_ context.Context, _ audit.Filter) (int64, error) {
	return 0, nil
}

func (m *ruleSvcMockAuditRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *ruleSvcMockAuditRepo) GetLatestByResource(_ context.Context, _ audit.ResourceType, _ string) (*audit.AuditLog, error) {
	return nil, errors.New("not implemented")
}

func (m *ruleSvcMockAuditRepo) ListByActor(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *ruleSvcMockAuditRepo) ListByResource(_ context.Context, _ audit.ResourceType, _ string, _ pagination.Pagination) (pagination.Result[*audit.AuditLog], error) {
	return pagination.Result[*audit.AuditLog]{}, nil
}

func (m *ruleSvcMockAuditRepo) CountByAction(_ context.Context, _ *shared.ID, _ audit.Action, _ time.Time) (int64, error) {
	return 0, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

type ruleSvcTestDeps struct {
	svc             *app.RuleService
	sourceRepo      *ruleSvcMockSourceRepo
	ruleRepo        *ruleSvcMockRuleRepo
	bundleRepo      *ruleSvcMockBundleRepo
	overrideRepo    *ruleSvcMockOverrideRepo
	syncHistoryRepo *ruleSvcMockSyncHistoryRepo
	auditRepo       *ruleSvcMockAuditRepo
}

func newRuleSvcTestDeps() *ruleSvcTestDeps {
	sourceRepo := newRuleSvcMockSourceRepo()
	ruleRepo := newRuleSvcMockRuleRepo()
	bundleRepo := newRuleSvcMockBundleRepo()
	overrideRepo := newRuleSvcMockOverrideRepo()
	syncHistoryRepo := newRuleSvcMockSyncHistoryRepo()
	auditRepo := newRuleSvcMockAuditRepo()
	log := logger.NewNop()
	auditSvc := app.NewAuditService(auditRepo, log)

	svc := app.NewRuleService(
		sourceRepo,
		ruleRepo,
		bundleRepo,
		overrideRepo,
		syncHistoryRepo,
		auditSvc,
		log,
	)

	return &ruleSvcTestDeps{
		svc:             svc,
		sourceRepo:      sourceRepo,
		ruleRepo:        ruleRepo,
		bundleRepo:      bundleRepo,
		overrideRepo:    overrideRepo,
		syncHistoryRepo: syncHistoryRepo,
		auditRepo:       auditRepo,
	}
}

func ruleSvcValidConfig() json.RawMessage {
	return json.RawMessage(`{"url":"https://github.com/example/rules","branch":"main"}`)
}

// ============================================================================
// Source CRUD Tests
// ============================================================================

func TestRuleService_CreateSource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	source, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:            tenantID.String(),
		Name:                "My Git Source",
		Description:         "Rules from GitHub",
		SourceType:          "git",
		Config:              ruleSvcValidConfig(),
		SyncEnabled:         true,
		SyncIntervalMinutes: 30,
		Priority:            200,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source == nil {
		t.Fatal("expected source, got nil")
	}
	if source.Name != "My Git Source" {
		t.Errorf("expected name 'My Git Source', got %q", source.Name)
	}
	if source.SourceType != rule.SourceTypeGit {
		t.Errorf("expected source type git, got %q", source.SourceType)
	}
	if source.SyncIntervalMinutes != 30 {
		t.Errorf("expected sync interval 30, got %d", source.SyncIntervalMinutes)
	}
	if source.Priority != 200 {
		t.Errorf("expected priority 200, got %d", source.Priority)
	}
	if !source.Enabled {
		t.Error("expected source to be enabled")
	}
	if !source.SyncEnabled {
		t.Error("expected sync to be enabled")
	}
	if source.TenantID != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, source.TenantID)
	}

	// Verify stored in repo
	if len(d.sourceRepo.sources) != 1 {
		t.Errorf("expected 1 source in repo, got %d", len(d.sourceRepo.sources))
	}
}

func TestRuleService_CreateSource_WithToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	source, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		ToolID:     toolID.String(),
		Name:       "Tool-specific source",
		SourceType: "http",
		Config:     ruleSvcValidConfig(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.ToolID == nil {
		t.Fatal("expected tool ID, got nil")
	}
	if *source.ToolID != toolID {
		t.Errorf("expected tool ID %s, got %s", toolID, *source.ToolID)
	}
}

func TestRuleService_CreateSource_WithCredentialsID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	credID := shared.NewID()

	source, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:      tenantID.String(),
		Name:          "Authenticated source",
		SourceType:    "git",
		Config:        ruleSvcValidConfig(),
		CredentialsID: credID.String(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if source.CredentialsID == nil {
		t.Fatal("expected credentials ID, got nil")
	}
	if *source.CredentialsID != credID {
		t.Errorf("expected credentials ID %s, got %s", credID, *source.CredentialsID)
	}
}

func TestRuleService_CreateSource_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   "not-a-uuid",
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateSource_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   shared.NewID().String(),
		ToolID:     "bad-uuid",
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	if err == nil {
		t.Fatal("expected error for invalid tool ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateSource_InvalidCredentialsID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:      shared.NewID().String(),
		Name:          "Test",
		SourceType:    "git",
		Config:        ruleSvcValidConfig(),
		CredentialsID: "invalid",
	})

	if err == nil {
		t.Fatal("expected error for invalid credentials ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateSource_InvalidSourceType(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   shared.NewID().String(),
		Name:       "Test",
		SourceType: "ftp",
		Config:     ruleSvcValidConfig(),
	})

	if err == nil {
		t.Fatal("expected error for invalid source type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateSource_RepoError(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	d.sourceRepo.createErr = errors.New("db connection lost")

	_, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   shared.NewID().String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestRuleService_CreateSource_AllSourceTypes(t *testing.T) {
	for _, st := range []string{"git", "http", "local"} {
		t.Run(st, func(t *testing.T) {
			d := newRuleSvcTestDeps()
			ctx := context.Background()

			source, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
				TenantID:   shared.NewID().String(),
				Name:       "Source " + st,
				SourceType: st,
				Config:     ruleSvcValidConfig(),
			})

			if err != nil {
				t.Fatalf("expected no error for source type %s, got %v", st, err)
			}
			if string(source.SourceType) != st {
				t.Errorf("expected source type %s, got %s", st, source.SourceType)
			}
		})
	}
}

func TestRuleService_CreateSource_DefaultSyncInterval(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	source, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:            shared.NewID().String(),
		Name:                "Default interval",
		SourceType:          "git",
		Config:              ruleSvcValidConfig(),
		SyncIntervalMinutes: 0, // Should use domain default (60)
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Domain NewSource sets default to 60
	if source.SyncIntervalMinutes != 60 {
		t.Errorf("expected default sync interval 60, got %d", source.SyncIntervalMinutes)
	}
}

// --- GetSource ---

func TestRuleService_GetSource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test Source",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	got, err := d.svc.GetSource(ctx, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %s, got %s", created.ID, got.ID)
	}
}

func TestRuleService_GetSource_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetSource(ctx, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_GetSource_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetSource(ctx, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

// --- GetSourceByTenantAndID ---

func TestRuleService_GetSourceByTenantAndID_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "local",
		Config:     ruleSvcValidConfig(),
	})

	got, err := d.svc.GetSourceByTenantAndID(ctx, tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID mismatch")
	}
}

func TestRuleService_GetSourceByTenantAndID_WrongTenant(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	otherTenant := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	_, err := d.svc.GetSourceByTenantAndID(ctx, otherTenant.String(), created.ID.String())
	if err == nil {
		t.Fatal("expected error for wrong tenant")
	}
}

func TestRuleService_GetSourceByTenantAndID_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetSourceByTenantAndID(ctx, "bad", shared.NewID().String())
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_GetSourceByTenantAndID_InvalidSourceID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetSourceByTenantAndID(ctx, shared.NewID().String(), "bad")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- ListSources ---

func TestRuleService_ListSources_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	for i := 0; i < 3; i++ {
		_, err := d.svc.CreateSource(ctx, app.CreateSourceInput{
			TenantID:   tenantID.String(),
			Name:       "Source",
			SourceType: "git",
			Config:     ruleSvcValidConfig(),
		})
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	result, err := d.svc.ListSources(ctx, app.ListSourcesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 sources, got %d", result.Total)
	}
}

func TestRuleService_ListSources_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListSources(ctx, app.ListSourcesInput{
		TenantID: "invalid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListSources_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListSources(ctx, app.ListSourcesInput{
		ToolID: "invalid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListSources_WithFilters(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	enabled := true

	result, err := d.svc.ListSources(ctx, app.ListSourcesInput{
		SourceType: "git",
		Enabled:    &enabled,
		SyncStatus: "pending",
		Search:     "test",
		Page:       1,
		PerPage:    20,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// No sources seeded, so empty result
	if result.Total != 0 {
		t.Errorf("expected 0 results, got %d", result.Total)
	}
}

// --- UpdateSource ---

func TestRuleService_UpdateSource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Original",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
		Priority:   100,
	})

	syncEnabled := false
	updated, err := d.svc.UpdateSource(ctx, app.UpdateSourceInput{
		TenantID:            tenantID.String(),
		SourceID:            created.ID.String(),
		Name:                "Updated Name",
		Description:         "Updated desc",
		SyncEnabled:         &syncEnabled,
		SyncIntervalMinutes: 120,
		Priority:            500,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %q", updated.Name)
	}
	if updated.Description != "Updated desc" {
		t.Errorf("expected description 'Updated desc', got %q", updated.Description)
	}
	if updated.SyncEnabled {
		t.Error("expected sync disabled")
	}
	if updated.SyncIntervalMinutes != 120 {
		t.Errorf("expected interval 120, got %d", updated.SyncIntervalMinutes)
	}
	if updated.Priority != 500 {
		t.Errorf("expected priority 500, got %d", updated.Priority)
	}
}

func TestRuleService_UpdateSource_EnableDisable(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	disabled := false
	updated, err := d.svc.UpdateSource(ctx, app.UpdateSourceInput{
		TenantID: tenantID.String(),
		SourceID: created.ID.String(),
		Enabled:  &disabled,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Enabled {
		t.Error("expected source to be disabled")
	}
}

func TestRuleService_UpdateSource_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	_, err := d.svc.UpdateSource(ctx, app.UpdateSourceInput{
		TenantID: tenantID.String(),
		SourceID: shared.NewID().String(),
		Name:     "Updated",
	})
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

func TestRuleService_UpdateSource_InvalidCredentialsID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	_, err := d.svc.UpdateSource(ctx, app.UpdateSourceInput{
		TenantID:      tenantID.String(),
		SourceID:      created.ID.String(),
		CredentialsID: "not-valid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_UpdateSource_WithConfig(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	newConfig := json.RawMessage(`{"url":"https://new-repo.git","branch":"develop"}`)
	updated, err := d.svc.UpdateSource(ctx, app.UpdateSourceInput{
		TenantID: tenantID.String(),
		SourceID: created.ID.String(),
		Config:   newConfig,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(updated.Config) != string(newConfig) {
		t.Errorf("config not updated")
	}
}

// --- DeleteSource ---

func TestRuleService_DeleteSource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "To Delete",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	// Add a rule associated with this source
	r := rule.NewRule(created.ID, tenantID, nil, "test-rule", "Test Rule", rule.SeverityHigh)
	_ = d.ruleRepo.Create(ctx, r)

	err := d.svc.DeleteSource(ctx, tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify source deleted
	if len(d.sourceRepo.sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(d.sourceRepo.sources))
	}
	// Verify associated rules deleted
	if len(d.ruleRepo.rules) != 0 {
		t.Errorf("expected 0 rules after source delete, got %d", len(d.ruleRepo.rules))
	}
}

func TestRuleService_DeleteSource_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.DeleteSource(ctx, shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

func TestRuleService_DeleteSource_DeleteRulesError(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	d.ruleRepo.deleteBySourceErr = errors.New("cannot delete rules")

	err := d.svc.DeleteSource(ctx, tenantID.String(), created.ID.String())
	if err == nil {
		t.Fatal("expected error when rule deletion fails")
	}
}

// --- EnableSource / DisableSource ---

func TestRuleService_EnableSource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	// Disable first, then enable
	disabled := false
	_, _ = d.svc.UpdateSource(ctx, app.UpdateSourceInput{
		TenantID: tenantID.String(),
		SourceID: created.ID.String(),
		Enabled:  &disabled,
	})

	result, err := d.svc.EnableSource(ctx, tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.Enabled {
		t.Error("expected source to be enabled")
	}
}

func TestRuleService_DisableSource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	result, err := d.svc.DisableSource(ctx, tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Enabled {
		t.Error("expected source to be disabled")
	}
}

func TestRuleService_EnableSource_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.EnableSource(ctx, shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

func TestRuleService_DisableSource_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.DisableSource(ctx, shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

// ============================================================================
// Rule Operations Tests
// ============================================================================

func TestRuleService_GetRule_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	r := rule.NewRule(shared.NewID(), shared.NewID(), nil, "sqli-check", "SQL Injection", rule.SeverityCritical)
	_ = d.ruleRepo.Create(ctx, r)

	got, err := d.svc.GetRule(ctx, r.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.RuleID != "sqli-check" {
		t.Errorf("expected rule ID 'sqli-check', got %q", got.RuleID)
	}
}

func TestRuleService_GetRule_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetRule(ctx, "invalid")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_GetRule_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetRule(ctx, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent rule")
	}
}

func TestRuleService_ListRules_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	sourceID := shared.NewID()
	tenantID := shared.NewID()

	for i := 0; i < 5; i++ {
		r := rule.NewRule(sourceID, tenantID, nil, "rule-"+string(rune('a'+i)), "Rule", rule.SeverityMedium)
		_ = d.ruleRepo.Create(ctx, r)
	}

	result, err := d.svc.ListRules(ctx, app.ListRulesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 5 {
		t.Errorf("expected 5 rules, got %d", result.Total)
	}
}

func TestRuleService_ListRules_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListRules(ctx, app.ListRulesInput{TenantID: "invalid"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListRules_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListRules(ctx, app.ListRulesInput{ToolID: "invalid"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListRules_InvalidSourceID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListRules(ctx, app.ListRulesInput{SourceID: "invalid"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListRules_WithSeverityFilter(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	result, err := d.svc.ListRules(ctx, app.ListRulesInput{
		Severity: "critical",
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	_ = result // Just verify no error on filter parsing
}

func TestRuleService_ListRulesBySource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	sourceID := shared.NewID()
	tenantID := shared.NewID()

	for i := 0; i < 3; i++ {
		r := rule.NewRule(sourceID, tenantID, nil, "rule-"+string(rune('a'+i)), "Rule", rule.SeverityLow)
		_ = d.ruleRepo.Create(ctx, r)
	}
	// Rule from another source
	otherSource := shared.NewID()
	r := rule.NewRule(otherSource, tenantID, nil, "other-rule", "Other", rule.SeverityHigh)
	_ = d.ruleRepo.Create(ctx, r)

	rules, err := d.svc.ListRulesBySource(ctx, sourceID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(rules) != 3 {
		t.Errorf("expected 3 rules for source, got %d", len(rules))
	}
}

func TestRuleService_ListRulesBySource_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListRulesBySource(ctx, "invalid")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CountRulesBySource_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	sourceID := shared.NewID()
	tenantID := shared.NewID()

	for i := 0; i < 4; i++ {
		r := rule.NewRule(sourceID, tenantID, nil, "rule-"+string(rune('a'+i)), "Rule", rule.SeverityInfo)
		_ = d.ruleRepo.Create(ctx, r)
	}

	count, err := d.svc.CountRulesBySource(ctx, sourceID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 4 {
		t.Errorf("expected count 4, got %d", count)
	}
}

func TestRuleService_CountRulesBySource_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CountRulesBySource(ctx, "bad")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// ============================================================================
// Override Tests
// ============================================================================

func TestRuleService_CreateOverride_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	createdBy := shared.NewID()

	override, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "java.lang.security.*",
		IsPattern:   true,
		Enabled:     false,
		Reason:      "Too noisy",
		CreatedBy:   createdBy.String(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if override.RulePattern != "java.lang.security.*" {
		t.Errorf("expected pattern 'java.lang.security.*', got %q", override.RulePattern)
	}
	if !override.IsPattern {
		t.Error("expected IsPattern to be true")
	}
	if override.Enabled {
		t.Error("expected Enabled to be false")
	}
	if override.Reason != "Too noisy" {
		t.Errorf("expected reason 'Too noisy', got %q", override.Reason)
	}
	if override.CreatedBy == nil || *override.CreatedBy != createdBy {
		t.Error("created_by mismatch")
	}
}

func TestRuleService_CreateOverride_WithSeverityOverride(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	override, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:         tenantID.String(),
		RulePattern:      "xss-check",
		Enabled:          true,
		SeverityOverride: "critical",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if override.SeverityOverride != rule.SeverityCritical {
		t.Errorf("expected severity override critical, got %q", override.SeverityOverride)
	}
}

func TestRuleService_CreateOverride_WithToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	override, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		RulePattern: "specific-rule",
		Enabled:     true,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if override.ToolID == nil || *override.ToolID != toolID {
		t.Error("tool ID mismatch")
	}
}

func TestRuleService_CreateOverride_WithScope(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	assetGroupID := shared.NewID()
	scanProfileID := shared.NewID()

	override, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:      tenantID.String(),
		RulePattern:   "test-rule",
		Enabled:       true,
		AssetGroupID:  assetGroupID.String(),
		ScanProfileID: scanProfileID.String(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if override.AssetGroupID == nil || *override.AssetGroupID != assetGroupID {
		t.Error("asset group ID mismatch")
	}
	if override.ScanProfileID == nil || *override.ScanProfileID != scanProfileID {
		t.Error("scan profile ID mismatch")
	}
}

func TestRuleService_CreateOverride_WithExpiration(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	override, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "temp-disable",
		Enabled:     false,
		ExpiresAt:   &expires,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if override.ExpiresAt == nil {
		t.Fatal("expected expiration to be set")
	}
}

func TestRuleService_CreateOverride_InvalidExpiresAt(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	badExpires := "not-a-date"

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
		ExpiresAt:   &badExpires,
	})

	if err == nil {
		t.Fatal("expected error for invalid expires_at")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateOverride_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    "bad",
		RulePattern: "test",
		Enabled:     true,
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateOverride_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    shared.NewID().String(),
		ToolID:      "bad",
		RulePattern: "test",
		Enabled:     true,
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateOverride_InvalidCreatedBy(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    shared.NewID().String(),
		RulePattern: "test",
		Enabled:     true,
		CreatedBy:   "bad",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateOverride_InvalidAssetGroupID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:     shared.NewID().String(),
		RulePattern:  "test",
		Enabled:      true,
		AssetGroupID: "invalid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateOverride_InvalidScanProfileID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:      shared.NewID().String(),
		RulePattern:   "test",
		Enabled:       true,
		ScanProfileID: "invalid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateOverride_RepoError(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	d.overrideRepo.createErr = errors.New("db error")

	_, err := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    shared.NewID().String(),
		RulePattern: "test",
		Enabled:     true,
	})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// --- GetOverride ---

func TestRuleService_GetOverride_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test-rule",
		Enabled:     true,
	})

	got, err := d.svc.GetOverride(ctx, created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != created.ID {
		t.Error("ID mismatch")
	}
}

func TestRuleService_GetOverride_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetOverride(ctx, "bad")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- ListOverrides ---

func TestRuleService_ListOverrides_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	for i := 0; i < 3; i++ {
		_, _ = d.svc.CreateOverride(ctx, app.CreateOverrideInput{
			TenantID:    tenantID.String(),
			RulePattern: "rule-" + string(rune('a'+i)),
			Enabled:     true,
		})
	}

	result, err := d.svc.ListOverrides(ctx, app.ListOverridesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 overrides, got %d", result.Total)
	}
}

func TestRuleService_ListOverrides_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListOverrides(ctx, app.ListOverridesInput{TenantID: "bad"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListOverrides_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListOverrides(ctx, app.ListOverridesInput{ToolID: "bad"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListOverrides_InvalidAssetGroupID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListOverrides(ctx, app.ListOverridesInput{AssetGroupID: "bad"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListOverrides_InvalidScanProfileID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListOverrides(ctx, app.ListOverridesInput{ScanProfileID: "bad"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- UpdateOverride ---

func TestRuleService_UpdateOverride_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "original-pattern",
		IsPattern:   false,
		Enabled:     true,
		Reason:      "Initial reason",
	})

	isPattern := true
	enabled := false
	updated, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:         tenantID.String(),
		OverrideID:       created.ID.String(),
		RulePattern:      "updated.*",
		IsPattern:        &isPattern,
		Enabled:          &enabled,
		SeverityOverride: "high",
		Reason:           "Updated reason",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.RulePattern != "updated.*" {
		t.Errorf("expected pattern 'updated.*', got %q", updated.RulePattern)
	}
	if !updated.IsPattern {
		t.Error("expected IsPattern true")
	}
	if updated.Enabled {
		t.Error("expected Enabled false")
	}
	if updated.SeverityOverride != rule.SeverityHigh {
		t.Errorf("expected severity high, got %q", updated.SeverityOverride)
	}
	if updated.Reason != "Updated reason" {
		t.Errorf("expected reason 'Updated reason', got %q", updated.Reason)
	}
}

func TestRuleService_UpdateOverride_WithScope(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	agID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
	})

	updated, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:     tenantID.String(),
		OverrideID:   created.ID.String(),
		AssetGroupID: agID.String(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.AssetGroupID == nil || *updated.AssetGroupID != agID {
		t.Error("asset group ID not set")
	}
}

func TestRuleService_UpdateOverride_SetExpiration(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
	})

	expires := time.Now().Add(48 * time.Hour).Format(time.RFC3339)
	updated, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:   tenantID.String(),
		OverrideID: created.ID.String(),
		ExpiresAt:  &expires,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.ExpiresAt == nil {
		t.Fatal("expected expiration to be set")
	}
}

func TestRuleService_UpdateOverride_ClearExpiration(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	initialExpires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
		ExpiresAt:   &initialExpires,
	})

	emptyExpires := ""
	updated, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:   tenantID.String(),
		OverrideID: created.ID.String(),
		ExpiresAt:  &emptyExpires,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.ExpiresAt != nil {
		t.Error("expected expiration to be cleared")
	}
}

func TestRuleService_UpdateOverride_InvalidExpiresAt(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
	})

	badExpires := "not-a-date"
	_, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:   tenantID.String(),
		OverrideID: created.ID.String(),
		ExpiresAt:  &badExpires,
	})

	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_UpdateOverride_InvalidAssetGroupID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
	})

	_, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:     tenantID.String(),
		OverrideID:   created.ID.String(),
		AssetGroupID: "bad-uuid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_UpdateOverride_InvalidScanProfileID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "test",
		Enabled:     true,
	})

	_, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:      tenantID.String(),
		OverrideID:    created.ID.String(),
		ScanProfileID: "bad-uuid",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_UpdateOverride_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	_, err := d.svc.UpdateOverride(ctx, app.UpdateOverrideInput{
		TenantID:   tenantID.String(),
		OverrideID: shared.NewID().String(),
	})
	if err == nil {
		t.Fatal("expected error for non-existent override")
	}
}

// --- DeleteOverride ---

func TestRuleService_DeleteOverride_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	created, _ := d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "to-delete",
		Enabled:     true,
	})

	err := d.svc.DeleteOverride(ctx, tenantID.String(), created.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(d.overrideRepo.overrides) != 0 {
		t.Errorf("expected 0 overrides, got %d", len(d.overrideRepo.overrides))
	}
}

func TestRuleService_DeleteOverride_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.DeleteOverride(ctx, shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent override")
	}
}

// --- ListActiveOverridesForTool ---

func TestRuleService_ListActiveOverridesForTool_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	_, _ = d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		RulePattern: "active-rule",
		Enabled:     true,
	})

	toolStr := toolID.String()
	overrides, err := d.svc.ListActiveOverridesForTool(ctx, tenantID.String(), &toolStr)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(overrides) != 1 {
		t.Errorf("expected 1 override, got %d", len(overrides))
	}
}

func TestRuleService_ListActiveOverridesForTool_NilToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	_, _ = d.svc.CreateOverride(ctx, app.CreateOverrideInput{
		TenantID:    tenantID.String(),
		RulePattern: "global-rule",
		Enabled:     true,
	})

	overrides, err := d.svc.ListActiveOverridesForTool(ctx, tenantID.String(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Should return overrides with nil tool ID
	_ = overrides
}

func TestRuleService_ListActiveOverridesForTool_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListActiveOverridesForTool(ctx, "bad", nil)
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListActiveOverridesForTool_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	badTool := "not-uuid"
	_, err := d.svc.ListActiveOverridesForTool(ctx, shared.NewID().String(), &badTool)
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// ============================================================================
// Bundle Lifecycle Tests
// ============================================================================

func TestRuleService_CreateBundle_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()
	sourceID := shared.NewID()

	bundle, err := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{sourceID.String()},
		StoragePath: "/bundles/test.tar.gz",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if bundle.Status != rule.BundleStatusBuilding {
		t.Errorf("expected status building, got %s", bundle.Status)
	}
	if bundle.StoragePath != "/bundles/test.tar.gz" {
		t.Errorf("expected storage path '/bundles/test.tar.gz', got %q", bundle.StoragePath)
	}
	if len(bundle.SourceIDs) != 1 {
		t.Errorf("expected 1 source ID, got %d", len(bundle.SourceIDs))
	}
}

func TestRuleService_CreateBundle_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    "bad",
		ToolID:      shared.NewID().String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateBundle_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    shared.NewID().String(),
		ToolID:      "bad",
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateBundle_InvalidSourceID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    shared.NewID().String(),
		ToolID:      shared.NewID().String(),
		SourceIDs:   []string{shared.NewID().String(), "bad-id"},
		StoragePath: "/test",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CreateBundle_RepoError(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	d.bundleRepo.createErr = errors.New("disk full")

	_, err := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    shared.NewID().String(),
		ToolID:      shared.NewID().String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// --- CompleteBundle ---

func TestRuleService_CompleteBundle_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/bundles/test.tar.gz",
	})

	completed, err := d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    bundle.ID.String(),
		Version:     "20240115-abcd1234",
		ContentHash: "abc123def456",
		RuleCount:   150,
		SourceCount: 3,
		SizeBytes:   1024 * 1024,
		SourceHashes: map[string]string{
			"src1": "hash1",
			"src2": "hash2",
		},
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if completed.Status != rule.BundleStatusReady {
		t.Errorf("expected status ready, got %s", completed.Status)
	}
	if completed.Version != "20240115-abcd1234" {
		t.Errorf("expected version '20240115-abcd1234', got %q", completed.Version)
	}
	if completed.ContentHash != "abc123def456" {
		t.Errorf("expected content hash 'abc123def456', got %q", completed.ContentHash)
	}
	if completed.RuleCount != 150 {
		t.Errorf("expected rule count 150, got %d", completed.RuleCount)
	}
	if completed.ExpiresAt == nil {
		t.Error("expected default expiration to be set")
	}
}

func TestRuleService_CompleteBundle_WithCustomExpiration(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})

	customExpires := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	completed, err := d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    bundle.ID.String(),
		Version:     "v1",
		ContentHash: "hash",
		ExpiresAt:   &customExpires,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if completed.ExpiresAt == nil {
		t.Fatal("expected custom expiration")
	}
	// Custom expiration should be approximately 30 days from now
	if completed.ExpiresAt.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Error("custom expiration should be ~30 days from now")
	}
}

func TestRuleService_CompleteBundle_InvalidBundleID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    "bad",
		Version:     "v1",
		ContentHash: "hash",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_CompleteBundle_BundleNotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    shared.NewID().String(),
		Version:     "v1",
		ContentHash: "hash",
	})
	if err == nil {
		t.Fatal("expected error for non-existent bundle")
	}
}

func TestRuleService_CompleteBundle_InvalidExpiresAt(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})

	badExpires := "not-a-date"
	_, err := d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    bundle.ID.String(),
		Version:     "v1",
		ContentHash: "hash",
		ExpiresAt:   &badExpires,
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- FailBundle ---

func TestRuleService_FailBundle_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})

	failed, err := d.svc.FailBundle(ctx, bundle.ID.String(), "compilation error: invalid YAML")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if failed.Status != rule.BundleStatusFailed {
		t.Errorf("expected status failed, got %s", failed.Status)
	}
	if failed.BuildError != "compilation error: invalid YAML" {
		t.Errorf("expected error message, got %q", failed.BuildError)
	}
}

func TestRuleService_FailBundle_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.FailBundle(ctx, "bad", "error")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_FailBundle_NotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.FailBundle(ctx, shared.NewID().String(), "error")
	if err == nil {
		t.Fatal("expected error for non-existent bundle")
	}
}

// --- GetLatestBundle ---

func TestRuleService_GetLatestBundle_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	// Create and complete a bundle
	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})
	_, _ = d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    bundle.ID.String(),
		Version:     "v1",
		ContentHash: "hash123",
	})

	latest, err := d.svc.GetLatestBundle(ctx, tenantID.String(), toolID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if latest.ID != bundle.ID {
		t.Error("latest bundle ID mismatch")
	}
}

func TestRuleService_GetLatestBundle_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetLatestBundle(ctx, "bad", shared.NewID().String())
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_GetLatestBundle_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetLatestBundle(ctx, shared.NewID().String(), "bad")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- GetBundleByID ---

func TestRuleService_GetBundleByID_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    shared.NewID().String(),
		ToolID:      shared.NewID().String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})

	got, err := d.svc.GetBundleByID(ctx, bundle.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got.ID != bundle.ID {
		t.Error("ID mismatch")
	}
}

func TestRuleService_GetBundleByID_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetBundleByID(ctx, "bad")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- ListBundles ---

func TestRuleService_ListBundles_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	for i := 0; i < 3; i++ {
		_, _ = d.svc.CreateBundle(ctx, app.CreateBundleInput{
			TenantID:    tenantID.String(),
			ToolID:      toolID.String(),
			SourceIDs:   []string{shared.NewID().String()},
			StoragePath: "/test",
		})
	}

	bundles, err := d.svc.ListBundles(ctx, app.ListBundlesInput{
		TenantID: tenantID.String(),
		ToolID:   toolID.String(),
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(bundles) != 3 {
		t.Errorf("expected 3 bundles, got %d", len(bundles))
	}
}

func TestRuleService_ListBundles_InvalidTenantID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListBundles(ctx, app.ListBundlesInput{TenantID: "bad"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListBundles_InvalidToolID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.ListBundles(ctx, app.ListBundlesInput{ToolID: "bad"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_ListBundles_WithStatusFilter(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	bundles, err := d.svc.ListBundles(ctx, app.ListBundlesInput{
		Status: "building",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	_ = bundles
}

// --- DeleteBundle ---

func TestRuleService_DeleteBundle_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    shared.NewID().String(),
		ToolID:      shared.NewID().String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})

	err := d.svc.DeleteBundle(ctx, bundle.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(d.bundleRepo.bundles) != 0 {
		t.Errorf("expected 0 bundles, got %d", len(d.bundleRepo.bundles))
	}
}

func TestRuleService_DeleteBundle_InvalidID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.DeleteBundle(ctx, "bad")
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

// --- CleanupExpiredBundles ---

func TestRuleService_CleanupExpiredBundles_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	d.bundleRepo.deleteExpired = 5

	count, err := d.svc.CleanupExpiredBundles(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 expired bundles cleaned, got %d", count)
	}
}

// --- Bundle Lifecycle: building -> ready -> expired ---

func TestRuleService_BundleLifecycle_BuildingToReady(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	// Step 1: Create (building)
	bundle, err := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    tenantID.String(),
		ToolID:      toolID.String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/bundles/lifecycle.tar.gz",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if bundle.Status != rule.BundleStatusBuilding {
		t.Errorf("expected building, got %s", bundle.Status)
	}

	// Step 2: Complete (ready)
	completed, err := d.svc.CompleteBundle(ctx, app.CompleteBundleInput{
		BundleID:    bundle.ID.String(),
		Version:     "v1.0",
		ContentHash: "abcdef1234567890",
		RuleCount:   42,
		SizeBytes:   2048,
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if completed.Status != rule.BundleStatusReady {
		t.Errorf("expected ready, got %s", completed.Status)
	}

	// Step 3: Verify it can be retrieved as latest
	latest, err := d.svc.GetLatestBundle(ctx, tenantID.String(), toolID.String())
	if err != nil {
		t.Fatalf("get latest: %v", err)
	}
	if latest.ID != bundle.ID {
		t.Error("latest bundle should be the completed one")
	}
}

func TestRuleService_BundleLifecycle_BuildingToFailed(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	bundle, _ := d.svc.CreateBundle(ctx, app.CreateBundleInput{
		TenantID:    shared.NewID().String(),
		ToolID:      shared.NewID().String(),
		SourceIDs:   []string{shared.NewID().String()},
		StoragePath: "/test",
	})

	failed, err := d.svc.FailBundle(ctx, bundle.ID.String(), "out of memory")
	if err != nil {
		t.Fatalf("fail: %v", err)
	}
	if failed.Status != rule.BundleStatusFailed {
		t.Errorf("expected failed, got %s", failed.Status)
	}
	if failed.BuildError != "out of memory" {
		t.Errorf("expected error 'out of memory', got %q", failed.BuildError)
	}
	if failed.BuildCompletedAt == nil {
		t.Error("expected build completed time to be set on failure")
	}
}

// ============================================================================
// Sync Operations Tests
// ============================================================================

func TestRuleService_RecordSyncResult_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	source, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Sync Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	result := &app.SyncResult{
		Status:         rule.SyncStatusSuccess,
		RulesAdded:     10,
		RulesUpdated:   5,
		RulesRemoved:   2,
		Duration:       3 * time.Second,
		PreviousHash:   "old-hash",
		NewContentHash: "new-hash",
	}

	err := d.svc.RecordSyncResult(ctx, source.ID.String(), result)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify source was updated
	updated := d.sourceRepo.sources[source.ID.String()]
	if updated.LastSyncStatus != rule.SyncStatusSuccess {
		t.Errorf("expected sync status success, got %s", updated.LastSyncStatus)
	}
	if updated.ContentHash != "new-hash" {
		t.Errorf("expected content hash 'new-hash', got %q", updated.ContentHash)
	}
	if updated.LastSyncAt == nil {
		t.Error("expected last sync time to be set")
	}

	// Verify sync history was recorded
	if len(d.syncHistoryRepo.entries) != 1 {
		t.Fatalf("expected 1 sync history entry, got %d", len(d.syncHistoryRepo.entries))
	}
	entry := d.syncHistoryRepo.entries[0]
	if entry.RulesAdded != 10 {
		t.Errorf("expected 10 rules added, got %d", entry.RulesAdded)
	}
	if entry.RulesUpdated != 5 {
		t.Errorf("expected 5 rules updated, got %d", entry.RulesUpdated)
	}
	if entry.RulesRemoved != 2 {
		t.Errorf("expected 2 rules removed, got %d", entry.RulesRemoved)
	}
}

func TestRuleService_RecordSyncResult_FailedSync(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	source, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "Fail Sync",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	result := &app.SyncResult{
		Status:       rule.SyncStatusFailed,
		Duration:     500 * time.Millisecond,
		ErrorMessage: "connection refused",
		ErrorDetails: map[string]any{"host": "example.com"},
	}

	err := d.svc.RecordSyncResult(ctx, source.ID.String(), result)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := d.sourceRepo.sources[source.ID.String()]
	if updated.LastSyncStatus != rule.SyncStatusFailed {
		t.Errorf("expected failed status, got %s", updated.LastSyncStatus)
	}
	if updated.LastSyncError != "connection refused" {
		t.Errorf("expected error message, got %q", updated.LastSyncError)
	}
}

func TestRuleService_RecordSyncResult_InvalidSourceID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.RecordSyncResult(ctx, "bad", &app.SyncResult{
		Status: rule.SyncStatusSuccess,
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_RecordSyncResult_SourceNotFound(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.RecordSyncResult(ctx, shared.NewID().String(), &app.SyncResult{
		Status: rule.SyncStatusSuccess,
	})
	if err == nil {
		t.Fatal("expected error for non-existent source")
	}
}

func TestRuleService_RecordSyncResult_NoContentHashUpdate(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	source, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "No Hash Update",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	// Set initial hash
	d.sourceRepo.sources[source.ID.String()].ContentHash = "original-hash"

	result := &app.SyncResult{
		Status:         rule.SyncStatusSuccess,
		NewContentHash: "", // Empty means no change
	}

	err := d.svc.RecordSyncResult(ctx, source.ID.String(), result)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	updated := d.sourceRepo.sources[source.ID.String()]
	if updated.ContentHash != "original-hash" {
		t.Errorf("expected original hash preserved, got %q", updated.ContentHash)
	}
}

// --- ListSourcesNeedingSync ---

func TestRuleService_ListSourcesNeedingSync_DefaultLimit(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	sources, err := d.svc.ListSourcesNeedingSync(ctx, 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	_ = sources // Empty is fine, just testing default limit logic
}

func TestRuleService_ListSourcesNeedingSync_WithLimit(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	// Seed some sources needing sync
	s1 := &rule.Source{ID: shared.NewID(), Name: "s1"}
	s2 := &rule.Source{ID: shared.NewID(), Name: "s2"}
	d.sourceRepo.needingSyncSources = []*rule.Source{s1, s2}

	sources, err := d.svc.ListSourcesNeedingSync(ctx, 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sources) != 1 {
		t.Errorf("expected 1 source with limit=1, got %d", len(sources))
	}
}

func TestRuleService_ListSourcesNeedingSync_NegativeLimit(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	// Negative limit should default to 10
	_, err := d.svc.ListSourcesNeedingSync(ctx, -5)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// --- GetSyncHistory ---

func TestRuleService_GetSyncHistory_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	tenantID := shared.NewID()

	source, _ := d.svc.CreateSource(ctx, app.CreateSourceInput{
		TenantID:   tenantID.String(),
		Name:       "History Test",
		SourceType: "git",
		Config:     ruleSvcValidConfig(),
	})

	// Record a few sync results
	for i := 0; i < 3; i++ {
		_ = d.svc.RecordSyncResult(ctx, source.ID.String(), &app.SyncResult{
			Status:   rule.SyncStatusSuccess,
			Duration: time.Second,
		})
	}

	history, err := d.svc.GetSyncHistory(ctx, source.ID.String(), 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(history) != 3 {
		t.Errorf("expected 3 history entries, got %d", len(history))
	}
}

func TestRuleService_GetSyncHistory_InvalidSourceID(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetSyncHistory(ctx, "bad", 10)
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestRuleService_GetSyncHistory_DefaultLimit(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	_, err := d.svc.GetSyncHistory(ctx, shared.NewID().String(), 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// --- UpsertRulesFromSync ---

func TestRuleService_UpsertRulesFromSync_Success(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	sourceID := shared.NewID()
	tenantID := shared.NewID()

	rules := []*rule.Rule{
		rule.NewRule(sourceID, tenantID, nil, "rule-1", "Rule 1", rule.SeverityCritical),
		rule.NewRule(sourceID, tenantID, nil, "rule-2", "Rule 2", rule.SeverityHigh),
		rule.NewRule(sourceID, tenantID, nil, "rule-3", "Rule 3", rule.SeverityMedium),
	}

	err := d.svc.UpsertRulesFromSync(ctx, rules)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(d.ruleRepo.rules) != 3 {
		t.Errorf("expected 3 rules upserted, got %d", len(d.ruleRepo.rules))
	}
}

func TestRuleService_UpsertRulesFromSync_EmptySlice(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.UpsertRulesFromSync(ctx, []*rule.Rule{})
	if err != nil {
		t.Fatalf("expected no error for empty slice, got %v", err)
	}
}

func TestRuleService_UpsertRulesFromSync_NilSlice(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()

	err := d.svc.UpsertRulesFromSync(ctx, nil)
	if err != nil {
		t.Fatalf("expected no error for nil slice, got %v", err)
	}
}

func TestRuleService_UpsertRulesFromSync_RepoError(t *testing.T) {
	d := newRuleSvcTestDeps()
	ctx := context.Background()
	d.ruleRepo.upsertErr = errors.New("batch insert failed")

	rules := []*rule.Rule{
		rule.NewRule(shared.NewID(), shared.NewID(), nil, "r1", "R1", rule.SeverityLow),
	}

	err := d.svc.UpsertRulesFromSync(ctx, rules)
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// ============================================================================
// Utility Function Tests
// ============================================================================

func TestComputeContentHash(t *testing.T) {
	hash := app.ComputeContentHash([]byte("hello world"))
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(hash) != 64 {
		t.Errorf("expected SHA256 hex length 64, got %d", len(hash))
	}

	// Same input should produce same hash
	hash2 := app.ComputeContentHash([]byte("hello world"))
	if hash != hash2 {
		t.Error("same input should produce same hash")
	}

	// Different input should produce different hash
	hash3 := app.ComputeContentHash([]byte("hello world!"))
	if hash == hash3 {
		t.Error("different input should produce different hash")
	}
}

func TestComputeContentHash_EmptyInput(t *testing.T) {
	hash := app.ComputeContentHash([]byte{})
	if hash == "" {
		t.Fatal("expected non-empty hash even for empty input")
	}
	if len(hash) != 64 {
		t.Errorf("expected SHA256 hex length 64, got %d", len(hash))
	}
}

func TestGenerateBundleVersion(t *testing.T) {
	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	version := app.GenerateBundleVersion(ts, "abcdef1234567890")

	expected := "20240115-abcdef12"
	if version != expected {
		t.Errorf("expected %q, got %q", expected, version)
	}
}

func TestGenerateBundleVersion_ShortHash(t *testing.T) {
	ts := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	version := app.GenerateBundleVersion(ts, "abc")

	expected := "20240601-abc"
	if version != expected {
		t.Errorf("expected %q, got %q", expected, version)
	}
}

func TestGenerateBundleVersion_ExactlyEightCharHash(t *testing.T) {
	ts := time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC)
	version := app.GenerateBundleVersion(ts, "12345678")

	expected := "20241231-12345678"
	if version != expected {
		t.Errorf("expected %q, got %q", expected, version)
	}
}
