package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/domain/toolcategory"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repositories (prefixed with toolSvc to avoid conflicts)
// ============================================================================

// toolSvcMockToolRepo implements tool.Repository for testing.
type toolSvcMockToolRepo struct {
	tools map[string]*tool.Tool
}

func newToolSvcMockToolRepo() *toolSvcMockToolRepo {
	return &toolSvcMockToolRepo{
		tools: make(map[string]*tool.Tool),
	}
}

func (m *toolSvcMockToolRepo) Create(_ context.Context, t *tool.Tool) error {
	// Check for duplicate name
	for _, existing := range m.tools {
		if existing.Name == t.Name {
			return fmt.Errorf("%w: tool with name %s already exists", shared.ErrConflict, t.Name)
		}
	}
	m.tools[t.ID.String()] = t
	return nil
}

func (m *toolSvcMockToolRepo) GetByID(_ context.Context, id shared.ID) (*tool.Tool, error) {
	t, ok := m.tools[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *toolSvcMockToolRepo) GetByName(_ context.Context, name string) (*tool.Tool, error) {
	for _, t := range m.tools {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *toolSvcMockToolRepo) List(_ context.Context, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	var result []*tool.Tool
	for _, t := range m.tools {
		if !m.matchesFilter(t, filter) {
			continue
		}
		result = append(result, t)
	}
	total := int64(len(result))
	return pagination.Result[*tool.Tool]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockToolRepo) ListByNames(_ context.Context, names []string) ([]*tool.Tool, error) {
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	var result []*tool.Tool
	for _, t := range m.tools {
		if nameSet[t.Name] {
			result = append(result, t)
		}
	}
	return result, nil
}

func (m *toolSvcMockToolRepo) ListByCategoryID(_ context.Context, categoryID shared.ID) ([]*tool.Tool, error) {
	var result []*tool.Tool
	for _, t := range m.tools {
		if t.CategoryID != nil && *t.CategoryID == categoryID {
			result = append(result, t)
		}
	}
	return result, nil
}

func (m *toolSvcMockToolRepo) ListByCategoryName(_ context.Context, categoryName string) ([]*tool.Tool, error) {
	// Simplified: we don't have category names in the mock, return empty
	return []*tool.Tool{}, nil
}

func (m *toolSvcMockToolRepo) ListByCapability(_ context.Context, capability string) ([]*tool.Tool, error) {
	var result []*tool.Tool
	for _, t := range m.tools {
		if t.HasCapability(capability) {
			result = append(result, t)
		}
	}
	return result, nil
}

func (m *toolSvcMockToolRepo) FindByCapabilities(_ context.Context, _ shared.ID, capabilities []string) (*tool.Tool, error) {
	for _, t := range m.tools {
		if !t.IsActive {
			continue
		}
		hasAll := true
		for _, cap := range capabilities {
			if !t.HasCapability(cap) {
				hasAll = false
				break
			}
		}
		if hasAll {
			return t, nil
		}
	}
	return nil, nil
}

func (m *toolSvcMockToolRepo) Update(_ context.Context, t *tool.Tool) error {
	if _, ok := m.tools[t.ID.String()]; !ok {
		return shared.ErrNotFound
	}
	m.tools[t.ID.String()] = t
	return nil
}

func (m *toolSvcMockToolRepo) Delete(_ context.Context, id shared.ID) error {
	if _, ok := m.tools[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.tools, id.String())
	return nil
}

func (m *toolSvcMockToolRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*tool.Tool, error) {
	t, ok := m.tools[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if t.TenantID == nil || *t.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *toolSvcMockToolRepo) GetByTenantAndName(_ context.Context, tenantID shared.ID, name string) (*tool.Tool, error) {
	for _, t := range m.tools {
		if t.Name == name && t.TenantID != nil && *t.TenantID == tenantID {
			return t, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *toolSvcMockToolRepo) GetPlatformToolByName(_ context.Context, name string) (*tool.Tool, error) {
	for _, t := range m.tools {
		if t.Name == name && t.TenantID == nil {
			return t, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *toolSvcMockToolRepo) ListPlatformTools(_ context.Context, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	var result []*tool.Tool
	for _, t := range m.tools {
		if t.TenantID != nil {
			continue
		}
		if !m.matchesFilter(t, filter) {
			continue
		}
		result = append(result, t)
	}
	total := int64(len(result))
	return pagination.Result[*tool.Tool]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockToolRepo) ListTenantCustomTools(_ context.Context, tenantID shared.ID, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	var result []*tool.Tool
	for _, t := range m.tools {
		if t.TenantID == nil || *t.TenantID != tenantID {
			continue
		}
		if !m.matchesFilter(t, filter) {
			continue
		}
		result = append(result, t)
	}
	total := int64(len(result))
	return pagination.Result[*tool.Tool]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockToolRepo) ListAvailableTools(_ context.Context, tenantID shared.ID, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	var result []*tool.Tool
	for _, t := range m.tools {
		// Platform tools or tenant's own custom tools
		if t.TenantID == nil || *t.TenantID == tenantID {
			if m.matchesFilter(t, filter) {
				result = append(result, t)
			}
		}
	}
	total := int64(len(result))
	return pagination.Result[*tool.Tool]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockToolRepo) DeleteTenantTool(_ context.Context, tenantID, id shared.ID) error {
	t, ok := m.tools[id.String()]
	if !ok {
		return shared.ErrNotFound
	}
	if t.TenantID == nil || *t.TenantID != tenantID {
		return shared.ErrNotFound
	}
	delete(m.tools, id.String())
	return nil
}

func (m *toolSvcMockToolRepo) BulkCreate(_ context.Context, tools []*tool.Tool) error {
	for _, t := range tools {
		m.tools[t.ID.String()] = t
	}
	return nil
}

func (m *toolSvcMockToolRepo) BulkUpdateVersions(_ context.Context, versions map[shared.ID]tool.VersionInfo) error {
	for id, v := range versions {
		if t, ok := m.tools[id.String()]; ok {
			t.CurrentVersion = v.CurrentVersion
			t.LatestVersion = v.LatestVersion
		}
	}
	return nil
}

func (m *toolSvcMockToolRepo) Count(_ context.Context, _ tool.ToolFilter) (int64, error) {
	return int64(len(m.tools)), nil
}

func (m *toolSvcMockToolRepo) GetAllCapabilities(_ context.Context) ([]string, error) {
	capSet := make(map[string]bool)
	for _, t := range m.tools {
		for _, c := range t.Capabilities {
			capSet[c] = true
		}
	}
	var caps []string
	for c := range capSet {
		caps = append(caps, c)
	}
	return caps, nil
}

func (m *toolSvcMockToolRepo) matchesFilter(t *tool.Tool, filter tool.ToolFilter) bool {
	if filter.IsActive != nil && t.IsActive != *filter.IsActive {
		return false
	}
	if filter.IsBuiltin != nil && t.IsBuiltin != *filter.IsBuiltin {
		return false
	}
	if filter.Search != "" {
		// Simplified search
		if t.Name != filter.Search && t.DisplayName != filter.Search {
			return false
		}
	}
	return true
}

// AddTool adds a tool directly to the mock (for test setup).
func (m *toolSvcMockToolRepo) AddTool(t *tool.Tool) {
	m.tools[t.ID.String()] = t
}

// toolSvcMockConfigRepo implements tool.TenantToolConfigRepository for testing.
type toolSvcMockConfigRepo struct {
	configs map[string]*tool.TenantToolConfig
}

func newToolSvcMockConfigRepo() *toolSvcMockConfigRepo {
	return &toolSvcMockConfigRepo{
		configs: make(map[string]*tool.TenantToolConfig),
	}
}

func (m *toolSvcMockConfigRepo) Create(_ context.Context, config *tool.TenantToolConfig) error {
	m.configs[config.ID.String()] = config
	return nil
}

func (m *toolSvcMockConfigRepo) GetByID(_ context.Context, id shared.ID) (*tool.TenantToolConfig, error) {
	c, ok := m.configs[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *toolSvcMockConfigRepo) GetByTenantAndTool(_ context.Context, tenantID, toolID shared.ID) (*tool.TenantToolConfig, error) {
	for _, c := range m.configs {
		if c.TenantID == tenantID && c.ToolID == toolID {
			return c, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *toolSvcMockConfigRepo) List(_ context.Context, filter tool.TenantToolConfigFilter, page pagination.Pagination) (pagination.Result[*tool.TenantToolConfig], error) {
	var result []*tool.TenantToolConfig
	for _, c := range m.configs {
		if c.TenantID != filter.TenantID {
			continue
		}
		if filter.ToolID != nil && c.ToolID != *filter.ToolID {
			continue
		}
		if filter.IsEnabled != nil && c.IsEnabled != *filter.IsEnabled {
			continue
		}
		result = append(result, c)
	}
	total := int64(len(result))
	return pagination.Result[*tool.TenantToolConfig]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockConfigRepo) Update(_ context.Context, config *tool.TenantToolConfig) error {
	if _, ok := m.configs[config.ID.String()]; !ok {
		return shared.ErrNotFound
	}
	m.configs[config.ID.String()] = config
	return nil
}

func (m *toolSvcMockConfigRepo) Delete(_ context.Context, id shared.ID) error {
	if _, ok := m.configs[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.configs, id.String())
	return nil
}

func (m *toolSvcMockConfigRepo) Upsert(_ context.Context, config *tool.TenantToolConfig) error {
	m.configs[config.ID.String()] = config
	return nil
}

func (m *toolSvcMockConfigRepo) GetEffectiveConfig(_ context.Context, _, _ shared.ID) (map[string]any, error) {
	return map[string]any{}, nil
}

func (m *toolSvcMockConfigRepo) ListEnabledTools(_ context.Context, tenantID shared.ID) ([]*tool.TenantToolConfig, error) {
	var result []*tool.TenantToolConfig
	for _, c := range m.configs {
		if c.TenantID == tenantID && c.IsEnabled {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *toolSvcMockConfigRepo) ListToolsWithConfig(_ context.Context, _ shared.ID, _ tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.ToolWithConfig], error) {
	return pagination.Result[*tool.ToolWithConfig]{
		Data:       []*tool.ToolWithConfig{},
		Total:      0,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: 0,
	}, nil
}

func (m *toolSvcMockConfigRepo) BulkEnable(_ context.Context, tenantID shared.ID, toolIDs []shared.ID) error {
	for _, tid := range toolIDs {
		for _, c := range m.configs {
			if c.TenantID == tenantID && c.ToolID == tid {
				c.IsEnabled = true
			}
		}
	}
	return nil
}

func (m *toolSvcMockConfigRepo) BulkDisable(_ context.Context, tenantID shared.ID, toolIDs []shared.ID) error {
	for _, tid := range toolIDs {
		for _, c := range m.configs {
			if c.TenantID == tenantID && c.ToolID == tid {
				c.IsEnabled = false
			}
		}
	}
	return nil
}

// toolSvcMockExecutionRepo implements tool.ToolExecutionRepository for testing.
type toolSvcMockExecutionRepo struct {
	executions map[string]*tool.ToolExecution
}

func newToolSvcMockExecutionRepo() *toolSvcMockExecutionRepo {
	return &toolSvcMockExecutionRepo{
		executions: make(map[string]*tool.ToolExecution),
	}
}

func (m *toolSvcMockExecutionRepo) Create(_ context.Context, exec *tool.ToolExecution) error {
	m.executions[exec.ID.String()] = exec
	return nil
}

func (m *toolSvcMockExecutionRepo) GetByID(_ context.Context, id shared.ID) (*tool.ToolExecution, error) {
	e, ok := m.executions[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return e, nil
}

func (m *toolSvcMockExecutionRepo) List(_ context.Context, filter tool.ToolExecutionFilter, page pagination.Pagination) (pagination.Result[*tool.ToolExecution], error) {
	var result []*tool.ToolExecution
	for _, e := range m.executions {
		if e.TenantID != filter.TenantID {
			continue
		}
		if filter.ToolID != nil && e.ToolID != *filter.ToolID {
			continue
		}
		if filter.Status != nil && e.Status != *filter.Status {
			continue
		}
		result = append(result, e)
	}
	total := int64(len(result))
	return pagination.Result[*tool.ToolExecution]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockExecutionRepo) Update(_ context.Context, exec *tool.ToolExecution) error {
	if _, ok := m.executions[exec.ID.String()]; !ok {
		return shared.ErrNotFound
	}
	m.executions[exec.ID.String()] = exec
	return nil
}

func (m *toolSvcMockExecutionRepo) GetToolStats(_ context.Context, _ shared.ID, toolID shared.ID, _ int) (*tool.ToolStats, error) {
	return &tool.ToolStats{ToolID: toolID}, nil
}

func (m *toolSvcMockExecutionRepo) GetTenantStats(_ context.Context, tenantID shared.ID, _ int) (*tool.TenantToolStats, error) {
	return &tool.TenantToolStats{TenantID: tenantID}, nil
}

// toolSvcMockAgentRepo is a minimal mock for agent.Repository.
type toolSvcMockAgentRepo struct {
	availableTools []string
}

func newToolSvcMockAgentRepo() *toolSvcMockAgentRepo {
	return &toolSvcMockAgentRepo{}
}

func (m *toolSvcMockAgentRepo) Create(_ context.Context, _ *agent.Agent) error { return nil }
func (m *toolSvcMockAgentRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *toolSvcMockAgentRepo) GetByID(_ context.Context, _ shared.ID) (*agent.Agent, error) {
	return nil, shared.ErrNotFound
}
func (m *toolSvcMockAgentRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*agent.Agent, error) {
	return nil, shared.ErrNotFound
}
func (m *toolSvcMockAgentRepo) GetByAPIKeyHash(_ context.Context, _ string) (*agent.Agent, error) {
	return nil, shared.ErrNotFound
}
func (m *toolSvcMockAgentRepo) List(_ context.Context, _ agent.Filter, _ pagination.Pagination) (pagination.Result[*agent.Agent], error) {
	return pagination.Result[*agent.Agent]{}, nil
}
func (m *toolSvcMockAgentRepo) Update(_ context.Context, _ *agent.Agent) error { return nil }
func (m *toolSvcMockAgentRepo) Delete(_ context.Context, _ shared.ID) error    { return nil }
func (m *toolSvcMockAgentRepo) UpdateLastSeen(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *toolSvcMockAgentRepo) IncrementStats(_ context.Context, _ shared.ID, _, _, _ int64) error {
	return nil
}
func (m *toolSvcMockAgentRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *toolSvcMockAgentRepo) FindAvailable(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *toolSvcMockAgentRepo) FindAvailableWithTool(_ context.Context, _ shared.ID, _ string) (*agent.Agent, error) {
	return nil, shared.ErrNotFound
}
func (m *toolSvcMockAgentRepo) MarkStaleAsOffline(_ context.Context, _ time.Duration) (int64, error) {
	return 0, nil
}
func (m *toolSvcMockAgentRepo) FindAvailableWithCapacity(_ context.Context, _ shared.ID, _ []string, _ string) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *toolSvcMockAgentRepo) ClaimJob(_ context.Context, _ shared.ID) error   { return nil }
func (m *toolSvcMockAgentRepo) ReleaseJob(_ context.Context, _ shared.ID) error { return nil }
func (m *toolSvcMockAgentRepo) UpdateOfflineTimestamp(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *toolSvcMockAgentRepo) MarkStaleAgentsOffline(_ context.Context, _ time.Duration) ([]shared.ID, error) {
	return nil, nil
}
func (m *toolSvcMockAgentRepo) GetAgentsOfflineSince(_ context.Context, _ time.Time) ([]*agent.Agent, error) {
	return nil, nil
}
func (m *toolSvcMockAgentRepo) GetAvailableToolsForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return m.availableTools, nil
}
func (m *toolSvcMockAgentRepo) HasAgentForTool(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *toolSvcMockAgentRepo) GetAvailableCapabilitiesForTenant(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *toolSvcMockAgentRepo) HasAgentForCapability(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *toolSvcMockAgentRepo) GetPlatformAgentStats(_ context.Context, _ shared.ID) (*agent.PlatformAgentStatsResult, error) {
	return nil, nil
}

// toolSvcMockCategoryRepo is a minimal mock for toolcategory.Repository.
type toolSvcMockCategoryRepo struct {
	categories map[string]*toolcategory.ToolCategory
}

func newToolSvcMockCategoryRepo() *toolSvcMockCategoryRepo {
	return &toolSvcMockCategoryRepo{
		categories: make(map[string]*toolcategory.ToolCategory),
	}
}

func (m *toolSvcMockCategoryRepo) Create(_ context.Context, cat *toolcategory.ToolCategory) error {
	m.categories[cat.ID.String()] = cat
	return nil
}

func (m *toolSvcMockCategoryRepo) GetByID(_ context.Context, id shared.ID) (*toolcategory.ToolCategory, error) {
	c, ok := m.categories[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *toolSvcMockCategoryRepo) GetByName(_ context.Context, _ *shared.ID, name string) (*toolcategory.ToolCategory, error) {
	for _, c := range m.categories {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *toolSvcMockCategoryRepo) List(_ context.Context, _ toolcategory.Filter, page pagination.Pagination) (pagination.Result[*toolcategory.ToolCategory], error) {
	var result []*toolcategory.ToolCategory
	for _, c := range m.categories {
		result = append(result, c)
	}
	total := int64(len(result))
	return pagination.Result[*toolcategory.ToolCategory]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *toolSvcMockCategoryRepo) Update(_ context.Context, cat *toolcategory.ToolCategory) error {
	m.categories[cat.ID.String()] = cat
	return nil
}

func (m *toolSvcMockCategoryRepo) Delete(_ context.Context, id shared.ID) error {
	delete(m.categories, id.String())
	return nil
}

func (m *toolSvcMockCategoryRepo) ExistsByName(_ context.Context, _ *shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *toolSvcMockCategoryRepo) ListAll(_ context.Context, _ *shared.ID) ([]*toolcategory.ToolCategory, error) {
	var result []*toolcategory.ToolCategory
	for _, c := range m.categories {
		result = append(result, c)
	}
	return result, nil
}

func (m *toolSvcMockCategoryRepo) CountByTenant(_ context.Context, _ shared.ID) (int64, error) {
	return int64(len(m.categories)), nil
}

// AddCategory adds a category directly to the mock.
func (m *toolSvcMockCategoryRepo) AddCategory(cat *toolcategory.ToolCategory) {
	m.categories[cat.ID.String()] = cat
}

// toolSvcMockPipelineDeactivator implements app.PipelineDeactivator for testing.
type toolSvcMockPipelineDeactivator struct {
	deactivatedCount int
	deactivatedIDs   []shared.ID
	err              error
	calledWith       string // tracks the tool name passed to DeactivatePipelinesByTool
}

func newToolSvcMockPipelineDeactivator() *toolSvcMockPipelineDeactivator {
	return &toolSvcMockPipelineDeactivator{}
}

func (m *toolSvcMockPipelineDeactivator) DeactivatePipelinesByTool(_ context.Context, toolName string) (int, []shared.ID, error) {
	m.calledWith = toolName
	if m.err != nil {
		return 0, nil, m.err
	}
	return m.deactivatedCount, m.deactivatedIDs, nil
}

func (m *toolSvcMockPipelineDeactivator) GetPipelinesUsingTool(_ context.Context, _ string) ([]shared.ID, error) {
	return m.deactivatedIDs, m.err
}

// ============================================================================
// Test Helpers
// ============================================================================

func newToolSvcTestService() (*app.ToolService, *toolSvcMockToolRepo, *toolSvcMockConfigRepo, *toolSvcMockExecutionRepo) {
	toolRepo := newToolSvcMockToolRepo()
	configRepo := newToolSvcMockConfigRepo()
	execRepo := newToolSvcMockExecutionRepo()
	log := logger.NewDevelopment()
	svc := app.NewToolService(toolRepo, configRepo, execRepo, log)
	return svc, toolRepo, configRepo, execRepo
}

func newToolSvcTestServiceFull() (*app.ToolService, *toolSvcMockToolRepo, *toolSvcMockConfigRepo, *toolSvcMockExecutionRepo, *toolSvcMockPipelineDeactivator) {
	svc, toolRepo, configRepo, execRepo := newToolSvcTestService()
	deactivator := newToolSvcMockPipelineDeactivator()
	svc.SetPipelineDeactivator(deactivator)
	return svc, toolRepo, configRepo, execRepo, deactivator
}

func createPlatformTool(name string, installMethod tool.InstallMethod) *tool.Tool {
	t, _ := tool.NewTool(name, name, nil, installMethod)
	return t
}

func createTenantTool(tenantID shared.ID, name string, installMethod tool.InstallMethod) *tool.Tool {
	createdBy := shared.NewID()
	t, _ := tool.NewTenantCustomTool(tenantID, createdBy, name, name, nil, installMethod)
	return t
}

// ============================================================================
// Tests: CreateTool (System/Platform)
// ============================================================================

func TestToolService_CreateTool_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateToolInput{
		Name:          "nuclei",
		DisplayName:   "Nuclei",
		Description:   "Fast vulnerability scanner",
		InstallMethod: "go",
		InstallCmd:    "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		Capabilities:  []string{"vuln-scan", "web-scan"},
		Tags:          []string{"scanner", "web"},
	}

	result, err := svc.CreateTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Name != "nuclei" {
		t.Errorf("expected name nuclei, got %s", result.Name)
	}
	if result.DisplayName != "Nuclei" {
		t.Errorf("expected display name Nuclei, got %s", result.DisplayName)
	}
	if result.InstallMethod != tool.InstallGo {
		t.Errorf("expected install method go, got %s", result.InstallMethod)
	}
	if !result.IsActive {
		t.Error("expected tool to be active by default")
	}
	if !result.IsBuiltin {
		t.Error("expected tool to be builtin (platform)")
	}
	if result.TenantID != nil {
		t.Error("expected platform tool to have nil TenantID")
	}
	if len(result.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(result.Capabilities))
	}
}

func TestToolService_CreateTool_AllInstallMethods(t *testing.T) {
	methods := []string{"go", "pip", "npm", "docker", "binary"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			svc, _, _, _ := newToolSvcTestService()

			input := app.CreateToolInput{
				Name:          "tool-" + method,
				InstallMethod: method,
			}

			result, err := svc.CreateTool(context.Background(), input)
			if err != nil {
				t.Fatalf("expected no error for method %s, got %v", method, err)
			}
			if string(result.InstallMethod) != method {
				t.Errorf("expected install method %s, got %s", method, result.InstallMethod)
			}
		})
	}
}

func TestToolService_CreateTool_InvalidInstallMethod(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateToolInput{
		Name:          "bad-tool",
		InstallMethod: "invalid",
	}

	_, err := svc.CreateTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid install method")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestToolService_CreateTool_EmptyName(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateToolInput{
		Name:          "",
		InstallMethod: "go",
	}

	_, err := svc.CreateTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestToolService_CreateTool_WithCategoryID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	catID := shared.NewID()

	input := app.CreateToolInput{
		Name:          "semgrep",
		InstallMethod: "pip",
		CategoryID:    catID.String(),
	}

	result, err := svc.CreateTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CategoryID == nil || *result.CategoryID != catID {
		t.Error("expected category ID to be set")
	}
}

func TestToolService_CreateTool_InvalidCategoryID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateToolInput{
		Name:          "semgrep",
		InstallMethod: "pip",
		CategoryID:    "not-a-uuid",
	}

	_, err := svc.CreateTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid category ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestToolService_CreateTool_WithOptionalFields(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateToolInput{
		Name:             "nuclei",
		InstallMethod:    "go",
		ConfigSchema:     map[string]any{"type": "object"},
		DefaultConfig:    map[string]any{"severity": "high"},
		SupportedTargets: []string{"url", "domain"},
		OutputFormats:    []string{"json", "sarif"},
		DocsURL:          "https://docs.example.com",
		GithubURL:        "https://github.com/example/tool",
		LogoURL:          "https://example.com/logo.png",
	}

	result, err := svc.CreateTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.SupportedTargets) != 2 {
		t.Errorf("expected 2 supported targets, got %d", len(result.SupportedTargets))
	}
	if result.DocsURL != "https://docs.example.com" {
		t.Errorf("expected docs URL to be set, got %s", result.DocsURL)
	}
}

// ============================================================================
// Tests: GetTool
// ============================================================================

func TestToolService_GetTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	result, err := svc.GetTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "nuclei" {
		t.Errorf("expected name nuclei, got %s", result.Name)
	}
}

func TestToolService_GetTool_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetTool(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestToolService_GetTool_InvalidID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetTool(context.Background(), "invalid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// ============================================================================
// Tests: GetToolByName
// ============================================================================

func TestToolService_GetToolByName_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	result, err := svc.GetToolByName(context.Background(), "nuclei")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID != existing.ID {
		t.Errorf("expected same tool ID")
	}
}

func TestToolService_GetToolByName_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetToolByName(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_GetToolByName_EmptyName(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetToolByName(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// ============================================================================
// Tests: ListTools
// ============================================================================

func TestToolService_ListTools_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	repo.AddTool(createPlatformTool("nuclei", tool.InstallGo))
	repo.AddTool(createPlatformTool("semgrep", tool.InstallPip))
	repo.AddTool(createPlatformTool("trivy", tool.InstallBinary))

	input := app.ListToolsInput{
		Page:    1,
		PerPage: 10,
	}

	result, err := svc.ListTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 tools, got %d", result.Total)
	}
}

func TestToolService_ListTools_FilterByActive(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	active := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(active)

	inactive := createPlatformTool("old-tool", tool.InstallBinary)
	inactive.Deactivate()
	repo.AddTool(inactive)

	isActive := true
	input := app.ListToolsInput{
		IsActive: &isActive,
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 active tool, got %d", result.Total)
	}
}

// ============================================================================
// Tests: ListToolsByCategory
// ============================================================================

func TestToolService_ListToolsByCategory_EmptyCategory(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.ListToolsByCategory(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty category")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestToolService_ListToolsByCategory_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	result, err := svc.ListToolsByCategory(context.Background(), "sast")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Mock returns empty for category name
	if len(result) != 0 {
		t.Errorf("expected 0 tools (mock), got %d", len(result))
	}
}

// ============================================================================
// Tests: ListToolsByCapability
// ============================================================================

func TestToolService_ListToolsByCapability_EmptyCapability(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.ListToolsByCapability(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty capability")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestToolService_ListToolsByCapability_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	nuclei := createPlatformTool("nuclei", tool.InstallGo)
	nuclei.Capabilities = []string{"vuln-scan", "web-scan"}
	repo.AddTool(nuclei)

	semgrep := createPlatformTool("semgrep", tool.InstallPip)
	semgrep.Capabilities = []string{"sast", "code-scan"}
	repo.AddTool(semgrep)

	result, err := svc.ListToolsByCapability(context.Background(), "vuln-scan")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 tool with vuln-scan, got %d", len(result))
	}
	if len(result) > 0 && result[0].Name != "nuclei" {
		t.Errorf("expected nuclei, got %s", result[0].Name)
	}
}

// ============================================================================
// Tests: UpdateTool
// ============================================================================

func TestToolService_UpdateTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	input := app.UpdateToolInput{
		ToolID:      existing.ID.String(),
		DisplayName: "Nuclei v3",
		Description: "Updated description",
		InstallCmd:  "go install nuclei@latest",
		Tags:        []string{"updated"},
	}

	result, err := svc.UpdateTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.DisplayName != "Nuclei v3" {
		t.Errorf("expected display name Nuclei v3, got %s", result.DisplayName)
	}
	if result.Description != "Updated description" {
		t.Errorf("expected updated description, got %s", result.Description)
	}
	if len(result.Tags) != 1 || result.Tags[0] != "updated" {
		t.Errorf("expected tags [updated], got %v", result.Tags)
	}
}

func TestToolService_UpdateTool_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.UpdateToolInput{
		ToolID:      shared.NewID().String(),
		DisplayName: "Updated",
	}

	_, err := svc.UpdateTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_UpdateTool_InvalidID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.UpdateToolInput{
		ToolID:      "bad-id",
		DisplayName: "Updated",
	}

	_, err := svc.UpdateTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
}

func TestToolService_UpdateTool_Capabilities(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	existing.Capabilities = []string{"old-cap"}
	repo.AddTool(existing)

	input := app.UpdateToolInput{
		ToolID:       existing.ID.String(),
		Capabilities: []string{"new-cap1", "new-cap2"},
	}

	result, err := svc.UpdateTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(result.Capabilities))
	}
}

// ============================================================================
// Tests: DeleteTool
// ============================================================================

func TestToolService_DeleteTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	// Create a non-builtin tool (custom tool without tenant)
	existing := createPlatformTool("custom-scanner", tool.InstallBinary)
	existing.IsBuiltin = false
	repo.AddTool(existing)

	err := svc.DeleteTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	_, err = repo.GetByID(context.Background(), existing.ID)
	if err == nil {
		t.Error("expected tool to be deleted")
	}
}

func TestToolService_DeleteTool_BuiltinFails(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	builtin := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(builtin)

	err := svc.DeleteTool(context.Background(), builtin.ID.String())
	if err == nil {
		t.Fatal("expected error when deleting builtin tool")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestToolService_DeleteTool_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	err := svc.DeleteTool(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_DeleteTool_CascadeDeactivation(t *testing.T) {
	svc, repo, _, _, deactivator := newToolSvcTestServiceFull()

	existing := createPlatformTool("custom-scanner", tool.InstallBinary)
	existing.IsBuiltin = false
	repo.AddTool(existing)

	pipelineID := shared.NewID()
	deactivator.deactivatedCount = 2
	deactivator.deactivatedIDs = []shared.ID{pipelineID, shared.NewID()}

	err := svc.DeleteTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deactivator.calledWith != "custom-scanner" {
		t.Errorf("expected deactivator called with custom-scanner, got %s", deactivator.calledWith)
	}
}

func TestToolService_DeleteTool_CascadeDeactivationError(t *testing.T) {
	svc, repo, _, _, deactivator := newToolSvcTestServiceFull()

	existing := createPlatformTool("custom-scanner", tool.InstallBinary)
	existing.IsBuiltin = false
	repo.AddTool(existing)

	deactivator.err = fmt.Errorf("pipeline service error")

	// Should still succeed - cascade errors are logged but don't fail the deletion
	err := svc.DeleteTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error despite cascade failure, got %v", err)
	}
}

// ============================================================================
// Tests: ActivateTool
// ============================================================================

func TestToolService_ActivateTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	existing.Deactivate()
	repo.AddTool(existing)

	if existing.IsActive {
		t.Fatal("precondition: tool should be inactive")
	}

	result, err := svc.ActivateTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsActive {
		t.Error("expected tool to be active after activation")
	}
}

func TestToolService_ActivateTool_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.ActivateTool(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_ActivateTool_AlreadyActive(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing) // already active

	result, err := svc.ActivateTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsActive {
		t.Error("expected tool to remain active")
	}
}

// ============================================================================
// Tests: DeactivateTool
// ============================================================================

func TestToolService_DeactivateTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	result, err := svc.DeactivateTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.IsActive {
		t.Error("expected tool to be inactive after deactivation")
	}
}

func TestToolService_DeactivateTool_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.DeactivateTool(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_DeactivateTool_CascadeDeactivation(t *testing.T) {
	svc, repo, _, _, deactivator := newToolSvcTestServiceFull()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	deactivator.deactivatedCount = 3
	deactivator.deactivatedIDs = []shared.ID{shared.NewID(), shared.NewID(), shared.NewID()}

	result, err := svc.DeactivateTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.IsActive {
		t.Error("expected tool to be inactive")
	}
	if deactivator.calledWith != "nuclei" {
		t.Errorf("expected deactivator called with nuclei, got %s", deactivator.calledWith)
	}
}

func TestToolService_DeactivateTool_CascadeError(t *testing.T) {
	svc, repo, _, _, deactivator := newToolSvcTestServiceFull()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	deactivator.err = fmt.Errorf("pipeline error")

	// Should still deactivate the tool - cascade errors don't block
	result, err := svc.DeactivateTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error despite cascade failure, got %v", err)
	}
	if result.IsActive {
		t.Error("expected tool to be inactive despite cascade error")
	}
}

func TestToolService_DeactivateTool_NoPipelineDeactivator(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	// No pipeline deactivator set

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	result, err := svc.DeactivateTool(context.Background(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error without deactivator, got %v", err)
	}
	if result.IsActive {
		t.Error("expected tool to be inactive")
	}
}

// ============================================================================
// Tests: UpdateToolVersion
// ============================================================================

func TestToolService_UpdateToolVersion_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	input := app.UpdateToolVersionInput{
		ToolID:         existing.ID.String(),
		CurrentVersion: "3.1.0",
		LatestVersion:  "3.2.0",
	}

	result, err := svc.UpdateToolVersion(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CurrentVersion != "3.1.0" {
		t.Errorf("expected current version 3.1.0, got %s", result.CurrentVersion)
	}
	if result.LatestVersion != "3.2.0" {
		t.Errorf("expected latest version 3.2.0, got %s", result.LatestVersion)
	}
	if !result.HasUpdateAvailable() {
		t.Error("expected update to be available")
	}
}

func TestToolService_UpdateToolVersion_SameVersion(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()

	existing := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(existing)

	input := app.UpdateToolVersionInput{
		ToolID:         existing.ID.String(),
		CurrentVersion: "3.1.0",
		LatestVersion:  "3.1.0",
	}

	result, err := svc.UpdateToolVersion(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.HasUpdateAvailable() {
		t.Error("expected no update available when versions match")
	}
}

func TestToolService_UpdateToolVersion_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.UpdateToolVersionInput{
		ToolID:         shared.NewID().String(),
		CurrentVersion: "1.0.0",
		LatestVersion:  "2.0.0",
	}

	_, err := svc.UpdateToolVersion(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

// ============================================================================
// Tests: CreateCustomTool (Tenant)
// ============================================================================

func TestToolService_CreateCustomTool_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	input := app.CreateCustomToolInput{
		TenantID:      tenantID.String(),
		CreatedBy:     userID.String(),
		Name:          "my-scanner",
		DisplayName:   "My Scanner",
		Description:   "Custom scanner",
		InstallMethod: "docker",
		Capabilities:  []string{"custom-scan"},
	}

	result, err := svc.CreateCustomTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "my-scanner" {
		t.Errorf("expected name my-scanner, got %s", result.Name)
	}
	if !result.IsCustomTool() {
		t.Error("expected custom tool (non-nil TenantID)")
	}
	if result.TenantID == nil || *result.TenantID != tenantID {
		t.Error("expected tool to belong to tenant")
	}
	if result.IsBuiltin {
		t.Error("expected custom tool to not be builtin")
	}
}

func TestToolService_CreateCustomTool_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateCustomToolInput{
		TenantID:      "invalid-uuid",
		Name:          "my-scanner",
		InstallMethod: "docker",
	}

	_, err := svc.CreateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestToolService_CreateCustomTool_InvalidCreatedBy(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.CreateCustomToolInput{
		TenantID:      tenantID.String(),
		CreatedBy:     "bad-uuid",
		Name:          "my-scanner",
		InstallMethod: "docker",
	}

	_, err := svc.CreateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid created_by")
	}
}

func TestToolService_CreateCustomTool_InvalidInstallMethod(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.CreateCustomToolInput{
		TenantID:      tenantID.String(),
		Name:          "my-scanner",
		InstallMethod: "bad",
	}

	_, err := svc.CreateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid install method")
	}
}

func TestToolService_CreateCustomTool_WithCategoryID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	catID := shared.NewID()

	input := app.CreateCustomToolInput{
		TenantID:      tenantID.String(),
		Name:          "my-scanner",
		InstallMethod: "docker",
		CategoryID:    catID.String(),
	}

	result, err := svc.CreateCustomTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.CategoryID == nil || *result.CategoryID != catID {
		t.Error("expected category ID to be set")
	}
}

func TestToolService_CreateCustomTool_InvalidCategoryID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.CreateCustomToolInput{
		TenantID:      tenantID.String(),
		Name:          "my-scanner",
		InstallMethod: "docker",
		CategoryID:    "not-uuid",
	}

	_, err := svc.CreateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid category ID")
	}
}

func TestToolService_CreateCustomTool_NoCreatedBy(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.CreateCustomToolInput{
		TenantID:      tenantID.String(),
		Name:          "my-scanner",
		InstallMethod: "docker",
		// CreatedBy is empty - should still work
	}

	result, err := svc.CreateCustomTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "my-scanner" {
		t.Errorf("expected name my-scanner, got %s", result.Name)
	}
}

// ============================================================================
// Tests: GetCustomTool
// ============================================================================

func TestToolService_GetCustomTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	result, err := svc.GetCustomTool(context.Background(), tenantID.String(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "my-scanner" {
		t.Errorf("expected name my-scanner, got %s", result.Name)
	}
}

func TestToolService_GetCustomTool_WrongTenant(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	existing := createTenantTool(tenant1, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	_, err := svc.GetCustomTool(context.Background(), tenant2.String(), existing.ID.String())
	if err == nil {
		t.Fatal("expected error when accessing another tenant's tool")
	}
}

func TestToolService_GetCustomTool_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetCustomTool(context.Background(), "bad-uuid", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_GetCustomTool_InvalidToolID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetCustomTool(context.Background(), shared.NewID().String(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tool ID")
	}
}

// ============================================================================
// Tests: ListPlatformTools
// ============================================================================

func TestToolService_ListPlatformTools_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	repo.AddTool(createPlatformTool("nuclei", tool.InstallGo))
	repo.AddTool(createPlatformTool("semgrep", tool.InstallPip))
	repo.AddTool(createTenantTool(tenantID, "custom", tool.InstallDocker))

	input := app.ListPlatformToolsInput{
		Page:    1,
		PerPage: 10,
	}

	result, err := svc.ListPlatformTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Only platform tools (tenant tool excluded)
	if result.Total != 2 {
		t.Errorf("expected 2 platform tools, got %d", result.Total)
	}
}

// ============================================================================
// Tests: ListCustomTools
// ============================================================================

func TestToolService_ListCustomTools_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	repo.AddTool(createPlatformTool("nuclei", tool.InstallGo))
	repo.AddTool(createTenantTool(tenant1, "custom1", tool.InstallDocker))
	repo.AddTool(createTenantTool(tenant1, "custom2", tool.InstallBinary))
	repo.AddTool(createTenantTool(tenant2, "other-tenant", tool.InstallPip))

	input := app.ListCustomToolsInput{
		TenantID: tenant1.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListCustomTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 custom tools for tenant1, got %d", result.Total)
	}
}

func TestToolService_ListCustomTools_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.ListCustomToolsInput{
		TenantID: "invalid",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListCustomTools(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: ListAvailableTools
// ============================================================================

func TestToolService_ListAvailableTools_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	repo.AddTool(createPlatformTool("nuclei", tool.InstallGo))
	repo.AddTool(createTenantTool(tenant1, "my-tool", tool.InstallDocker))
	repo.AddTool(createTenantTool(tenant2, "other-tool", tool.InstallPip))

	input := app.ListAvailableToolsInput{
		TenantID: tenant1.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListAvailableTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Platform + tenant1's own = 2
	if result.Total != 2 {
		t.Errorf("expected 2 available tools, got %d", result.Total)
	}
}

func TestToolService_ListAvailableTools_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.ListAvailableToolsInput{
		TenantID: "bad",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListAvailableTools(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: UpdateCustomTool
// ============================================================================

func TestToolService_UpdateCustomTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	input := app.UpdateCustomToolInput{
		TenantID:    tenantID.String(),
		ToolID:      existing.ID.String(),
		DisplayName: "Updated Scanner",
		Description: "Updated desc",
	}

	result, err := svc.UpdateCustomTool(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.DisplayName != "Updated Scanner" {
		t.Errorf("expected Updated Scanner, got %s", result.DisplayName)
	}
}

func TestToolService_UpdateCustomTool_TenantIsolation(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	existing := createTenantTool(tenant1, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	input := app.UpdateCustomToolInput{
		TenantID:    tenant2.String(),
		ToolID:      existing.ID.String(),
		DisplayName: "Hacked",
	}

	_, err := svc.UpdateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when updating another tenant's tool")
	}
}

func TestToolService_UpdateCustomTool_CannotUpdatePlatform(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	// Platform tool
	platform := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platform)

	input := app.UpdateCustomToolInput{
		TenantID:    tenantID.String(),
		ToolID:      platform.ID.String(),
		DisplayName: "Hacked",
	}

	// GetCustomTool uses GetByTenantAndID which won't find platform tools
	_, err := svc.UpdateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when updating platform tool via custom tool endpoint")
	}
}

func TestToolService_UpdateCustomTool_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.UpdateCustomToolInput{
		TenantID:    "bad",
		ToolID:      shared.NewID().String(),
		DisplayName: "test",
	}

	_, err := svc.UpdateCustomTool(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: DeleteCustomTool
// ============================================================================

func TestToolService_DeleteCustomTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	err := svc.DeleteCustomTool(context.Background(), tenantID.String(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	_, err = repo.GetByTenantAndID(context.Background(), tenantID, existing.ID)
	if err == nil {
		t.Error("expected tool to be deleted")
	}
}

func TestToolService_DeleteCustomTool_TenantIsolation(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	existing := createTenantTool(tenant1, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	err := svc.DeleteCustomTool(context.Background(), tenant2.String(), existing.ID.String())
	if err == nil {
		t.Fatal("expected error when deleting another tenant's tool")
	}
}

func TestToolService_DeleteCustomTool_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	err := svc.DeleteCustomTool(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_DeleteCustomTool_InvalidToolID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	err := svc.DeleteCustomTool(context.Background(), tenantID.String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid tool ID")
	}
}

func TestToolService_DeleteCustomTool_CascadeDeactivation(t *testing.T) {
	svc, repo, _, _, deactivator := newToolSvcTestServiceFull()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	deactivator.deactivatedCount = 1
	deactivator.deactivatedIDs = []shared.ID{shared.NewID()}

	err := svc.DeleteCustomTool(context.Background(), tenantID.String(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if deactivator.calledWith != "my-scanner" {
		t.Errorf("expected deactivator called with my-scanner, got %s", deactivator.calledWith)
	}
}

// ============================================================================
// Tests: ActivateCustomTool
// ============================================================================

func TestToolService_ActivateCustomTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	existing.Deactivate()
	repo.AddTool(existing)

	result, err := svc.ActivateCustomTool(context.Background(), tenantID.String(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.IsActive {
		t.Error("expected custom tool to be active")
	}
}

func TestToolService_ActivateCustomTool_TenantIsolation(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	existing := createTenantTool(tenant1, "my-scanner", tool.InstallDocker)
	existing.Deactivate()
	repo.AddTool(existing)

	_, err := svc.ActivateCustomTool(context.Background(), tenant2.String(), existing.ID.String())
	if err == nil {
		t.Fatal("expected error when activating another tenant's tool")
	}
}

func TestToolService_ActivateCustomTool_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.ActivateCustomTool(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: DeactivateCustomTool
// ============================================================================

func TestToolService_DeactivateCustomTool_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	result, err := svc.DeactivateCustomTool(context.Background(), tenantID.String(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.IsActive {
		t.Error("expected custom tool to be inactive")
	}
}

func TestToolService_DeactivateCustomTool_TenantIsolation(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	existing := createTenantTool(tenant1, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	_, err := svc.DeactivateCustomTool(context.Background(), tenant2.String(), existing.ID.String())
	if err == nil {
		t.Fatal("expected error when deactivating another tenant's tool")
	}
}

func TestToolService_DeactivateCustomTool_CascadeDeactivation(t *testing.T) {
	svc, repo, _, _, deactivator := newToolSvcTestServiceFull()
	tenantID := shared.NewID()

	existing := createTenantTool(tenantID, "my-scanner", tool.InstallDocker)
	repo.AddTool(existing)

	deactivator.deactivatedCount = 2
	deactivator.deactivatedIDs = []shared.ID{shared.NewID(), shared.NewID()}

	result, err := svc.DeactivateCustomTool(context.Background(), tenantID.String(), existing.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.IsActive {
		t.Error("expected tool to be inactive")
	}
	if deactivator.calledWith != "my-scanner" {
		t.Errorf("expected deactivator called with my-scanner, got %s", deactivator.calledWith)
	}
}

// ============================================================================
// Tests: TenantToolConfig Operations
// ============================================================================

func TestToolService_CreateTenantToolConfig_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	input := app.CreateTenantToolConfigInput{
		TenantID:  tenantID.String(),
		ToolID:    platformTool.ID.String(),
		Config:    map[string]any{"severity": "high"},
		IsEnabled: true,
	}

	result, err := svc.CreateTenantToolConfig(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.TenantID != tenantID {
		t.Error("expected tenant ID to match")
	}
	if !result.IsEnabled {
		t.Error("expected config to be enabled")
	}
}

func TestToolService_CreateTenantToolConfig_ToolNotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.CreateTenantToolConfigInput{
		TenantID: tenantID.String(),
		ToolID:   shared.NewID().String(),
	}

	_, err := svc.CreateTenantToolConfig(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_CreateTenantToolConfig_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CreateTenantToolConfigInput{
		TenantID: "bad",
		ToolID:   shared.NewID().String(),
	}

	_, err := svc.CreateTenantToolConfig(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_GetTenantToolConfig_Success(t *testing.T) {
	svc, repo, configRepo, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	config, _ := tool.NewTenantToolConfig(tenantID, platformTool.ID, map[string]any{"key": "val"}, nil)
	configRepo.configs[config.ID.String()] = config

	result, err := svc.GetTenantToolConfig(context.Background(), tenantID.String(), platformTool.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.TenantID != tenantID {
		t.Error("expected correct tenant ID")
	}
}

func TestToolService_DeleteTenantToolConfig_Success(t *testing.T) {
	svc, repo, configRepo, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	config, _ := tool.NewTenantToolConfig(tenantID, platformTool.ID, nil, nil)
	configRepo.configs[config.ID.String()] = config

	err := svc.DeleteTenantToolConfig(context.Background(), tenantID.String(), platformTool.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestToolService_UpdateTenantToolConfig_CreateNew(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	input := app.UpdateTenantToolConfigInput{
		TenantID:  tenantID.String(),
		ToolID:    platformTool.ID.String(),
		Config:    map[string]any{"severity": "critical"},
		IsEnabled: false,
	}

	result, err := svc.UpdateTenantToolConfig(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.IsEnabled {
		t.Error("expected config to be disabled")
	}
}

func TestToolService_UpdateTenantToolConfig_UpdateExisting(t *testing.T) {
	svc, repo, configRepo, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	// Create existing config
	config, _ := tool.NewTenantToolConfig(tenantID, platformTool.ID, map[string]any{"old": "value"}, nil)
	configRepo.configs[config.ID.String()] = config

	input := app.UpdateTenantToolConfigInput{
		TenantID:  tenantID.String(),
		ToolID:    platformTool.ID.String(),
		Config:    map[string]any{"new": "value"},
		IsEnabled: true,
	}

	result, err := svc.UpdateTenantToolConfig(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Config["new"] != "value" {
		t.Error("expected config to be updated")
	}
}

// ============================================================================
// Tests: EnableToolForTenant / DisableToolForTenant
// ============================================================================

func TestToolService_EnableToolForTenant_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	err := svc.EnableToolForTenant(context.Background(), tenantID.String(), toolID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestToolService_EnableToolForTenant_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	err := svc.EnableToolForTenant(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_DisableToolForTenant_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	err := svc.DisableToolForTenant(context.Background(), tenantID.String(), toolID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestToolService_DisableToolForTenant_InvalidToolID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	err := svc.DisableToolForTenant(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid tool ID")
	}
}

// ============================================================================
// Tests: BulkEnableTools / BulkDisableTools
// ============================================================================

func TestToolService_BulkEnableTools_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.BulkEnableToolsInput{
		TenantID: tenantID.String(),
		ToolIDs:  []string{shared.NewID().String(), shared.NewID().String()},
	}

	err := svc.BulkEnableTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestToolService_BulkEnableTools_InvalidToolID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.BulkEnableToolsInput{
		TenantID: tenantID.String(),
		ToolIDs:  []string{shared.NewID().String(), "invalid-uuid"},
	}

	err := svc.BulkEnableTools(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tool ID in bulk")
	}
}

func TestToolService_BulkDisableTools_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.BulkDisableToolsInput{
		TenantID: tenantID.String(),
		ToolIDs:  []string{shared.NewID().String()},
	}

	err := svc.BulkDisableTools(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// ============================================================================
// Tests: Tool Execution Operations
// ============================================================================

func TestToolService_RecordToolExecution_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	input := app.RecordToolExecutionInput{
		TenantID:     tenantID.String(),
		ToolID:       platformTool.ID.String(),
		InputConfig:  map[string]any{"targets": []string{"example.com"}},
		TargetsCount: 1,
	}

	result, err := svc.RecordToolExecution(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != tool.ExecutionStatusRunning {
		t.Errorf("expected status running, got %s", result.Status)
	}
	if result.TargetsCount != 1 {
		t.Errorf("expected 1 target, got %d", result.TargetsCount)
	}
}

func TestToolService_RecordToolExecution_WithAgent(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	agentID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	input := app.RecordToolExecutionInput{
		TenantID:     tenantID.String(),
		ToolID:       platformTool.ID.String(),
		AgentID:      agentID.String(),
		TargetsCount: 5,
	}

	result, err := svc.RecordToolExecution(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentID == nil || *result.AgentID != agentID {
		t.Error("expected agent ID to be set")
	}
}

func TestToolService_RecordToolExecution_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.RecordToolExecutionInput{
		TenantID: "bad",
		ToolID:   shared.NewID().String(),
	}

	_, err := svc.RecordToolExecution(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_CompleteToolExecution_Success(t *testing.T) {
	svc, _, _, execRepo := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	exec := tool.NewToolExecution(tenantID, toolID, nil, nil, 10)
	execRepo.executions[exec.ID.String()] = exec

	input := app.CompleteToolExecutionInput{
		ExecutionID:   exec.ID.String(),
		FindingsCount: 5,
		OutputSummary: map[string]any{"critical": 2, "high": 3},
	}

	result, err := svc.CompleteToolExecution(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != tool.ExecutionStatusCompleted {
		t.Errorf("expected status completed, got %s", result.Status)
	}
	if result.FindingsCount != 5 {
		t.Errorf("expected 5 findings, got %d", result.FindingsCount)
	}
}

func TestToolService_CompleteToolExecution_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.CompleteToolExecutionInput{
		ExecutionID: shared.NewID().String(),
	}

	_, err := svc.CompleteToolExecution(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-existent execution")
	}
}

func TestToolService_FailToolExecution_Success(t *testing.T) {
	svc, _, _, execRepo := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	exec := tool.NewToolExecution(tenantID, toolID, nil, nil, 10)
	execRepo.executions[exec.ID.String()] = exec

	input := app.FailToolExecutionInput{
		ExecutionID:  exec.ID.String(),
		ErrorMessage: "connection refused",
	}

	result, err := svc.FailToolExecution(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != tool.ExecutionStatusFailed {
		t.Errorf("expected status failed, got %s", result.Status)
	}
	if result.ErrorMessage != "connection refused" {
		t.Errorf("expected error message, got %s", result.ErrorMessage)
	}
}

func TestToolService_TimeoutToolExecution_Success(t *testing.T) {
	svc, _, _, execRepo := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	exec := tool.NewToolExecution(tenantID, toolID, nil, nil, 10)
	execRepo.executions[exec.ID.String()] = exec

	result, err := svc.TimeoutToolExecution(context.Background(), exec.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != tool.ExecutionStatusTimeout {
		t.Errorf("expected status timeout, got %s", result.Status)
	}
}

func TestToolService_TimeoutToolExecution_InvalidID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.TimeoutToolExecution(context.Background(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid execution ID")
	}
}

// ============================================================================
// Tests: GetToolStats / GetTenantToolStats
// ============================================================================

func TestToolService_GetToolStats_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	stats, err := svc.GetToolStats(context.Background(), tenantID.String(), toolID.String(), 30)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats == nil {
		t.Fatal("expected stats, got nil")
	}
}

func TestToolService_GetToolStats_DefaultDays(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	// days=0 should default to 30
	stats, err := svc.GetToolStats(context.Background(), tenantID.String(), toolID.String(), 0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats == nil {
		t.Fatal("expected stats, got nil")
	}
}

func TestToolService_GetToolStats_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetToolStats(context.Background(), "bad", shared.NewID().String(), 30)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_GetTenantToolStats_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	stats, err := svc.GetTenantToolStats(context.Background(), tenantID.String(), 30)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats == nil {
		t.Fatal("expected stats, got nil")
	}
}

func TestToolService_GetTenantToolStats_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetTenantToolStats(context.Background(), "bad", 30)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: ListToolExecutions
// ============================================================================

func TestToolService_ListToolExecutions_Success(t *testing.T) {
	svc, _, _, execRepo := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	exec1 := tool.NewToolExecution(tenantID, toolID, nil, nil, 5)
	execRepo.executions[exec1.ID.String()] = exec1

	exec2 := tool.NewToolExecution(tenantID, toolID, nil, nil, 10)
	execRepo.executions[exec2.ID.String()] = exec2

	input := app.ListToolExecutionsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListToolExecutions(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 executions, got %d", result.Total)
	}
}

func TestToolService_ListToolExecutions_FilterByStatus(t *testing.T) {
	svc, _, _, execRepo := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	exec1 := tool.NewToolExecution(tenantID, toolID, nil, nil, 5)
	execRepo.executions[exec1.ID.String()] = exec1

	exec2 := tool.NewToolExecution(tenantID, toolID, nil, nil, 10)
	exec2.Complete(3, nil)
	execRepo.executions[exec2.ID.String()] = exec2

	input := app.ListToolExecutionsInput{
		TenantID: tenantID.String(),
		Status:   "completed",
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListToolExecutions(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 completed execution, got %d", result.Total)
	}
}

func TestToolService_ListToolExecutions_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.ListToolExecutionsInput{
		TenantID: "bad",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListToolExecutions(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: SetAgentRepo / SetCategoryRepo / SetPipelineDeactivator
// ============================================================================

func TestToolService_SetAgentRepo(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	agentRepo := newToolSvcMockAgentRepo()
	// Should not panic
	svc.SetAgentRepo(agentRepo)
}

func TestToolService_SetCategoryRepo(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	catRepo := newToolSvcMockCategoryRepo()
	// Should not panic
	svc.SetCategoryRepo(catRepo)
}

func TestToolService_SetPipelineDeactivator(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	deactivator := newToolSvcMockPipelineDeactivator()
	// Should not panic
	svc.SetPipelineDeactivator(deactivator)
}

// ============================================================================
// Tests: ListToolsWithConfig
// ============================================================================

func TestToolService_ListToolsWithConfig_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.ListToolsWithConfigInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListToolsWithConfig(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Empty result from mock is fine
	if result.Total != 0 {
		t.Errorf("expected 0 tools from mock, got %d", result.Total)
	}
}

func TestToolService_ListToolsWithConfig_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.ListToolsWithConfigInput{
		TenantID: "bad",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListToolsWithConfig(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: GetToolWithConfig
// ============================================================================

func TestToolService_GetToolWithConfig_Success(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	platformTool.DefaultConfig = map[string]any{"severity": "high"}
	repo.AddTool(platformTool)

	result, err := svc.GetToolWithConfig(context.Background(), tenantID.String(), platformTool.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Tool.Name != "nuclei" {
		t.Errorf("expected nuclei, got %s", result.Tool.Name)
	}
	if !result.IsEnabled {
		t.Error("expected IsEnabled to default to true when no tenant config")
	}
	if result.TenantConfig != nil {
		t.Error("expected nil TenantConfig when no config exists")
	}
}

func TestToolService_GetToolWithConfig_WithCategory(t *testing.T) {
	svc, repo, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	catRepo := newToolSvcMockCategoryRepo()
	svc.SetCategoryRepo(catRepo)

	catID := shared.NewID()
	catRepo.AddCategory(&toolcategory.ToolCategory{
		ID:          catID,
		Name:        "sast",
		DisplayName: "SAST",
		Icon:        "shield",
		Color:       "blue",
		IsBuiltin:   true,
	})

	platformTool := createPlatformTool("semgrep", tool.InstallPip)
	platformTool.CategoryID = &catID
	repo.AddTool(platformTool)

	result, err := svc.GetToolWithConfig(context.Background(), tenantID.String(), platformTool.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Category == nil {
		t.Fatal("expected category to be embedded")
	}
	if result.Category.Name != "sast" {
		t.Errorf("expected category name sast, got %s", result.Category.Name)
	}
	if result.Category.DisplayName != "SAST" {
		t.Errorf("expected category display name SAST, got %s", result.Category.DisplayName)
	}
}

func TestToolService_GetToolWithConfig_NotFound(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	_, err := svc.GetToolWithConfig(context.Background(), tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent tool")
	}
}

func TestToolService_GetToolWithConfig_InvalidIDs(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetToolWithConfig(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}

	_, err = svc.GetToolWithConfig(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid tool ID")
	}
}

// ============================================================================
// Tests: ListEnabledToolsForTenant
// ============================================================================

func TestToolService_ListEnabledToolsForTenant_Success(t *testing.T) {
	svc, repo, configRepo, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	platformTool := createPlatformTool("nuclei", tool.InstallGo)
	repo.AddTool(platformTool)

	config, _ := tool.NewTenantToolConfig(tenantID, platformTool.ID, nil, nil)
	config.IsEnabled = true
	configRepo.configs[config.ID.String()] = config

	result, err := svc.ListEnabledToolsForTenant(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 enabled tool, got %d", len(result))
	}
}

func TestToolService_ListEnabledToolsForTenant_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.ListEnabledToolsForTenant(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// ============================================================================
// Tests: RecordToolExecution with PipelineRunID and StepRunID
// ============================================================================

func TestToolService_RecordToolExecution_WithPipelineContext(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()
	pipelineRunID := shared.NewID()
	stepRunID := shared.NewID()

	input := app.RecordToolExecutionInput{
		TenantID:      tenantID.String(),
		ToolID:        toolID.String(),
		PipelineRunID: pipelineRunID.String(),
		StepRunID:     stepRunID.String(),
		TargetsCount:  3,
	}

	result, err := svc.RecordToolExecution(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.PipelineRunID == nil || *result.PipelineRunID != pipelineRunID {
		t.Error("expected pipeline run ID to be set")
	}
	if result.StepRunID == nil || *result.StepRunID != stepRunID {
		t.Error("expected step run ID to be set")
	}
}

func TestToolService_RecordToolExecution_InvalidAgentID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.RecordToolExecutionInput{
		TenantID: tenantID.String(),
		ToolID:   shared.NewID().String(),
		AgentID:  "bad-uuid",
	}

	_, err := svc.RecordToolExecution(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid agent ID")
	}
}

func TestToolService_RecordToolExecution_InvalidPipelineRunID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.RecordToolExecutionInput{
		TenantID:      tenantID.String(),
		ToolID:        shared.NewID().String(),
		PipelineRunID: "bad-uuid",
	}

	_, err := svc.RecordToolExecution(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid pipeline run ID")
	}
}

func TestToolService_RecordToolExecution_InvalidStepRunID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()

	input := app.RecordToolExecutionInput{
		TenantID:  tenantID.String(),
		ToolID:    shared.NewID().String(),
		StepRunID: "bad-uuid",
	}

	_, err := svc.RecordToolExecution(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid step run ID")
	}
}

// ============================================================================
// Tests: GetEffectiveToolConfig
// ============================================================================

func TestToolService_GetEffectiveToolConfig_Success(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	config, err := svc.GetEffectiveToolConfig(context.Background(), tenantID.String(), toolID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if config == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestToolService_GetEffectiveToolConfig_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetEffectiveToolConfig(context.Background(), "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_GetEffectiveToolConfig_InvalidToolID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	_, err := svc.GetEffectiveToolConfig(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid tool ID")
	}
}

// ============================================================================
// Tests: ListTenantToolConfigs
// ============================================================================

func TestToolService_ListTenantToolConfigs_Success(t *testing.T) {
	svc, _, configRepo, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID := shared.NewID()

	config, _ := tool.NewTenantToolConfig(tenantID, toolID, nil, nil)
	configRepo.configs[config.ID.String()] = config

	input := app.ListTenantToolConfigsInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListTenantToolConfigs(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 config, got %d", result.Total)
	}
}

func TestToolService_ListTenantToolConfigs_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newToolSvcTestService()

	input := app.ListTenantToolConfigsInput{
		TenantID: "bad",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListTenantToolConfigs(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestToolService_ListTenantToolConfigs_WithToolFilter(t *testing.T) {
	svc, _, configRepo, _ := newToolSvcTestService()
	tenantID := shared.NewID()
	toolID1 := shared.NewID()
	toolID2 := shared.NewID()

	config1, _ := tool.NewTenantToolConfig(tenantID, toolID1, nil, nil)
	configRepo.configs[config1.ID.String()] = config1

	config2, _ := tool.NewTenantToolConfig(tenantID, toolID2, nil, nil)
	configRepo.configs[config2.ID.String()] = config2

	input := app.ListTenantToolConfigsInput{
		TenantID: tenantID.String(),
		ToolID:   toolID1.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListTenantToolConfigs(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected 1 config filtered by tool, got %d", result.Total)
	}
}
