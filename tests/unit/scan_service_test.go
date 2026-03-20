package unit

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	scanservice "github.com/openctemio/api/internal/app/scan"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock: scan.Repository
// =============================================================================

type mockScanRepo struct {
	scans map[string]*scan.Scan

	// Error overrides for specific methods
	createErr        error
	getByTenantErr   error
	updateErr        error
	deleteErr        error
	listErr          error
	listDueErr       error
	statsErr         error
	listByPipelineID []*scan.Scan
	listByPipelineE  error
}

func newMockScanRepo() *mockScanRepo {
	return &mockScanRepo{scans: make(map[string]*scan.Scan)}
}

func (m *mockScanRepo) Create(_ context.Context, s *scan.Scan) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.scans[s.ID.String()] = s
	return nil
}

func (m *mockScanRepo) GetByID(_ context.Context, id shared.ID) (*scan.Scan, error) {
	s, ok := m.scans[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *mockScanRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scan.Scan, error) {
	if m.getByTenantErr != nil {
		return nil, m.getByTenantErr
	}
	s, ok := m.scans[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if s.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return s, nil
}

func (m *mockScanRepo) GetByName(_ context.Context, tenantID shared.ID, name string) (*scan.Scan, error) {
	for _, s := range m.scans {
		if s.TenantID == tenantID && s.Name == name {
			return s, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *mockScanRepo) List(_ context.Context, _ scan.Filter, page pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	if m.listErr != nil {
		return pagination.Result[*scan.Scan]{}, m.listErr
	}
	result := make([]*scan.Scan, 0, len(m.scans))
	for _, s := range m.scans {
		result = append(result, s)
	}
	total := int64(len(result))
	return pagination.Result[*scan.Scan]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *mockScanRepo) Update(_ context.Context, s *scan.Scan) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.scans[s.ID.String()] = s
	return nil
}

func (m *mockScanRepo) Delete(_ context.Context, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.scans[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.scans, id.String())
	return nil
}

func (m *mockScanRepo) ListDueForExecution(_ context.Context, _ time.Time) ([]*scan.Scan, error) {
	if m.listDueErr != nil {
		return nil, m.listDueErr
	}
	var result []*scan.Scan
	now := time.Now()
	for _, s := range m.scans {
		if s.IsDueForExecution(now) {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockScanRepo) UpdateNextRunAt(_ context.Context, _ shared.ID, _ *time.Time) error {
	return nil
}

func (m *mockScanRepo) RecordRun(_ context.Context, _ shared.ID, _ shared.ID, _ string) error {
	return nil
}

func (m *mockScanRepo) GetStats(_ context.Context, _ shared.ID) (*scan.Stats, error) {
	if m.statsErr != nil {
		return nil, m.statsErr
	}
	return &scan.Stats{
		Total:  int64(len(m.scans)),
		Active: int64(len(m.scans)),
	}, nil
}

func (m *mockScanRepo) Count(_ context.Context, _ scan.Filter) (int64, error) {
	return int64(len(m.scans)), nil
}

func (m *mockScanRepo) ListByAssetGroupID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	return nil, nil
}

func (m *mockScanRepo) ListByPipelineID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	if m.listByPipelineE != nil {
		return nil, m.listByPipelineE
	}
	return m.listByPipelineID, nil
}

func (m *mockScanRepo) UpdateStatusByAssetGroupID(_ context.Context, _ shared.ID, _ scan.Status) error {
	return nil
}

// addScan is a helper to insert a scan into the mock.
func (m *mockScanRepo) addScan(s *scan.Scan) {
	m.scans[s.ID.String()] = s
}

// =============================================================================
// Mock: pipeline.TemplateRepository
// =============================================================================

type mockTemplateRepo struct {
	templates map[string]*pipeline.Template
}

func newMockTemplateRepo() *mockTemplateRepo {
	return &mockTemplateRepo{templates: make(map[string]*pipeline.Template)}
}

func (m *mockTemplateRepo) Create(_ context.Context, t *pipeline.Template) error {
	m.templates[t.ID.String()] = t
	return nil
}

func (m *mockTemplateRepo) GetByID(_ context.Context, id shared.ID) (*pipeline.Template, error) {
	t, ok := m.templates[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *mockTemplateRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*pipeline.Template, error) {
	t, ok := m.templates[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *mockTemplateRepo) GetByName(_ context.Context, _ shared.ID, _ string, _ int) (*pipeline.Template, error) {
	return nil, shared.ErrNotFound
}

func (m *mockTemplateRepo) List(_ context.Context, _ pipeline.TemplateFilter, _ pagination.Pagination) (pagination.Result[*pipeline.Template], error) {
	return pagination.Result[*pipeline.Template]{}, nil
}

func (m *mockTemplateRepo) Update(_ context.Context, _ *pipeline.Template) error { return nil }
func (m *mockTemplateRepo) Delete(_ context.Context, _ shared.ID) error          { return nil }
func (m *mockTemplateRepo) DeleteInTx(_ context.Context, _ *sql.Tx, _ shared.ID) error {
	return nil
}
func (m *mockTemplateRepo) GetWithSteps(_ context.Context, _ shared.ID) (*pipeline.Template, error) {
	return nil, nil
}
func (m *mockTemplateRepo) GetSystemTemplateByID(_ context.Context, _ shared.ID) (*pipeline.Template, error) {
	return nil, nil
}
func (m *mockTemplateRepo) ListWithSystemTemplates(_ context.Context, _ shared.ID, _ pipeline.TemplateFilter, _ pagination.Pagination) (pagination.Result[*pipeline.Template], error) {
	return pagination.Result[*pipeline.Template]{}, nil
}

// =============================================================================
// Mock: assetgroup.Repository
// =============================================================================

type mockAssetGroupRepo struct {
	groups          map[string]*assetgroup.AssetGroup
	assetTypeCounts map[string]int64 // for CountAssetsByType
}

func newMockAssetGroupRepo() *mockAssetGroupRepo {
	return &mockAssetGroupRepo{
		groups:          make(map[string]*assetgroup.AssetGroup),
		assetTypeCounts: make(map[string]int64),
	}
}

func (m *mockAssetGroupRepo) Create(_ context.Context, g *assetgroup.AssetGroup) error {
	m.groups[g.ID().String()] = g
	return nil
}

func (m *mockAssetGroupRepo) GetByID(_ context.Context, id shared.ID) (*assetgroup.AssetGroup, error) {
	g, ok := m.groups[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return g, nil
}

func (m *mockAssetGroupRepo) Update(_ context.Context, _ *assetgroup.AssetGroup) error { return nil }
func (m *mockAssetGroupRepo) Delete(_ context.Context, _ shared.ID) error              { return nil }
func (m *mockAssetGroupRepo) List(_ context.Context, _ assetgroup.Filter, _ assetgroup.ListOptions, _ pagination.Pagination) (pagination.Result[*assetgroup.AssetGroup], error) {
	return pagination.Result[*assetgroup.AssetGroup]{}, nil
}
func (m *mockAssetGroupRepo) Count(_ context.Context, _ assetgroup.Filter) (int64, error) {
	return 0, nil
}
func (m *mockAssetGroupRepo) ExistsByName(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockAssetGroupRepo) GetStats(_ context.Context, _ shared.ID) (*assetgroup.Stats, error) {
	return nil, nil
}
func (m *mockAssetGroupRepo) AddAssets(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}
func (m *mockAssetGroupRepo) RemoveAssets(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}
func (m *mockAssetGroupRepo) GetGroupAssets(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*assetgroup.GroupAsset], error) {
	return pagination.Result[*assetgroup.GroupAsset]{}, nil
}
func (m *mockAssetGroupRepo) GetGroupFindings(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*assetgroup.GroupFinding], error) {
	return pagination.Result[*assetgroup.GroupFinding]{}, nil
}
func (m *mockAssetGroupRepo) GetGroupIDsByAssetID(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAssetGroupRepo) RecalculateCounts(_ context.Context, _ shared.ID) error { return nil }
func (m *mockAssetGroupRepo) GetDistinctAssetTypes(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}
func (m *mockAssetGroupRepo) GetDistinctAssetTypesMultiple(_ context.Context, _ []shared.ID) ([]string, error) {
	return nil, nil
}
func (m *mockAssetGroupRepo) CountAssetsByType(_ context.Context, _ shared.ID) (map[string]int64, error) {
	return m.assetTypeCounts, nil
}

// =============================================================================
// Mock: pipeline.RunRepository
// =============================================================================

type mockRunRepo struct {
	runs                map[string]*pipeline.Run
	createLimitErr      error
	activeByScanCount   int
	activeByTenantCount int
}

func newMockRunRepo() *mockRunRepo {
	return &mockRunRepo{runs: make(map[string]*pipeline.Run)}
}

func (m *mockRunRepo) Create(_ context.Context, r *pipeline.Run) error {
	m.runs[r.ID.String()] = r
	return nil
}

func (m *mockRunRepo) GetByID(_ context.Context, id shared.ID) (*pipeline.Run, error) {
	r, ok := m.runs[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return r, nil
}

func (m *mockRunRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*pipeline.Run, error) {
	r, ok := m.runs[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return r, nil
}

func (m *mockRunRepo) List(_ context.Context, _ pipeline.RunFilter, _ pagination.Pagination) (pagination.Result[*pipeline.Run], error) {
	return pagination.Result[*pipeline.Run]{}, nil
}

func (m *mockRunRepo) ListByScanID(_ context.Context, _ shared.ID, _, _ int) ([]*pipeline.Run, int64, error) {
	return nil, 0, nil
}

func (m *mockRunRepo) Update(_ context.Context, r *pipeline.Run) error {
	m.runs[r.ID.String()] = r
	return nil
}

func (m *mockRunRepo) Delete(_ context.Context, _ shared.ID) error                        { return nil }
func (m *mockRunRepo) GetWithStepRuns(_ context.Context, _ shared.ID) (*pipeline.Run, error) {
	return nil, nil
}
func (m *mockRunRepo) GetActiveByPipelineID(_ context.Context, _ shared.ID) ([]*pipeline.Run, error) {
	return nil, nil
}
func (m *mockRunRepo) GetActiveByAssetID(_ context.Context, _ shared.ID) ([]*pipeline.Run, error) {
	return nil, nil
}
func (m *mockRunRepo) CountActiveByPipelineID(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockRunRepo) CountActiveByTenantID(_ context.Context, _ shared.ID) (int, error) {
	return m.activeByTenantCount, nil
}
func (m *mockRunRepo) CountActiveByScanID(_ context.Context, _ shared.ID) (int, error) {
	return m.activeByScanCount, nil
}
func (m *mockRunRepo) CreateRunIfUnderLimit(_ context.Context, r *pipeline.Run, _, _ int) error {
	if m.createLimitErr != nil {
		return m.createLimitErr
	}
	m.runs[r.ID.String()] = r
	return nil
}
func (m *mockRunRepo) UpdateStats(_ context.Context, _ shared.ID, _, _, _, _ int) error { return nil }
func (m *mockRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ pipeline.RunStatus, _ string) error {
	return nil
}
func (m *mockRunRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (pipeline.RunStats, error) {
	return pipeline.RunStats{}, nil
}

// =============================================================================
// Mock: pipeline.StepRepository
// =============================================================================

type mockStepRepo struct {
	steps map[string][]*pipeline.Step // keyed by pipeline ID
}

func newMockStepRepo() *mockStepRepo {
	return &mockStepRepo{steps: make(map[string][]*pipeline.Step)}
}

func (m *mockStepRepo) Create(_ context.Context, _ *pipeline.Step) error        { return nil }
func (m *mockStepRepo) CreateBatch(_ context.Context, _ []*pipeline.Step) error { return nil }
func (m *mockStepRepo) GetByID(_ context.Context, _ shared.ID) (*pipeline.Step, error) {
	return nil, nil
}
func (m *mockStepRepo) GetByPipelineID(_ context.Context, pipelineID shared.ID) ([]*pipeline.Step, error) {
	steps, ok := m.steps[pipelineID.String()]
	if !ok {
		return []*pipeline.Step{}, nil
	}
	return steps, nil
}
func (m *mockStepRepo) GetByKey(_ context.Context, _ shared.ID, _ string) (*pipeline.Step, error) {
	return nil, nil
}
func (m *mockStepRepo) Update(_ context.Context, _ *pipeline.Step) error              { return nil }
func (m *mockStepRepo) Delete(_ context.Context, _ shared.ID) error                   { return nil }
func (m *mockStepRepo) DeleteByPipelineID(_ context.Context, _ shared.ID) error       { return nil }
func (m *mockStepRepo) DeleteByPipelineIDInTx(_ context.Context, _ *sql.Tx, _ shared.ID) error {
	return nil
}
func (m *mockStepRepo) Reorder(_ context.Context, _ shared.ID, _ map[string]int) error { return nil }
func (m *mockStepRepo) FindPipelineIDsByToolName(_ context.Context, _ string) ([]shared.ID, error) {
	return nil, nil
}

// =============================================================================
// Mock: pipeline.StepRunRepository
// =============================================================================

type mockStepRunRepo struct{}

func (m *mockStepRunRepo) Create(_ context.Context, _ *pipeline.StepRun) error        { return nil }
func (m *mockStepRunRepo) CreateBatch(_ context.Context, _ []*pipeline.StepRun) error { return nil }
func (m *mockStepRunRepo) GetByID(_ context.Context, _ shared.ID) (*pipeline.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) GetByPipelineRunID(_ context.Context, _ shared.ID) ([]*pipeline.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) GetByStepKey(_ context.Context, _ shared.ID, _ string) (*pipeline.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) List(_ context.Context, _ pipeline.StepRunFilter) ([]*pipeline.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) Update(_ context.Context, _ *pipeline.StepRun) error { return nil }
func (m *mockStepRunRepo) Delete(_ context.Context, _ shared.ID) error         { return nil }
func (m *mockStepRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ pipeline.StepRunStatus, _, _ string) error {
	return nil
}
func (m *mockStepRunRepo) AssignAgent(_ context.Context, _, _, _ shared.ID) error {
	return nil
}
func (m *mockStepRunRepo) Complete(_ context.Context, _ shared.ID, _ int, _ map[string]any) error {
	return nil
}
func (m *mockStepRunRepo) GetPendingByDependencies(_ context.Context, _ shared.ID, _ []string) ([]*pipeline.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (pipeline.RunStats, error) {
	return pipeline.RunStats{}, nil
}

// =============================================================================
// Mock: command.Repository
// =============================================================================

type mockCommandRepo struct {
	commands map[string]*command.Command
}

func newMockCommandRepo() *mockCommandRepo {
	return &mockCommandRepo{commands: make(map[string]*command.Command)}
}

func (m *mockCommandRepo) Create(_ context.Context, cmd *command.Command) error {
	m.commands[cmd.ID.String()] = cmd
	return nil
}
func (m *mockCommandRepo) GetByID(_ context.Context, _ shared.ID) (*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetPendingForAgent(_ context.Context, _ shared.ID, _ *shared.ID, _ int) ([]*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) List(_ context.Context, _ command.Filter, _ pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}
func (m *mockCommandRepo) Update(_ context.Context, _ *command.Command) error { return nil }
func (m *mockCommandRepo) Delete(_ context.Context, _ shared.ID) error        { return nil }
func (m *mockCommandRepo) ExpireOldCommands(_ context.Context) (int64, error) { return 0, nil }
func (m *mockCommandRepo) FindExpired(_ context.Context) ([]*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetByAuthTokenHash(_ context.Context, _ string) (*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) CountActivePlatformJobsByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockCommandRepo) CountQueuedPlatformJobsByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockCommandRepo) CountQueuedPlatformJobs(_ context.Context) (int, error) { return 0, nil }
func (m *mockCommandRepo) GetQueuedPlatformJobs(_ context.Context, _ int) ([]*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetNextPlatformJob(_ context.Context, _ shared.ID, _ []string, _ []string) (*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) UpdateQueuePriorities(_ context.Context) (int64, error) { return 0, nil }
func (m *mockCommandRepo) RecoverStuckJobs(_ context.Context, _, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) ExpireOldPlatformJobs(_ context.Context, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) GetQueuePosition(_ context.Context, _ shared.ID) (*command.QueuePosition, error) {
	return nil, nil
}
func (m *mockCommandRepo) ListPlatformJobsByTenant(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}
func (m *mockCommandRepo) ListPlatformJobsAdmin(_ context.Context, _, _ *shared.ID, _ *command.CommandStatus, _ pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}
func (m *mockCommandRepo) GetPlatformJobsByAgent(_ context.Context, _ shared.ID, _ *command.CommandStatus) ([]*command.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) RecoverStuckTenantCommands(_ context.Context, _, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) FailExhaustedCommands(_ context.Context, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (command.CommandStats, error) {
	return command.CommandStats{}, nil
}

// =============================================================================
// Mock: scannertemplate.Repository
// =============================================================================

type mockScannerTemplateRepo struct{}

func (m *mockScannerTemplateRepo) Create(_ context.Context, _ *scannertemplate.ScannerTemplate) error {
	return nil
}
func (m *mockScannerTemplateRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*scannertemplate.ScannerTemplate, error) {
	return nil, nil
}
func (m *mockScannerTemplateRepo) GetByTenantAndName(_ context.Context, _ shared.ID, _ scannertemplate.TemplateType, _ string) (*scannertemplate.ScannerTemplate, error) {
	return nil, nil
}
func (m *mockScannerTemplateRepo) List(_ context.Context, _ scannertemplate.Filter, _ pagination.Pagination) (pagination.Result[*scannertemplate.ScannerTemplate], error) {
	return pagination.Result[*scannertemplate.ScannerTemplate]{}, nil
}
func (m *mockScannerTemplateRepo) ListByIDs(_ context.Context, _ shared.ID, _ []shared.ID) ([]*scannertemplate.ScannerTemplate, error) {
	return nil, nil
}
func (m *mockScannerTemplateRepo) Update(_ context.Context, _ *scannertemplate.ScannerTemplate) error {
	return nil
}
func (m *mockScannerTemplateRepo) Delete(_ context.Context, _, _ shared.ID) error { return nil }
func (m *mockScannerTemplateRepo) CountByTenant(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockScannerTemplateRepo) CountByType(_ context.Context, _ shared.ID, _ scannertemplate.TemplateType) (int64, error) {
	return 0, nil
}
func (m *mockScannerTemplateRepo) ExistsByName(_ context.Context, _ shared.ID, _ scannertemplate.TemplateType, _ string) (bool, error) {
	return false, nil
}
func (m *mockScannerTemplateRepo) GetUsage(_ context.Context, _ shared.ID) (*scannertemplate.TemplateUsage, error) {
	return nil, nil
}

// =============================================================================
// Mock: templatesource.Repository
// =============================================================================

type mockTemplateSourceRepo struct{}

func (m *mockTemplateSourceRepo) Create(_ context.Context, _ *templatesource.TemplateSource) error {
	return nil
}
func (m *mockTemplateSourceRepo) GetByID(_ context.Context, _ shared.ID) (*templatesource.TemplateSource, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*templatesource.TemplateSource, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) GetByTenantAndName(_ context.Context, _ shared.ID, _ string) (*templatesource.TemplateSource, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) List(_ context.Context, _ templatesource.ListInput) (*templatesource.ListOutput, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) ListByTenantAndTemplateType(_ context.Context, _ shared.ID, _ scannertemplate.TemplateType) ([]*templatesource.TemplateSource, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) ListEnabledForSync(_ context.Context, _ shared.ID) ([]*templatesource.TemplateSource, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) ListAllNeedingSync(_ context.Context) ([]*templatesource.TemplateSource, error) {
	return nil, nil
}
func (m *mockTemplateSourceRepo) Update(_ context.Context, _ *templatesource.TemplateSource) error {
	return nil
}
func (m *mockTemplateSourceRepo) Delete(_ context.Context, _ shared.ID) error { return nil }
func (m *mockTemplateSourceRepo) UpdateSyncStatus(_ context.Context, _ *templatesource.TemplateSource) error {
	return nil
}
func (m *mockTemplateSourceRepo) CountByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}

// =============================================================================
// Mock: tool.Repository
// =============================================================================

type mockToolRepo struct {
	tools map[string]*tool.Tool
}

func newMockToolRepo() *mockToolRepo {
	return &mockToolRepo{tools: make(map[string]*tool.Tool)}
}

func (m *mockToolRepo) Create(_ context.Context, _ *tool.Tool) error { return nil }
func (m *mockToolRepo) GetByID(_ context.Context, _ shared.ID) (*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) GetByName(_ context.Context, name string) (*tool.Tool, error) {
	t, ok := m.tools[name]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}
func (m *mockToolRepo) List(_ context.Context, _ tool.ToolFilter, _ pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *mockToolRepo) ListByNames(_ context.Context, _ []string) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) ListByCategoryID(_ context.Context, _ shared.ID) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) ListByCategoryName(_ context.Context, _ string) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) ListByCapability(_ context.Context, _ string) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string) (*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) Update(_ context.Context, _ *tool.Tool) error  { return nil }
func (m *mockToolRepo) Delete(_ context.Context, _ shared.ID) error   { return nil }
func (m *mockToolRepo) BulkCreate(_ context.Context, _ []*tool.Tool) error { return nil }
func (m *mockToolRepo) BulkUpdateVersions(_ context.Context, _ map[shared.ID]tool.VersionInfo) error {
	return nil
}
func (m *mockToolRepo) Count(_ context.Context, _ tool.ToolFilter) (int64, error) { return 0, nil }
func (m *mockToolRepo) GetAllCapabilities(_ context.Context) ([]string, error)    { return nil, nil }
func (m *mockToolRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) GetByTenantAndName(_ context.Context, _ shared.ID, _ string) (*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) GetPlatformToolByName(_ context.Context, _ string) (*tool.Tool, error) {
	return nil, nil
}
func (m *mockToolRepo) ListPlatformTools(_ context.Context, _ tool.ToolFilter, _ pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *mockToolRepo) ListTenantCustomTools(_ context.Context, _ shared.ID, _ tool.ToolFilter, _ pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *mockToolRepo) ListAvailableTools(_ context.Context, _ shared.ID, _ tool.ToolFilter, _ pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *mockToolRepo) DeleteTenantTool(_ context.Context, _, _ shared.ID) error { return nil }

// addTool is a helper to insert an active tool into the mock.
func (m *mockToolRepo) addTool(name string, active bool) {
	m.tools[name] = &tool.Tool{
		ID:               shared.NewID(),
		Name:             name,
		IsActive:         active,
		SupportedTargets: []string{},
	}
}

// =============================================================================
// Mock: TemplateSyncer
// =============================================================================

type mockTemplateSyncer struct{}

func (m *mockTemplateSyncer) SyncSource(_ context.Context, _ *templatesource.TemplateSource) (*scanservice.TemplateSyncResult, error) {
	return &scanservice.TemplateSyncResult{Success: true}, nil
}

// =============================================================================
// Mock: AgentSelector
// =============================================================================

type mockAgentSelector struct {
	available     bool
	message       string
	canUsePlatform bool
	platformReason string
	selectResult  *scanservice.SelectAgentResult
	selectErr     error
}

func (m *mockAgentSelector) CheckAgentAvailability(_ context.Context, _ shared.ID, _ string, _ bool) *scanservice.AgentAvailability {
	return &scanservice.AgentAvailability{
		Available: m.available,
		Message:   m.message,
	}
}

func (m *mockAgentSelector) CanUsePlatformAgents(_ context.Context, _ shared.ID) (bool, string) {
	return m.canUsePlatform, m.platformReason
}

func (m *mockAgentSelector) SelectAgent(_ context.Context, _ scanservice.SelectAgentRequest) (*scanservice.SelectAgentResult, error) {
	if m.selectErr != nil {
		return nil, m.selectErr
	}
	if m.selectResult != nil {
		return m.selectResult, nil
	}
	return &scanservice.SelectAgentResult{
		Agent:      &agent.Agent{},
		IsPlatform: false,
	}, nil
}

// =============================================================================
// Mock: SecurityValidator
// =============================================================================

type mockSecurityValidator struct {
	cronErr error
}

func (m *mockSecurityValidator) ValidateIdentifier(_ string, _ int, _ string) *scanservice.ValidationResult {
	return &scanservice.ValidationResult{Valid: true}
}

func (m *mockSecurityValidator) ValidateIdentifiers(_ []string, _ int, _ string) *scanservice.ValidationResult {
	return &scanservice.ValidationResult{Valid: true}
}

func (m *mockSecurityValidator) ValidateScannerConfig(_ context.Context, _ shared.ID, _ map[string]any) *scanservice.ValidationResult {
	return &scanservice.ValidationResult{Valid: true}
}

func (m *mockSecurityValidator) ValidateCronExpression(_ string) error {
	return m.cronErr
}

// =============================================================================
// Mock: AuditService
// =============================================================================

type mockAuditService struct {
	events []scanservice.AuditEvent
}

func (m *mockAuditService) LogEvent(_ context.Context, _ scanservice.AuditContext, event scanservice.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

// =============================================================================
// Test Helper: create scan service with mocks
// =============================================================================

type testScanServiceDeps struct {
	scanRepo       *mockScanRepo
	templateRepo   *mockTemplateRepo
	assetGroupRepo *mockAssetGroupRepo
	runRepo        *mockRunRepo
	stepRepo       *mockStepRepo
	commandRepo    *mockCommandRepo
	toolRepo       *mockToolRepo
	agentSelector  *mockAgentSelector
	secValidator   *mockSecurityValidator
	auditSvc       *mockAuditService
}

func newTestScanService() (*scanservice.Service, *testScanServiceDeps) {
	deps := &testScanServiceDeps{
		scanRepo:       newMockScanRepo(),
		templateRepo:   newMockTemplateRepo(),
		assetGroupRepo: newMockAssetGroupRepo(),
		runRepo:        newMockRunRepo(),
		stepRepo:       newMockStepRepo(),
		commandRepo:    newMockCommandRepo(),
		toolRepo:       newMockToolRepo(),
		agentSelector: &mockAgentSelector{
			available: true,
		},
		secValidator: &mockSecurityValidator{},
		auditSvc:     &mockAuditService{},
	}

	log := logger.NewNop()

	svc := scanservice.NewService(
		deps.scanRepo,
		deps.templateRepo,
		deps.assetGroupRepo,
		deps.runRepo,
		deps.stepRepo,
		&mockStepRunRepo{},
		deps.commandRepo,
		&mockScannerTemplateRepo{},
		&mockTemplateSourceRepo{},
		deps.toolRepo,
		&mockTemplateSyncer{},
		deps.agentSelector,
		deps.secValidator,
		log,
		scanservice.WithAuditService(deps.auditSvc),
	)

	return svc, deps
}

// createTestScanInRepo is a helper to create a scan entity in the mock repo directly.
func createTestScanInRepo(deps *testScanServiceDeps, tenantID shared.ID, name string, scanType scan.ScanType) *scan.Scan {
	agID := shared.NewID()
	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group-"+name, assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	s, _ := scan.NewScan(tenantID, name, ag.ID(), scanType)
	if scanType == scan.ScanTypeSingle {
		_ = s.SetSingleScanner("nuclei", map[string]any{}, 1)
	} else {
		pipelineID := shared.NewID()
		tmpl := &pipeline.Template{ID: pipelineID, TenantID: tenantID, IsActive: true, Name: "test-pipeline"}
		deps.templateRepo.templates[pipelineID.String()] = tmpl
		_ = s.SetWorkflow(pipelineID)
	}

	// Suppress unused variable
	_ = agID
	deps.scanRepo.addScan(s)
	return s
}

// =============================================================================
// Tests: CreateScan
// =============================================================================

func TestScanService_CreateScan_SingleScanner_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	// Create asset group for scan target
	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	// Register an active tool
	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:      tenantID.String(),
		Name:          "Test Single Scan",
		Description:   "A test scan",
		AssetGroupID:  ag.ID().String(),
		ScanType:      "single",
		ScannerName:   "nuclei",
		ScannerConfig: map[string]any{"severity": "high"},
		ScheduleType:  "manual",
		Tags:          []string{"test"},
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected scan result, got nil")
	}
	if result.Name != "Test Single Scan" {
		t.Errorf("expected name 'Test Single Scan', got %q", result.Name)
	}
	if result.ScanType != scan.ScanTypeSingle {
		t.Errorf("expected scan type single, got %s", result.ScanType)
	}
	if result.ScannerName != "nuclei" {
		t.Errorf("expected scanner name nuclei, got %s", result.ScannerName)
	}
	if result.Status != scan.StatusActive {
		t.Errorf("expected status active, got %s", result.Status)
	}
	if len(deps.auditSvc.events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(deps.auditSvc.events))
	}
}

func TestScanService_CreateScan_WorkflowType_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	// Create asset group
	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	// Create pipeline template
	pipelineID := shared.NewID()
	tmpl := &pipeline.Template{ID: pipelineID, TenantID: tenantID, IsActive: true, Name: "test-pipeline"}
	deps.templateRepo.templates[pipelineID.String()] = tmpl

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Test Workflow Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "workflow",
		PipelineID:   pipelineID.String(),
		ScheduleType: "manual",
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScanType != scan.ScanTypeWorkflow {
		t.Errorf("expected scan type workflow, got %s", result.ScanType)
	}
	if result.PipelineID == nil || *result.PipelineID != pipelineID {
		t.Errorf("expected pipeline ID %s", pipelineID)
	}
}

func TestScanService_CreateScan_EmptyName(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "", // empty name
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestScanService_CreateScan_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanService()

	input := scanservice.CreateScanInput{
		TenantID:     "not-a-uuid",
		Name:         "Test Scan",
		AssetGroupID: shared.NewID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestScanService_CreateScan_NoTargetOrAssetGroup(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	input := scanservice.CreateScanInput{
		TenantID: tenantID.String(),
		Name:     "Missing Target Scan",
		ScanType: "single",
		// No AssetGroupID and no Targets
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for missing asset group and targets")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestScanService_CreateScan_InvalidSchedule(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Cron Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
		ScheduleType: "crontab",
		ScheduleCron: "invalid-cron-expression",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid cron expression")
	}
}

func TestScanService_CreateScan_ScannerNotFound(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	// No tool registered with name "unknown-scanner"

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Bad Scanner Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "unknown-scanner",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for unknown scanner")
	}
}

func TestScanService_CreateScan_DisabledScanner(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	// Register a disabled tool
	deps.toolRepo.addTool("disabled-scanner", false)

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Disabled Scanner Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "disabled-scanner",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for disabled scanner")
	}
}

func TestScanService_CreateScan_WithTargets(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:    tenantID.String(),
		Name:        "Targets Scan",
		Targets:     []string{"example.com", "test.example.com"},
		ScanType:    "single",
		ScannerName: "nuclei",
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !result.HasTargets() {
		t.Error("expected scan to have targets")
	}
}

func TestScanService_CreateScan_RepositorySaveError(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	deps.toolRepo.addTool("nuclei", true)
	deps.scanRepo.createErr = errors.New("database connection lost")

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Test Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when repository save fails")
	}
}

// =============================================================================
// Tests: GetScan
// =============================================================================

func TestScanService_GetScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Get Test Scan", scan.ScanTypeSingle)

	result, err := svc.GetScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID != s.ID {
		t.Errorf("expected ID %s, got %s", s.ID, result.ID)
	}
	if result.Name != "Get Test Scan" {
		t.Errorf("expected name 'Get Test Scan', got %q", result.Name)
	}
}

func TestScanService_GetScan_NotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	_, err := svc.GetScan(context.Background(), tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestScanService_GetScan_InvalidID(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	_, err := svc.GetScan(context.Background(), tenantID.String(), "not-a-valid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestScanService_GetScan_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanService()

	_, err := svc.GetScan(context.Background(), "bad-tenant", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestScanService_GetScan_CrossTenantDenied(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Tenant A Scan", scan.ScanTypeSingle)

	_, err := svc.GetScan(context.Background(), otherTenantID.String(), s.ID.String())
	if err == nil {
		t.Fatal("expected error for cross-tenant access")
	}
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-tenant access, got %v", err)
	}
}

// =============================================================================
// Tests: UpdateScan
// =============================================================================

func TestScanService_UpdateScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Original Name", scan.ScanTypeSingle)

	input := scanservice.UpdateScanInput{
		TenantID:    tenantID.String(),
		ScanID:      s.ID.String(),
		Name:        "Updated Name",
		Description: "Updated description",
	}

	result, err := svc.UpdateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %q", result.Name)
	}
	if result.Description != "Updated description" {
		t.Errorf("expected description 'Updated description', got %q", result.Description)
	}
}

func TestScanService_UpdateScan_PartialUpdate(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Partial Update Scan", scan.ScanTypeSingle)
	originalName := s.Name

	// Only update description (leave name empty to keep original)
	input := scanservice.UpdateScanInput{
		TenantID:    tenantID.String(),
		ScanID:      s.ID.String(),
		Description: "New description",
	}

	result, err := svc.UpdateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// Name should remain unchanged
	if result.Name != originalName {
		t.Errorf("expected name %q to remain unchanged, got %q", originalName, result.Name)
	}
	if result.Description != "New description" {
		t.Errorf("expected description 'New description', got %q", result.Description)
	}
}

func TestScanService_UpdateScan_NotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	input := scanservice.UpdateScanInput{
		TenantID: tenantID.String(),
		ScanID:   shared.NewID().String(),
		Name:     "Updated",
	}

	_, err := svc.UpdateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestScanService_UpdateScan_Tags(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Tags Scan", scan.ScanTypeSingle)

	input := scanservice.UpdateScanInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
		Tags:     []string{"new-tag-1", "new-tag-2"},
	}

	result, err := svc.UpdateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(result.Tags))
	}
}

func TestScanService_UpdateScan_Schedule(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Schedule Update Scan", scan.ScanTypeSingle)

	scheduleTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	input := scanservice.UpdateScanInput{
		TenantID:     tenantID.String(),
		ScanID:       s.ID.String(),
		ScheduleType: "daily",
		ScheduleTime: &scheduleTime,
		Timezone:     "UTC",
	}

	result, err := svc.UpdateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScheduleType != scan.ScheduleDaily {
		t.Errorf("expected schedule type daily, got %s", result.ScheduleType)
	}
}

// =============================================================================
// Tests: DeleteScan
// =============================================================================

func TestScanService_DeleteScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Delete Test", scan.ScanTypeSingle)

	err := svc.DeleteScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	_, err = svc.GetScan(context.Background(), tenantID.String(), s.ID.String())
	if !errors.Is(err, shared.ErrNotFound) {
		t.Error("expected scan to be deleted")
	}
}

func TestScanService_DeleteScan_NotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	err := svc.DeleteScan(context.Background(), tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for deleting non-existent scan")
	}
}

func TestScanService_DeleteScan_AuditLogged(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Audit Delete Scan", scan.ScanTypeSingle)

	err := svc.DeleteScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify audit event was logged
	found := false
	for _, e := range deps.auditSvc.events {
		if e.ResourceID == s.ID.String() && e.Success {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit event for scan deletion")
	}
}

// =============================================================================
// Tests: ListScans
// =============================================================================

func TestScanService_ListScans_WithFilters(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	// Create multiple scans
	createTestScanInRepo(deps, tenantID, "Scan A", scan.ScanTypeSingle)
	createTestScanInRepo(deps, tenantID, "Scan B", scan.ScanTypeSingle)
	createTestScanInRepo(deps, tenantID, "Scan C", scan.ScanTypeWorkflow)

	input := scanservice.ListScansInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListScans(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 3 {
		t.Errorf("expected total 3, got %d", result.Total)
	}
}

func TestScanService_ListScans_Pagination(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	for i := 0; i < 5; i++ {
		createTestScanInRepo(deps, tenantID, "Scan-"+string(rune('A'+i)), scan.ScanTypeSingle)
	}

	input := scanservice.ListScansInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  2,
	}

	result, err := svc.ListScans(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if result.TotalPages != 3 {
		t.Errorf("expected 3 pages, got %d", result.TotalPages)
	}
}

func TestScanService_ListScans_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanService()

	input := scanservice.ListScansInput{
		TenantID: "invalid",
		Page:     1,
		PerPage:  10,
	}

	_, err := svc.ListScans(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestScanService_ListScans_EmptyResult(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	input := scanservice.ListScansInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  10,
	}

	result, err := svc.ListScans(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
}

// =============================================================================
// Tests: TriggerScan
// =============================================================================

func TestScanService_TriggerScan_SingleScanner_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Trigger Single Scan", scan.ScanTypeSingle)

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	run, err := svc.TriggerScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if run == nil {
		t.Fatal("expected run result, got nil")
	}
	if run.Status != pipeline.RunStatusRunning {
		t.Errorf("expected run status running, got %s", run.Status)
	}
}

func TestScanService_TriggerScan_ScanNotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   shared.NewID().String(),
	}

	_, err := svc.TriggerScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for scan not found")
	}
}

func TestScanService_TriggerScan_ScanNotActive(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Paused Scan", scan.ScanTypeSingle)
	_ = s.Pause() // Pause the scan

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	_, err := svc.TriggerScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for paused scan")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestScanService_TriggerScan_NoAgentAvailable(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("nuclei", true)
	deps.agentSelector.available = false
	deps.agentSelector.message = "no agents online"

	s := createTestScanInRepo(deps, tenantID, "No Agent Scan", scan.ScanTypeSingle)

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	_, err := svc.TriggerScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when no agent available")
	}
}

func TestScanService_TriggerScan_ToolDisabledAtTriggerTime(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	// Create scan with active tool, then disable it
	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Disabled Tool Scan", scan.ScanTypeSingle)

	// Now disable the tool
	deps.toolRepo.tools["nuclei"].IsActive = false

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	_, err := svc.TriggerScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when tool is disabled at trigger time")
	}
}

func TestScanService_TriggerScan_ConcurrentLimitExceeded(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Concurrent Limit Scan", scan.ScanTypeSingle)

	// Set up the run repo to return limit exceeded error
	deps.runRepo.createLimitErr = shared.NewDomainError(
		"CONCURRENT_LIMIT_EXCEEDED",
		"maximum concurrent runs exceeded",
		shared.ErrValidation,
	)

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	_, err := svc.TriggerScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when concurrent limit exceeded")
	}
}

func TestScanService_TriggerScan_Workflow_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	// Create workflow scan
	s := createTestScanInRepo(deps, tenantID, "Trigger Workflow Scan", scan.ScanTypeWorkflow)

	// Add steps to the pipeline
	pipelineID := *s.PipelineID
	deps.stepRepo.steps[pipelineID.String()] = []*pipeline.Step{
		{
			ID:         shared.NewID(),
			PipelineID: pipelineID,
			StepKey:    "scan-step",
			StepOrder:  1,
			Tool:       "nuclei",
		},
	}
	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	run, err := svc.TriggerScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if run == nil {
		t.Fatal("expected run, got nil")
	}
}

// =============================================================================
// Tests: GetScanStatus (via GetScan status field)
// =============================================================================

func TestScanService_GetScanStatus_Active(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Status Scan", scan.ScanTypeSingle)

	result, err := svc.GetScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != scan.StatusActive {
		t.Errorf("expected status active, got %s", result.Status)
	}
}

func TestScanService_GetScanStatus_Paused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Paused Status Scan", scan.ScanTypeSingle)
	_ = s.Pause()

	result, err := svc.GetScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != scan.StatusPaused {
		t.Errorf("expected status paused, got %s", result.Status)
	}
}

// =============================================================================
// Tests: ActivateScan / PauseScan / DisableScan
// =============================================================================

func TestScanService_ActivateScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Activate Scan", scan.ScanTypeSingle)
	_ = s.Pause()

	result, err := svc.ActivateScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != scan.StatusActive {
		t.Errorf("expected status active, got %s", result.Status)
	}
}

func TestScanService_PauseScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Pause Scan", scan.ScanTypeSingle)

	result, err := svc.PauseScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != scan.StatusPaused {
		t.Errorf("expected status paused, got %s", result.Status)
	}
}

func TestScanService_DisableScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Disable Scan", scan.ScanTypeSingle)

	result, err := svc.DisableScan(context.Background(), tenantID.String(), s.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Status != scan.StatusDisabled {
		t.Errorf("expected status disabled, got %s", result.Status)
	}
}

// =============================================================================
// Tests: CloneScan
// =============================================================================

func TestScanService_CloneScan_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	original := createTestScanInRepo(deps, tenantID, "Original Scan", scan.ScanTypeSingle)

	clone, err := svc.CloneScan(context.Background(), tenantID.String(), original.ID.String(), "Cloned Scan")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if clone.Name != "Cloned Scan" {
		t.Errorf("expected name 'Cloned Scan', got %q", clone.Name)
	}
	if clone.ID == original.ID {
		t.Error("clone should have a different ID")
	}
	if clone.ScanType != original.ScanType {
		t.Errorf("expected same scan type, got %s", clone.ScanType)
	}
}

func TestScanService_CloneScan_NotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	_, err := svc.CloneScan(context.Background(), tenantID.String(), shared.NewID().String(), "Clone")
	if err == nil {
		t.Fatal("expected error for cloning non-existent scan")
	}
}

// =============================================================================
// Tests: GetStats
// =============================================================================

func TestScanService_GetStats_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	createTestScanInRepo(deps, tenantID, "Stats Scan 1", scan.ScanTypeSingle)
	createTestScanInRepo(deps, tenantID, "Stats Scan 2", scan.ScanTypeSingle)

	stats, err := svc.GetStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("expected total 2, got %d", stats.Total)
	}
}

func TestScanService_GetStats_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanService()

	_, err := svc.GetStats(context.Background(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// =============================================================================
// Tests: BulkActivate / BulkPause / BulkDisable / BulkDelete
// =============================================================================

func TestScanService_BulkActivate_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s1 := createTestScanInRepo(deps, tenantID, "Bulk A", scan.ScanTypeSingle)
	s2 := createTestScanInRepo(deps, tenantID, "Bulk B", scan.ScanTypeSingle)
	_ = s1.Pause()
	_ = s2.Pause()

	result, err := svc.BulkActivate(context.Background(), tenantID.String(), []string{s1.ID.String(), s2.ID.String()})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Successful) != 2 {
		t.Errorf("expected 2 successful, got %d", len(result.Successful))
	}
	if len(result.Failed) != 0 {
		t.Errorf("expected 0 failed, got %d", len(result.Failed))
	}
}

func TestScanService_BulkDelete_PartialFailure(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s1 := createTestScanInRepo(deps, tenantID, "Bulk Delete A", scan.ScanTypeSingle)
	nonExistentID := shared.NewID().String()

	result, err := svc.BulkDelete(context.Background(), tenantID.String(), []string{s1.ID.String(), nonExistentID})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.Successful) != 1 {
		t.Errorf("expected 1 successful, got %d", len(result.Successful))
	}
	if len(result.Failed) != 1 {
		t.Errorf("expected 1 failed, got %d", len(result.Failed))
	}
}

// =============================================================================
// Tests: DeactivateScansByPipeline (cascade)
// =============================================================================

func TestScanService_DeactivateScansByPipeline_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	pipelineID := shared.NewID()
	tmpl := &pipeline.Template{ID: pipelineID, TenantID: tenantID, IsActive: true, Name: "cascade-test-pipeline"}
	deps.templateRepo.templates[pipelineID.String()] = tmpl

	// Create two active scans using this pipeline
	s1, _ := scan.NewScan(tenantID, "Pipeline Scan 1", shared.NewID(), scan.ScanTypeWorkflow)
	_ = s1.SetWorkflow(pipelineID)
	deps.scanRepo.addScan(s1)

	s2, _ := scan.NewScan(tenantID, "Pipeline Scan 2", shared.NewID(), scan.ScanTypeWorkflow)
	_ = s2.SetWorkflow(pipelineID)
	deps.scanRepo.addScan(s2)

	deps.scanRepo.listByPipelineID = []*scan.Scan{s1, s2}

	count, err := svc.DeactivateScansByPipeline(context.Background(), pipelineID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 paused, got %d", count)
	}

	// Verify scans are paused
	for _, s := range []*scan.Scan{s1, s2} {
		if s.Status != scan.StatusPaused {
			t.Errorf("expected scan %s to be paused, got %s", s.ID, s.Status)
		}
	}
}

func TestScanService_DeactivateScansByPipeline_SkipsAlreadyPaused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	pipelineID := shared.NewID()

	s1, _ := scan.NewScan(tenantID, "Already Paused Scan", shared.NewID(), scan.ScanTypeWorkflow)
	_ = s1.SetWorkflow(pipelineID)
	_ = s1.Pause()
	deps.scanRepo.addScan(s1)

	deps.scanRepo.listByPipelineID = []*scan.Scan{s1}

	count, err := svc.DeactivateScansByPipeline(context.Background(), pipelineID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 paused (already paused), got %d", count)
	}
}

// =============================================================================
// Tests: ListScanRuns
// =============================================================================

func TestScanService_ListScanRuns_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	s := createTestScanInRepo(deps, tenantID, "Runs Scan", scan.ScanTypeSingle)

	result, err := svc.ListScanRuns(context.Background(), tenantID.String(), s.ID.String(), 1, 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result map, got nil")
	}
}

func TestScanService_ListScanRuns_ScanNotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	_, err := svc.ListScanRuns(context.Background(), tenantID.String(), shared.NewID().String(), 1, 10)
	if err == nil {
		t.Fatal("expected error for scan not found")
	}
}

func TestScanService_ListScanRuns_InvalidIDs(t *testing.T) {
	svc, _ := newTestScanService()

	_, err := svc.ListScanRuns(context.Background(), "bad-tenant", shared.NewID().String(), 1, 10)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}

	_, err = svc.ListScanRuns(context.Background(), shared.NewID().String(), "bad-scan-id", 1, 10)
	if err == nil {
		t.Fatal("expected error for invalid scan ID")
	}
}

// =============================================================================
// Tests: GetOverviewStats
// =============================================================================

func TestScanService_GetOverviewStats_Success(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	stats, err := svc.GetOverviewStats(context.Background(), tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats == nil {
		t.Fatal("expected stats, got nil")
	}
}

func TestScanService_GetOverviewStats_InvalidTenantID(t *testing.T) {
	svc, _ := newTestScanService()

	_, err := svc.GetOverviewStats(context.Background(), "invalid-id")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// =============================================================================
// Tests: CreateScan with crontab schedule
// =============================================================================

func TestScanService_CreateScan_ValidCrontab(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Crontab Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
		ScheduleType: "crontab",
		ScheduleCron: "0 2 * * *", // Every day at 2am
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScheduleType != scan.ScheduleCrontab {
		t.Errorf("expected crontab schedule, got %s", result.ScheduleType)
	}
	if result.NextRunAt == nil {
		t.Error("expected next_run_at to be computed for crontab")
	}
}

func TestScanService_CreateScan_InvalidTimezone(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	deps.toolRepo.addTool("nuclei", true)

	scheduleTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Bad TZ Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
		ScheduleType: "daily",
		ScheduleTime: &scheduleTime,
		Timezone:     "Invalid/Timezone",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid timezone")
	}
}

// =============================================================================
// Tests: CreateScan with agent preference
// =============================================================================

func TestScanService_CreateScan_AgentPreference(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:        tenantID.String(),
		Name:            "Tenant Agent Scan",
		AssetGroupID:    ag.ID().String(),
		ScanType:        "single",
		ScannerName:     "nuclei",
		AgentPreference: "tenant",
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.AgentPreference != scan.AgentPreferenceTenant {
		t.Errorf("expected agent preference 'tenant', got %s", result.AgentPreference)
	}
}

// =============================================================================
// Tests: CreateScan with multiple asset groups
// =============================================================================

func TestScanService_CreateScan_MultipleAssetGroups(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag1, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "group-1", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	ag2, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "group-2", assetgroup.EnvironmentStaging, assetgroup.CriticalityMedium)
	deps.assetGroupRepo.groups[ag1.ID().String()] = ag1
	deps.assetGroupRepo.groups[ag2.ID().String()] = ag2
	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:      tenantID.String(),
		Name:          "Multi Group Scan",
		AssetGroupIDs: []string{ag1.ID().String(), ag2.ID().String()},
		ScanType:      "single",
		ScannerName:   "nuclei",
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result.AssetGroupIDs) != 2 {
		t.Errorf("expected 2 asset group IDs, got %d", len(result.AssetGroupIDs))
	}
}

// =============================================================================
// Tests: Security validation integration
// =============================================================================

func TestScanService_CreateScan_CronSecurityValidationFails(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	deps.toolRepo.addTool("nuclei", true)
	deps.secValidator.cronErr = errors.New("cron expression contains forbidden characters")

	input := scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Cron Inject Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "nuclei",
		ScheduleType: "crontab",
		ScheduleCron: "$(malicious_cmd)",
	}

	_, err := svc.CreateScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for security validation failure")
	}
}
