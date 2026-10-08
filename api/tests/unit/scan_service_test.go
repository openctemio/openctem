package unit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	assettyperef "github.com/openctemio/openctem/api/pkg/domain/asset"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/templatesource"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// =============================================================================
// Mock: scan.Repository
// =============================================================================

type mockScanRepo struct {
	scans map[string]*scan.Scan

	// lastListFilter is the filter of the most recent List call.
	lastListFilter scan.Filter

	// Error overrides for specific methods
	createErr            error
	getByTenantErr       error
	updateErr            error
	deleteErr            error
	listErr              error
	listDueErr           error
	statsErr             error
	listByScanWorkflowID []*scan.Scan
	listByScanWorkflowE  error

	updateCalls int         // full-row Update calls
	refreshes   []shared.ID // RefreshRunSummary calls (scan ids)
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

func (m *mockScanRepo) List(_ context.Context, filter scan.Filter, page pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	m.lastListFilter = filter
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
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.scans[s.ID.String()] = s
	return nil
}

func (m *mockScanRepo) Delete(_ context.Context, _ shared.ID, id shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.scans[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.scans, id.String())
	return nil
}

func (m *mockScanRepo) CountScheduledWithoutNextRun(_ context.Context) (int, []string, error) {
	return 0, nil, nil
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

func (m *mockScanRepo) UpdateNextRunAt(_ context.Context, _ shared.ID, _ shared.ID, _ *time.Time) error {
	return nil
}

func (m *mockScanRepo) RefreshRunSummary(_ context.Context, _ shared.ID, scanID shared.ID) error {
	m.refreshes = append(m.refreshes, scanID)
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

func (m *mockScanRepo) ListByScanWorkflowID(_ context.Context, _ shared.ID) ([]*scan.Scan, error) {
	if m.listByScanWorkflowE != nil {
		return nil, m.listByScanWorkflowE
	}
	return m.listByScanWorkflowID, nil
}

func (m *mockScanRepo) UpdateStatusByAssetGroupID(_ context.Context, _ shared.ID, _ scan.Status) error {
	return nil
}

func (m *mockScanRepo) ClaimScheduledRun(_ context.Context, _ shared.ID, _ shared.ID, _ time.Time, _ *time.Time) (bool, error) {
	return true, nil
}

// addScan is a helper to insert a scan into the mock.
func (m *mockScanRepo) addScan(s *scan.Scan) {
	m.scans[s.ID.String()] = s
}

// =============================================================================
// Mock: scanrun.TemplateRepository
// =============================================================================

type mockTemplateRepo struct {
	templates map[string]*scanworkflow.Workflow
}

func newMockTemplateRepo() *mockTemplateRepo {
	return &mockTemplateRepo{templates: make(map[string]*scanworkflow.Workflow)}
}

func (m *mockTemplateRepo) Create(_ context.Context, t *scanworkflow.Workflow) error {
	m.templates[t.ID.String()] = t
	return nil
}

func (m *mockTemplateRepo) GetByID(_ context.Context, id shared.ID) (*scanworkflow.Workflow, error) {
	t, ok := m.templates[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *mockTemplateRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*scanworkflow.Workflow, error) {
	t, ok := m.templates[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *mockTemplateRepo) GetByName(_ context.Context, _ shared.ID, _ string, _ int) (*scanworkflow.Workflow, error) {
	return nil, shared.ErrNotFound
}

func (m *mockTemplateRepo) List(_ context.Context, _ scanworkflow.Filter, _ pagination.Pagination) (pagination.Result[*scanworkflow.Workflow], error) {
	return pagination.Result[*scanworkflow.Workflow]{}, nil
}

func (m *mockTemplateRepo) Update(_ context.Context, _ *scanworkflow.Workflow) error { return nil }
func (m *mockTemplateRepo) Delete(_ context.Context, _ shared.ID) error              { return nil }
func (m *mockTemplateRepo) Remove(_ context.Context, _, _ shared.ID) (bool, error)   { return false, nil }
func (m *mockTemplateRepo) DeleteInTx(_ context.Context, _ *sql.Tx, _ shared.ID) error {
	return nil
}
func (m *mockTemplateRepo) GetWithSteps(_ context.Context, id shared.ID) (*scanworkflow.Workflow, error) {
	if t, ok := m.templates[id.String()]; ok {
		return t, nil
	}
	return nil, shared.ErrNotFound
}
func (m *mockTemplateRepo) GetSystemTemplateByID(_ context.Context, _ shared.ID) (*scanworkflow.Workflow, error) {
	return nil, nil
}
func (m *mockTemplateRepo) ListWithSystemTemplates(_ context.Context, _ shared.ID, _ scanworkflow.Filter, _ pagination.Pagination) (pagination.Result[*scanworkflow.Workflow], error) {
	return pagination.Result[*scanworkflow.Workflow]{}, nil
}

// =============================================================================
// Mock: assetgroup.Repository
// =============================================================================

type mockAssetGroupRepo struct {
	groups          map[string]*assetgroup.AssetGroup
	assetTypeCounts map[assettyperef.TypeRef]int64 // for CountAssetsByType
	members         map[shared.ID][]*assetgroup.GroupAsset
}

func newMockAssetGroupRepo() *mockAssetGroupRepo {
	return &mockAssetGroupRepo{
		groups:          make(map[string]*assetgroup.AssetGroup),
		assetTypeCounts: make(map[assettyperef.TypeRef]int64),
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

func (m *mockAssetGroupRepo) GetByTenantAndID(ctx context.Context, _, id shared.ID) (*assetgroup.AssetGroup, error) {
	return m.GetByID(ctx, id)
}

func (m *mockAssetGroupRepo) Update(_ context.Context, _ shared.ID, _ *assetgroup.AssetGroup) error {
	return nil
}
func (m *mockAssetGroupRepo) Delete(_ context.Context, _ shared.ID, _ shared.ID) error { return nil }
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
func (m *mockAssetGroupRepo) AddAssets(_ context.Context, _ shared.ID, ids []shared.ID) (int, error) {
	return len(ids), nil
}
func (m *mockAssetGroupRepo) FilterTenantAssetIDs(_ context.Context, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	return ids, nil
}
func (m *mockAssetGroupRepo) RemoveAssets(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}
func (m *mockAssetGroupRepo) GetGroupAssets(_ context.Context, id shared.ID, page pagination.Pagination, _ *shared.DataScope) (pagination.Result[*assetgroup.GroupAsset], error) {
	a := m.members[id]
	return pagination.NewResult(a, int64(len(a)), page), nil
}
func (m *mockAssetGroupRepo) ListScanMembers(_ context.Context, q assetgroup.ScanMemberQuery) (*assetgroup.ScanMemberPage, error) {
	page := &assetgroup.ScanMemberPage{}
	if !q.AfterID.IsZero() {
		return page, nil // one page holds every member
	}
	for _, a := range m.members[q.GroupID] {
		if a.Status == "archived" {
			page.ArchivedCount++
			continue
		}
		page.Members = append(page.Members, &assetgroup.ScanMember{ID: a.ID, Name: a.Name, Type: a.Type, Status: a.Status})
	}
	return page, nil
}
func (m *mockAssetGroupRepo) GetGroupFindings(_ context.Context, _ shared.ID, _ pagination.Pagination, _ *shared.DataScope) (pagination.Result[*assetgroup.GroupFinding], error) {
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
func (m *mockAssetGroupRepo) CountAssetsByType(_ context.Context, _ shared.ID) (map[assettyperef.TypeRef]int64, error) {
	return m.assetTypeCounts, nil
}

// =============================================================================
// Mock: scanrun.RunRepository
// =============================================================================

type mockRunRepo struct {
	runs                map[string]*scanrundom.Run
	createLimitErr      error
	activeByScanCount   int
	activeByTenantCount int
}

func newMockRunRepo() *mockRunRepo {
	return &mockRunRepo{runs: make(map[string]*scanrundom.Run)}
}

func (m *mockRunRepo) Create(_ context.Context, r *scanrundom.Run) error {
	m.runs[r.ID.String()] = r
	return nil
}

func (m *mockRunRepo) GetByID(_ context.Context, id shared.ID) (*scanrundom.Run, error) {
	r, ok := m.runs[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return r, nil
}

func (m *mockRunRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*scanrundom.Run, error) {
	r, ok := m.runs[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return r, nil
}

func (m *mockRunRepo) List(_ context.Context, _ scanrundom.RunFilter, _ pagination.Pagination) (pagination.Result[*scanrundom.Run], error) {
	return pagination.Result[*scanrundom.Run]{}, nil
}

func (m *mockRunRepo) ListByScanID(_ context.Context, _ shared.ID, _, _ int) ([]*scanrundom.Run, int64, error) {
	return nil, 0, nil
}

func (m *mockRunRepo) Update(_ context.Context, r *scanrundom.Run) error {
	m.runs[r.ID.String()] = r
	return nil
}

func (m *mockRunRepo) Delete(_ context.Context, _ shared.ID) error { return nil }
func (m *mockRunRepo) GetWithStepRuns(_ context.Context, _ shared.ID) (*scanrundom.Run, error) {
	return nil, nil
}
func (m *mockRunRepo) GetActiveByScanWorkflowID(_ context.Context, _ shared.ID) ([]*scanrundom.Run, error) {
	return nil, nil
}
func (m *mockRunRepo) GetActiveByAssetID(_ context.Context, _ shared.ID) ([]*scanrundom.Run, error) {
	return nil, nil
}
func (m *mockRunRepo) CountActiveByScanWorkflowID(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockRunRepo) CountActiveByTenantID(_ context.Context, _ shared.ID) (int, error) {
	return m.activeByTenantCount, nil
}
func (m *mockRunRepo) CountActiveByScanID(_ context.Context, _ shared.ID) (int, error) {
	return m.activeByScanCount, nil
}
func (m *mockRunRepo) CreateRunIfUnderLimit(_ context.Context, r *scanrundom.Run, _, _ int) error {
	if m.createLimitErr != nil {
		return m.createLimitErr
	}
	m.runs[r.ID.String()] = r
	return nil
}
func (m *mockRunRepo) UpdateStats(_ context.Context, _ shared.ID, _, _, _, _ int) error { return nil }
func (m *mockRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ scanrundom.RunStatus, _ string) error {
	return nil
}
func (m *mockRunRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (scanrundom.RunStats, error) {
	return scanrundom.RunStats{}, nil
}
func (m *mockRunRepo) MarkTimedOutRuns(_ context.Context) (int64, error) {
	return 0, nil
}
func (m *mockRunRepo) ListPendingRetries(_ context.Context, _ int) ([]scanrundom.RetryCandidate, error) {
	return nil, nil
}
func (m *mockRunRepo) ReleaseFailedRetryDispatch(_ context.Context, _ shared.ID) error {
	return nil
}

// =============================================================================
// Mock: scanrun.StepRepository
// =============================================================================

type mockStepRepo struct {
	steps map[string][]*scanworkflow.Step // keyed by scan workflow ID
}

func newMockStepRepo() *mockStepRepo {
	return &mockStepRepo{steps: make(map[string][]*scanworkflow.Step)}
}

func (m *mockStepRepo) Create(_ context.Context, _ *scanworkflow.Step) error        { return nil }
func (m *mockStepRepo) CreateBatch(_ context.Context, _ []*scanworkflow.Step) error { return nil }
func (m *mockStepRepo) GetByID(_ context.Context, _ shared.ID) (*scanworkflow.Step, error) {
	return nil, nil
}
func (m *mockStepRepo) GetByScanWorkflowID(_ context.Context, scanWorkflowID shared.ID) ([]*scanworkflow.Step, error) {
	steps, ok := m.steps[scanWorkflowID.String()]
	if !ok {
		return []*scanworkflow.Step{}, nil
	}
	return steps, nil
}
func (m *mockStepRepo) GetByKey(_ context.Context, _ shared.ID, _ string) (*scanworkflow.Step, error) {
	return nil, nil
}
func (m *mockStepRepo) Update(_ context.Context, _ *scanworkflow.Step) error        { return nil }
func (m *mockStepRepo) Delete(_ context.Context, _ shared.ID) error                 { return nil }
func (m *mockStepRepo) DeleteByScanWorkflowID(_ context.Context, _ shared.ID) error { return nil }
func (m *mockStepRepo) DeleteByScanWorkflowIDInTx(_ context.Context, _ *sql.Tx, _ shared.ID) error {
	return nil
}
func (m *mockStepRepo) Reorder(_ context.Context, _ shared.ID, _ map[string]int) error { return nil }
func (m *mockStepRepo) FindScanWorkflowIDsByToolName(_ context.Context, _ shared.ID, _ string) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockStepRepo) MutateSteps(_ context.Context, _, scanWorkflowID shared.ID, mutate func([]*scanworkflow.Step) ([]*scanworkflow.Step, error)) ([]*scanworkflow.Step, error) {
	next, err := mutate(m.steps[scanWorkflowID.String()])
	if err != nil {
		return nil, err
	}
	m.steps[scanWorkflowID.String()] = next
	return next, nil
}

// =============================================================================
// Mock: scanrun.StepRunRepository
// =============================================================================

type mockStepRunRepo struct{}

func (m *mockStepRunRepo) Create(_ context.Context, _ *scanrundom.StepRun) error        { return nil }
func (m *mockStepRunRepo) CreateBatch(_ context.Context, _ []*scanrundom.StepRun) error { return nil }
func (m *mockStepRunRepo) GetByID(_ context.Context, _ shared.ID) (*scanrundom.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) GetByScanRunID(_ context.Context, _ shared.ID) ([]*scanrundom.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) GetByStepKey(_ context.Context, _ shared.ID, _ string) (*scanrundom.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) List(_ context.Context, _ scanrundom.StepRunFilter) ([]*scanrundom.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) Update(_ context.Context, _ *scanrundom.StepRun) error { return nil }
func (m *mockStepRunRepo) Delete(_ context.Context, _ shared.ID) error           { return nil }
func (m *mockStepRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ scanrundom.StepRunStatus, _, _ string) error {
	return nil
}
func (m *mockStepRunRepo) AssignSensor(_ context.Context, _, _, _ shared.ID) error {
	return nil
}
func (m *mockStepRunRepo) Complete(_ context.Context, _ shared.ID, _ int, _ map[string]any) error {
	return nil
}
func (m *mockStepRunRepo) GetPendingByDependencies(_ context.Context, _ shared.ID, _ []string) ([]*scanrundom.StepRun, error) {
	return nil, nil
}
func (m *mockStepRunRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (scanrundom.RunStats, error) {
	return scanrundom.RunStats{}, nil
}

// =============================================================================
// Mock: commanddom.Repository
// =============================================================================

type mockCommandRepo struct {
	commands map[string]*commanddom.Command
}

func newMockCommandRepo() *mockCommandRepo {
	return &mockCommandRepo{commands: make(map[string]*commanddom.Command)}
}

func (m *mockCommandRepo) Create(_ context.Context, cmd *commanddom.Command) error {
	m.commands[cmd.ID.String()] = cmd
	return nil
}
func (m *mockCommandRepo) GetByID(_ context.Context, _ shared.ID) (*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetPendingForSensor(_ context.Context, _ shared.ID, _ *shared.ID, _ []string, _ int) ([]*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) ClaimForSensor(_ context.Context, _, _ shared.ID, _ string) (bool, error) {
	return true, nil
}
func (m *mockCommandRepo) List(_ context.Context, _ commanddom.Filter, _ pagination.Pagination) (pagination.Result[*commanddom.Command], error) {
	return pagination.Result[*commanddom.Command]{}, nil
}
func (m *mockCommandRepo) Update(_ context.Context, _ *commanddom.Command) error    { return nil }
func (m *mockCommandRepo) Delete(_ context.Context, _ shared.ID, _ shared.ID) error { return nil }
func (m *mockCommandRepo) FindExpired(_ context.Context) ([]*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetByAuthTokenHash(_ context.Context, _ string) (*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) CountActivePlatformJobsByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockCommandRepo) CountQueuedPlatformJobsByTenant(_ context.Context, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockCommandRepo) CountQueuedPlatformJobs(_ context.Context) (int, error) { return 0, nil }
func (m *mockCommandRepo) GetQueuedPlatformJobs(_ context.Context, _ int) ([]*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetNextPlatformJob(_ context.Context, _ shared.ID, _ []string, _ []string) (*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) UpdateQueuePriorities(_ context.Context) (int64, error) { return 0, nil }
func (m *mockCommandRepo) RecoverStuckJobs(_ context.Context, _, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) FindQueueExpiredPlatformJobs(_ context.Context, _ int) ([]*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) GetQueuePosition(_ context.Context, _ shared.ID) (*commanddom.QueuePosition, error) {
	return nil, nil
}
func (m *mockCommandRepo) ListPlatformJobsByTenant(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*commanddom.Command], error) {
	return pagination.Result[*commanddom.Command]{}, nil
}
func (m *mockCommandRepo) ListPlatformJobsAdmin(_ context.Context, _, _ *shared.ID, _ *commanddom.CommandStatus, _ pagination.Pagination) (pagination.Result[*commanddom.Command], error) {
	return pagination.Result[*commanddom.Command]{}, nil
}
func (m *mockCommandRepo) GetPlatformJobsBySensor(_ context.Context, _ shared.ID, _ *commanddom.CommandStatus) ([]*commanddom.Command, error) {
	return nil, nil
}
func (m *mockCommandRepo) ReleasePendingFromUnavailableSensors(_ context.Context) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) RecoverStuckTenantCommands(_ context.Context, _, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) FailExhaustedCommands(_ context.Context, _ int) (int64, error) {
	return 0, nil
}
func (m *mockCommandRepo) GetStatsByTenant(_ context.Context, _ shared.ID) (commanddom.CommandStats, error) {
	return commanddom.CommandStats{}, nil
}
func (m *mockCommandRepo) CancelByScanRunID(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
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
func (m *mockToolRepo) GetByName(_ context.Context, _ shared.ID, name string) (*tool.Tool, error) {
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
	// Return the first registered active tool so workflow step tool-resolution
	// can succeed in tests that seed a tool; unseeded tests still get nil.
	for _, t := range m.tools {
		if t.IsActive {
			return t, nil
		}
	}
	return nil, nil
}
func (m *mockToolRepo) Update(_ context.Context, _ *tool.Tool) error       { return nil }
func (m *mockToolRepo) Delete(_ context.Context, _ shared.ID) error        { return nil }
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
// Mock: SensorSelector
// =============================================================================

type mockSensorSelector struct {
	available      bool
	message        string
	canUsePlatform bool
	platformReason string
	selectResult   *scanservice.SelectSensorResult
	selectErr      error
}

func (m *mockSensorSelector) CheckSensorAvailability(_ context.Context, _ shared.ID, _ string, _ bool) *scanservice.SensorAvailability {
	return &scanservice.SensorAvailability{
		Available: m.available,
		Message:   m.message,
	}
}

func (m *mockSensorSelector) CanUsePlatformSensors(_ context.Context, _ shared.ID) (bool, string) {
	return m.canUsePlatform, m.platformReason
}

func (m *mockSensorSelector) SelectSensor(_ context.Context, _ scanservice.SelectSensorRequest) (*scanservice.SelectSensorResult, error) {
	if m.selectErr != nil {
		return nil, m.selectErr
	}
	if m.selectResult != nil {
		return m.selectResult, nil
	}
	return &scanservice.SelectSensorResult{
		Sensor:     &sensor.Sensor{},
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
	events   []scanservice.AuditEvent
	contexts []scanservice.AuditContext
}

func (m *mockAuditService) LogEvent(_ context.Context, actx scanservice.AuditContext, event scanservice.AuditEvent) error {
	m.events = append(m.events, event)
	m.contexts = append(m.contexts, actx)
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
	sensorSelector *mockSensorSelector
	secValidator   *mockSecurityValidator
	auditSvc       *mockAuditService
}

func newTestScanService(opts ...scanservice.ServiceOption) (*scanservice.Service, *testScanServiceDeps) {
	deps := &testScanServiceDeps{
		scanRepo:       newMockScanRepo(),
		templateRepo:   newMockTemplateRepo(),
		assetGroupRepo: newMockAssetGroupRepo(),
		runRepo:        newMockRunRepo(),
		stepRepo:       newMockStepRepo(),
		commandRepo:    newMockCommandRepo(),
		toolRepo:       newMockToolRepo(),
		sensorSelector: &mockSensorSelector{
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
		deps.sensorSelector,
		deps.secValidator,
		log,
		append([]scanservice.ServiceOption{scanservice.WithAuditService(deps.auditSvc)}, opts...)...,
	)
	// A workflow scan's first steps are queued by the scan run service, the
	// one step dispatcher (research/27 P0-2), as in production.
	svc.SetStepQueuer(scanrun.NewService(deps.templateRepo, deps.stepRepo, deps.runRepo,
		&mockStepRunRepo{}, newMockSensorRepo(), deps.commandRepo, nil, log,
		scanrun.WithToolRepo(deps.toolRepo), scanrun.WithWebScope(noWebScope{})))

	return svc, deps
}

// createTestScanInRepo is a helper to create a scan entity in the mock repo directly.
func createTestScanInRepo(deps *testScanServiceDeps, tenantID shared.ID, name string, scanType scan.ScanType) *scan.Scan {
	agID := shared.NewID()
	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group-"+name, assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	if deps.assetGroupRepo.members == nil {
		deps.assetGroupRepo.members = map[shared.ID][]*assetgroup.GroupAsset{}
	}
	deps.assetGroupRepo.members[ag.ID()] = []*assetgroup.GroupAsset{{ID: shared.NewID(), Name: "app.example.com"}}

	s, _ := scan.NewScan(tenantID, name, ag.ID(), scanType)
	if scanType == scan.ScanTypeSingle {
		_ = s.SetSingleScanner("nuclei", map[string]any{}, 1)
	} else {
		scanWorkflowID := shared.NewID()
		tmpl := &scanworkflow.Workflow{ID: scanWorkflowID, TenantID: tenantID, IsActive: true, Name: "test-pipeline"}
		deps.templateRepo.templates[scanWorkflowID.String()] = tmpl
		_ = s.SetWorkflow(scanWorkflowID)
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

	// Create scan workflow
	scanWorkflowID := shared.NewID()
	tmpl := &scanworkflow.Workflow{ID: scanWorkflowID, TenantID: tenantID, IsActive: true, Name: "test-pipeline"}
	deps.templateRepo.templates[scanWorkflowID.String()] = tmpl

	input := scanservice.CreateScanInput{
		TenantID:       tenantID.String(),
		Name:           "Test Workflow Scan",
		AssetGroupID:   ag.ID().String(),
		ScanType:       "workflow",
		ScanWorkflowID: scanWorkflowID.String(),
		ScheduleType:   "manual",
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ScanType != scan.ScanTypeWorkflow {
		t.Errorf("expected scan type workflow, got %s", result.ScanType)
	}
	if result.ScanWorkflowID == nil || *result.ScanWorkflowID != scanWorkflowID {
		t.Errorf("expected pipeline ID %s", scanWorkflowID)
	}
}

// TestScanService_QuickScan_WorkflowRejectsInternalTarget asserts the workflow
// path now runs SSRF target validation (previously skipped entirely).
func TestScanService_QuickScan_WorkflowRejectsInternalTarget(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	scanWorkflowID := shared.NewID()
	deps.templateRepo.templates[scanWorkflowID.String()] = &scanworkflow.Workflow{
		ID: scanWorkflowID, TenantID: tenantID, IsActive: true, Name: "wf",
	}

	_, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
		TenantID:   tenantID.String(),
		Targets:    []string{"127.0.0.1"},
		WorkflowID: scanWorkflowID.String(),
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("workflow quick-scan with internal target: want ErrValidation, got %v", err)
	}
}

// TestScanService_QuickScan_WorkflowAppliesTargets asserts workflow-path targets
// are applied to the run rather than silently dropped: they must be persisted on
// the scan and surfaced in the dispatched step command payload (sensors read
// job.Payload["targets"]).
func TestScanService_QuickScan_WorkflowAppliesTargets(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	scanWorkflowID := shared.NewID()
	deps.templateRepo.templates[scanWorkflowID.String()] = &scanworkflow.Workflow{
		ID: scanWorkflowID, TenantID: tenantID, IsActive: true, Name: "wf",
	}
	step, err := scanworkflow.NewStep(scanWorkflowID, "scan", "Scan", 1, []string{"vulnscan"})
	if err != nil {
		t.Fatalf("NewStep: %v", err)
	}
	deps.stepRepo.steps[scanWorkflowID.String()] = []*scanworkflow.Step{step}
	deps.toolRepo.addTool("nuclei", true) // active tool matching the step capability

	targets := []string{"example.com", "test.example.com"}
	res, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
		TenantID:   tenantID.String(),
		Targets:    targets,
		WorkflowID: scanWorkflowID.String(),
	})
	if err != nil {
		t.Fatalf("workflow quick-scan: unexpected error: %v", err)
	}
	if res.TargetCount != len(targets) {
		t.Fatalf("target count = %d, want %d", res.TargetCount, len(targets))
	}

	// Targets must be persisted on the scan entity.
	sc := deps.scanRepo.scans[res.ScanID]
	if sc == nil || len(sc.Targets) != len(targets) {
		t.Fatalf("targets not persisted on scan: %+v", sc)
	}

	// The dispatched workflow step command must carry the targets at top level.
	if len(deps.commandRepo.commands) == 0 {
		t.Fatal("expected a workflow step command to be created")
	}
	found := false
	for _, cmd := range deps.commandRepo.commands {
		var p map[string]any
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			t.Fatalf("payload decode: %v", err)
		}
		if raw, ok := p["targets"].([]any); ok && len(raw) == len(targets) {
			found = true
		}
	}
	if !found {
		t.Fatal("workflow step command payload did not carry targets — silent-drop regression")
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

// A scan whose asset group is empty resolves to nothing: the trigger is
// refused, and no run or command is created.
func TestScanService_TriggerScan_EmptyAssetGroupRefused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Empty Group Scan", scan.ScanTypeSingle)
	deps.assetGroupRepo.members[s.AssetGroupID] = nil

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	})
	if err == nil || run != nil {
		t.Fatalf("want the trigger refused, got run %v, err %v", run, err)
	}
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "NO_TARGETS") {
		t.Fatalf("want NO_TARGETS validation error, got %v", err)
	}
}

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
	if run.Status != scanrundom.RunStatusRunning {
		t.Errorf("expected run status running, got %s", run.Status)
	}
}

// Triggering used to write the whole scan row back from the copy it read
// before dispatching: a pause or config edit saved while the trigger ran was
// silently undone. The trigger now refreshes the run summary from the runs
// and never rewrites the scan.
func TestScanService_TriggerScan_DoesNotRewriteTheScanRow(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "No clobber", scan.ScanTypeSingle)
	before := deps.scanRepo.updateCalls

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if got := deps.scanRepo.updateCalls - before; got != 0 {
		t.Errorf("TriggerScan rewrote the scan row %d time(s); it must not (stale copy clobbers concurrent edits)", got)
	}
	if run == nil || len(deps.scanRepo.refreshes) != 1 || deps.scanRepo.refreshes[0] != s.ID {
		t.Errorf("RefreshRunSummary calls = %v, want exactly [%s]", deps.scanRepo.refreshes, s.ID)
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

func TestScanService_TriggerScan_NoSensorAvailable(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("nuclei", true)
	deps.sensorSelector.available = false
	deps.sensorSelector.message = "no sensors online"

	s := createTestScanInRepo(deps, tenantID, "No Sensor Scan", scan.ScanTypeSingle)

	input := scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	}

	_, err := svc.TriggerScan(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when no sensor available")
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

	// Add steps to the scan workflow
	scanWorkflowID := *s.ScanWorkflowID
	deps.stepRepo.steps[scanWorkflowID.String()] = []*scanworkflow.Step{
		{
			ID:             shared.NewID(),
			ScanWorkflowID: scanWorkflowID,
			StepKey:        "scan-step",
			StepOrder:      1,
			Tool:           "nuclei",
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

// recordingVersions records the spec a workflow run was pinned to.
type recordingVersions struct {
	tenant, workflow shared.ID
	spec             scanworkflow.Spec
}

func (r *recordingVersions) PinVersion(_ context.Context, tenantID, workflowID shared.ID, spec scanworkflow.Spec) (int, string, error) {
	r.tenant, r.workflow, r.spec = tenantID, workflowID, spec
	return 4, "d1g3st", nil
}

func (r *recordingVersions) GetVersion(context.Context, shared.ID, shared.ID, int) (*scanworkflow.Spec, error) {
	return &r.spec, nil
}

// research/62 P0-10: a workflow scan's run is pinned, under the scan's
// tenant, to the workflow's spec as it starts.
func TestScanService_TriggerScan_Workflow_PinsVersion(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Pinned Workflow Scan", scan.ScanTypeWorkflow)
	scanWorkflowID := *s.ScanWorkflowID
	deps.stepRepo.steps[scanWorkflowID.String()] = []*scanworkflow.Step{
		{ID: shared.NewID(), ScanWorkflowID: scanWorkflowID, StepKey: "scan-step", StepOrder: 1, Tool: "nuclei"},
	}
	deps.toolRepo.addTool("nuclei", true)
	versions := &recordingVersions{}
	svc.SetWorkflowVersions(versions)

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: s.ID.String()})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if run.ScanWorkflowVersion != 4 || run.SpecDigest != "d1g3st" {
		t.Fatalf("run pinned to %d %q, want 4 d1g3st", run.ScanWorkflowVersion, run.SpecDigest)
	}
	if versions.tenant != tenantID || versions.workflow != scanWorkflowID {
		t.Fatalf("pinned under tenant %s workflow %s", versions.tenant, versions.workflow)
	}
	if len(versions.spec.Steps) != 1 || versions.spec.Steps[0].Tool != "nuclei" {
		t.Fatalf("pinned spec steps = %+v", versions.spec.Steps)
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

	actor := shared.NewID()
	clone, err := svc.CloneScan(context.Background(), tenantID.String(), original.ID.String(), "Cloned Scan", actor.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// The person cloning owns the clone: its schedule never runs as the
	// system (research 21b H2).
	if clone.CreatedBy == nil || *clone.CreatedBy != actor {
		t.Errorf("clone owner = %v, want the actor %s", clone.CreatedBy, actor)
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

func TestScanService_CloneScan_RequiresActor(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	original := createTestScanInRepo(deps, tenantID, "Original Scan", scan.ScanTypeSingle)
	if _, err := svc.CloneScan(context.Background(), tenantID.String(), original.ID.String(), "Clone", ""); err == nil {
		t.Fatal("a clone without an acting user must be refused (it would have no owner)")
	}
}

func TestScanService_CloneScan_NotFound(t *testing.T) {
	svc, _ := newTestScanService()
	tenantID := shared.NewID()

	_, err := svc.CloneScan(context.Background(), tenantID.String(), shared.NewID().String(), "Clone", shared.NewID().String())
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
// Tests: DeactivateScansByScanWorkflow (cascade)
// =============================================================================

func TestScanService_DeactivateScansByPipeline_Success(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	scanWorkflowID := shared.NewID()
	tmpl := &scanworkflow.Workflow{ID: scanWorkflowID, TenantID: tenantID, IsActive: true, Name: "cascade-test-pipeline"}
	deps.templateRepo.templates[scanWorkflowID.String()] = tmpl

	// Create two active scans using this scan workflow
	s1, _ := scan.NewScan(tenantID, "ScanRun Scan 1", shared.NewID(), scan.ScanTypeWorkflow)
	_ = s1.SetWorkflow(scanWorkflowID)
	deps.scanRepo.addScan(s1)

	s2, _ := scan.NewScan(tenantID, "ScanRun Scan 2", shared.NewID(), scan.ScanTypeWorkflow)
	_ = s2.SetWorkflow(scanWorkflowID)
	deps.scanRepo.addScan(s2)

	deps.scanRepo.listByScanWorkflowID = []*scan.Scan{s1, s2}

	count, err := svc.DeactivateScansByScanWorkflow(context.Background(), scanWorkflowID)
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
	scanWorkflowID := shared.NewID()

	s1, _ := scan.NewScan(tenantID, "Already Paused Scan", shared.NewID(), scan.ScanTypeWorkflow)
	_ = s1.SetWorkflow(scanWorkflowID)
	_ = s1.Pause()
	deps.scanRepo.addScan(s1)

	deps.scanRepo.listByScanWorkflowID = []*scan.Scan{s1}

	count, err := svc.DeactivateScansByScanWorkflow(context.Background(), scanWorkflowID)
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
// Tests: CreateScan with sensor preference
// =============================================================================

func TestScanService_CreateScan_SensorPreference(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag
	deps.toolRepo.addTool("nuclei", true)

	input := scanservice.CreateScanInput{
		TenantID:         tenantID.String(),
		Name:             "Tenant Sensor Scan",
		AssetGroupID:     ag.ID().String(),
		ScanType:         "single",
		ScannerName:      "nuclei",
		SensorPreference: "tenant",
	}

	result, err := svc.CreateScan(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.SensorPreference != scan.SensorPreferenceTenant {
		t.Errorf("expected sensor preference 'tenant', got %s", result.SensorPreference)
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

// Asset collectors are in the tool catalog (metadata.kind = "collector") so
// collector sensors can report them, but a scan must refuse them.
func TestScanService_CreateScan_CollectorToolRefused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	ag, _ := assetgroup.NewAssetGroupWithTenant(tenantID, "test-group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
	deps.assetGroupRepo.groups[ag.ID().String()] = ag

	deps.toolRepo.addTool("vcenter", true)
	deps.toolRepo.tools["vcenter"].Metadata = map[string]any{"kind": tool.KindCollector}

	_, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID:     tenantID.String(),
		Name:         "Collector Scan",
		AssetGroupID: ag.ID().String(),
		ScanType:     "single",
		ScannerName:  "vcenter",
	})
	if err == nil {
		t.Fatal("expected error for a collector tool")
	}
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "asset collector") {
		t.Errorf("err = %v, want a validation error naming the asset collector", err)
	}
}

func TestScanService_TriggerScan_CollectorToolRefused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	deps.toolRepo.addTool("ldap", true)
	s := createTestScanInRepo(deps, tenantID, "Collector Scan", scan.ScanTypeSingle)
	s.ScannerName = "ldap"
	deps.toolRepo.tools["ldap"].Metadata = map[string]any{"kind": tool.KindCollector}

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(),
		ScanID:   s.ID.String(),
	})
	if err == nil {
		t.Fatal("expected error when the scan's tool is a collector")
	}
	if !strings.Contains(err.Error(), "asset collector") {
		t.Errorf("err = %v, want it to name the asset collector", err)
	}
}

// Overlap policy for scheduled runs (D4): a scheduled occurrence while the
// previous run is still active is skipped, not stacked (up to 3 concurrent
// runs of the same scan used to pile up).
func TestScanService_TriggerScan_ScheduledSkipsWhileRunning(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Overlap", scan.ScanTypeSingle)
	deps.runRepo.activeByScanCount = 1

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
		TriggerType: scanworkflow.TriggerTypeSchedule, SkipIfRunning: true,
	})
	if !errors.Is(err, scanservice.ErrScanRunInProgress) {
		t.Fatalf("err = %v, want ErrScanRunInProgress", err)
	}

	// A manual trigger is not subject to the overlap policy.
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
	}); err != nil {
		t.Fatalf("manual trigger: %v", err)
	}
}

// Every run used to be recorded as trigger_type 'manual', scheduled ones too.
func TestScanService_TriggerScan_RecordsTriggerType(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Trigger type", scan.ScanTypeSingle)
	s.SetCreatedBy(shared.NewID()) // a scheduled run needs an owner

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.TriggerType != scanworkflow.TriggerTypeSchedule {
		t.Fatalf("trigger_type = %s, want schedule", run.TriggerType)
	}
	run, err = svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.TriggerType != scanworkflow.TriggerTypeManual {
		t.Fatalf("trigger_type = %s, want manual", run.TriggerType)
	}
}

// UpdateScan skipped the checks CreateScan runs: an unparseable cron or an
// unknown timezone was saved and then quietly honored as "every 24h" / UTC.
func TestScanService_UpdateScan_RefusesUnhonorableSchedule(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Bad schedule", scan.ScanTypeSingle)
	at := time.Date(0, 1, 1, 3, 0, 0, 0, time.UTC)
	cases := []scanservice.UpdateScanInput{
		{TenantID: tenantID.String(), ScanID: s.ID.String(), ScheduleType: "crontab", ScheduleCron: "61 * * * *"},
		{TenantID: tenantID.String(), ScanID: s.ID.String(), ScheduleType: "daily", ScheduleTime: &at, Timezone: "Mars/Olympus_Mons"},
	}
	for _, in := range cases {
		if _, err := svc.UpdateScan(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("UpdateScan(%s %q tz=%q): err = %v, want validation error", in.ScheduleType, in.ScheduleCron, in.Timezone, err)
		}
	}
}

// A workflow run started only steps with step_order == 1: independent steps
// numbered otherwise never started (the run hung until the run timeout), and
// a "never" condition on a first step was ignored.
func TestScanService_TriggerScan_Workflow_StartsByDependencyGraph(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "Graph start", scan.ScanTypeWorkflow)
	scanWorkflowID := *s.ScanWorkflowID
	deps.toolRepo.addTool("nuclei", true)
	deps.toolRepo.addTool("httpx", true)
	deps.stepRepo.steps[scanWorkflowID.String()] = []*scanworkflow.Step{
		{ID: shared.NewID(), ScanWorkflowID: scanWorkflowID, StepKey: "probe", StepOrder: 2, Tool: "httpx"},
		{ID: shared.NewID(), ScanWorkflowID: scanWorkflowID, StepKey: "vulns", StepOrder: 3, Tool: "nuclei"},
		{ID: shared.NewID(), ScanWorkflowID: scanWorkflowID, StepKey: "off", StepOrder: 4, Tool: "nuclei",
			Condition: scanworkflow.NeverCondition()},
		{ID: shared.NewID(), ScanWorkflowID: scanWorkflowID, StepKey: "after", StepOrder: 5, Tool: "nuclei",
			DependsOn: []string{"probe"}},
	}
	before := len(deps.commandRepo.commands)

	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(deps.commandRepo.commands) - before; got != 2 {
		t.Fatalf("queued %d step command(s), want 2 (the two independent steps; not the 'never' one, not the dependent)", got)
	}
}

// The list sort reaches the repository validated; an unknown field is a
// validation error (400), never silently dropped (RFC-048 §3.5).
func TestScanService_ListScans_Sort(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	_, err := svc.ListScans(context.Background(), scanservice.ListScansInput{
		TenantID: tenantID.String(), Sort: "-last_run_at", Page: 1, PerPage: 10,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	got := deps.scanRepo.lastListFilter
	if got.Sort.Field() != "last_run_at" || !got.Sort.Desc() {
		t.Fatalf("sort reached the repository as %s desc=%v", got.Sort.Field(), got.Sort.Desc())
	}
	if got.TenantID == nil || *got.TenantID != tenantID {
		t.Fatal("the list filter lost the caller's tenant")
	}

	deps.scanRepo.lastListFilter = scan.Filter{}
	_, err = svc.ListScans(context.Background(), scanservice.ListScansInput{
		TenantID: tenantID.String(), Sort: "tenant_id", Page: 1, PerPage: 10,
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown sort field: err = %v, want a validation error", err)
	}
	if deps.scanRepo.lastListFilter.TenantID != nil {
		t.Fatal("an invalid sort still queried the repository")
	}
}

type fakeOwnerActivity struct{ active bool }

func (f fakeOwnerActivity) IsActiveTenantMember(context.Context, shared.ID, shared.ID) (bool, error) {
	return f.active, nil
}

// A scheduled run acts as the scan's owner. With no owner it would act as the
// unrestricted system, so it is refused (research 21b H2/H3, RFC-050 SP-3).
// A manual trigger by a person is unaffected.
func TestScanService_TriggerScan_ScheduledRunWithoutOwnerRefused(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Ownerless", scan.ScanTypeSingle)

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	})
	if !errors.Is(err, scanservice.ErrScanHasNoOwner) {
		t.Fatalf("scheduled run of an ownerless scan: err = %v, want ErrScanHasNoOwner", err)
	}
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggeredBy: shared.NewID().String(),
	}); err != nil {
		t.Fatalf("a manual trigger by a person must still work: %v", err)
	}
}

// A scheduled run whose owner is disabled or left pauses the scan and is
// refused; it never runs on behalf of a person who no longer has access.
func TestScanService_TriggerScan_ScheduledRunWithInactiveOwnerPauses(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	s := createTestScanInRepo(deps, tenantID, "Leaver's scan", scan.ScanTypeSingle)
	s.SetCreatedBy(shared.NewID())
	svc.SetOwnerActivity(fakeOwnerActivity{active: false})

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	})
	if !errors.Is(err, scanservice.ErrScanOwnerInactive) {
		t.Fatalf("err = %v, want ErrScanOwnerInactive", err)
	}
	got, gerr := svc.GetScan(context.Background(), tenantID.String(), s.ID.String())
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got.Status != scan.StatusPaused {
		t.Errorf("scan status = %s, want paused", got.Status)
	}

	svc.SetOwnerActivity(fakeOwnerActivity{active: true})
	s2 := createTestScanInRepo(deps, tenantID, "Active owner", scan.ScanTypeSingle)
	s2.SetCreatedBy(shared.NewID())
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s2.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	}); err != nil {
		t.Fatalf("scheduled run with an active owner: %v", err)
	}
}

// =============================================================================
// Tests: refused triggers are blocked runs
// =============================================================================

// dispatchedRuns counts the runs that are not blocked (a refused trigger
// leaves only a blocked run behind).
func dispatchedRuns(deps *testScanServiceDeps) int {
	n := 0
	for _, r := range deps.runRepo.runs {
		if r.Status != scanrundom.RunStatusBlocked {
			n++
		}
	}
	return n
}

// blockedRuns returns the runs of scanID recorded as blocked.
func blockedRuns(deps *testScanServiceDeps, scanID shared.ID) []*scanrundom.Run {
	var out []*scanrundom.Run
	for _, r := range deps.runRepo.runs {
		if r.ScanID != nil && *r.ScanID == scanID && r.Status == scanrundom.RunStatusBlocked {
			out = append(out, r)
		}
	}
	return out
}

// A trigger refused before dispatch (here: no sensor online) is recorded as a
// blocked run with the refusal code, and the scan's summary is refreshed.
// Before, nothing was recorded for a manual trigger, and a scheduled one moved
// last_run_at with no run behind it.
func TestScanService_TriggerScan_RefusalRecordsBlockedRun(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	deps.sensorSelector.available = false
	s := createTestScanInRepo(deps, tenantID, "Refused", scan.ScanTypeSingle)
	userID := shared.NewID().String()

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), TriggeredBy: userID,
		Context: map[string]any{"caller": "supplied"},
	})
	if err == nil {
		t.Fatal("expected the trigger to be refused")
	}
	got := blockedRuns(deps, s.ID)
	if len(got) != 1 {
		t.Fatalf("blocked runs = %d, want 1", len(got))
	}
	b := got[0]
	if b.RefusalCode != "NO_SENSOR_AVAILABLE" || b.ErrorMessage == "" || b.TenantID != tenantID ||
		b.TriggeredBy != userID || b.TriggerType != scanworkflow.TriggerTypeManual || b.StartedAt != nil || b.CompletedAt == nil {
		t.Fatalf("blocked run = %+v", b)
	}
	if _, leaked := b.Context["caller"]; leaked {
		t.Error("the blocked run stored the caller's trigger context")
	}
	if len(deps.scanRepo.refreshes) != 1 || deps.scanRepo.refreshes[0] != s.ID {
		t.Errorf("RefreshRunSummary calls = %v, want [%s]", deps.scanRepo.refreshes, s.ID)
	}
}

// A scan of another tenant is not found for the caller's tenant: no run is
// written anywhere and no summary is touched.
func TestScanService_TriggerScan_OtherTenantRecordsNothing(t *testing.T) {
	svc, deps := newTestScanService()
	victim := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	deps.sensorSelector.available = false
	s := createTestScanInRepo(deps, victim, "Victim", scan.ScanTypeSingle)

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: shared.NewID().String(), ScanID: s.ID.String(),
	})
	if err == nil {
		t.Fatal("another tenant triggered the scan")
	}
	if n := len(deps.runRepo.runs); n != 0 {
		t.Fatalf("%d run(s) written for a scan the caller cannot see", n)
	}
	if len(deps.scanRepo.refreshes) != 0 {
		t.Fatal("summary refreshed for a scan the caller cannot see")
	}
}

// The overlap skip of a scheduled occurrence (D4) is recorded by the
// scheduler as a skip, not as a blocked run.
func TestScanService_TriggerScan_OverlapSkipIsNotBlocked(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	deps.runRepo.activeByScanCount = 1
	s := createTestScanInRepo(deps, tenantID, "Overlap", scan.ScanTypeSingle)
	s.CreatedBy = &tenantID // a scheduled run needs an owner

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
		TriggerType: scanworkflow.TriggerTypeSchedule, SkipIfRunning: true,
	})
	if !errors.Is(err, scanservice.ErrScanRunInProgress) {
		t.Fatalf("err = %v, want ErrScanRunInProgress", err)
	}
	if got := blockedRuns(deps, s.ID); len(got) != 0 {
		t.Fatalf("overlap skip recorded %d blocked run(s)", len(got))
	}
}

// noWebScope is a web scope builder with no path exclusions (RFC-056).
type noWebScope struct{}

func (noWebScope) BuildWebScope(context.Context, shared.ID, []string) (*scopeapp.WebScope, error) {
	return nil, nil
}
