package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/compliance"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TestDynamicWhere_AllFiltersExecute runs every dynamic WHERE builder that
// numbers its placeholders from len(args) with ALL of its filters set, so
// every placeholder is emitted at once. Postgres rejects a statement whose
// $N placeholders do not line up with the bound arguments (count or type),
// so a numbering mistake in any builder fails here. Requires DATABASE_URL
// (CI applies every migration first).
func TestDynamicWhere_AllFiltersExecute(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	ctx := context.Background()
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	db := &DB{DB: sqlDB}

	tenantID := seedTestTenant(ctx, t, sqlDB)
	tenant := tenantID.String()
	id := shared.NewID()
	since := time.Now().Add(-24 * time.Hour)
	until := time.Now()
	yes := true
	search := "x"
	page := pagination.New(1, 10)

	check := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	{
		_, err := NewAssetGroupRepository(db).Count(ctx, assetgroup.Filter{TenantID: &tenant})
		check("AssetGroupRepository.Count", err)
	}
	{
		scanStatus := branch.ScanStatusPassed
		f := branch.Filter{
			RepositoryID: &id, Name: "main", Types: []branch.Type{branch.TypeMain, branch.TypeMain},
			IsDefault: &yes, ScanStatus: &scanStatus,
		}
		repo := NewBranchRepository(db)
		_, err := repo.List(ctx, f, branch.ListOptions{}, page)
		check("BranchRepository.List", err)
		_, err = repo.Count(ctx, f)
		check("BranchRepository.Count", err)
	}
	{
		cType, cStatus, cPrio := command.CommandTypeScan, command.CommandStatusPending, command.CommandPriorityLow
		repo := NewCommandRepository(db)
		_, err := repo.List(ctx, command.Filter{
			TenantID: &tenantID, SensorID: &id, Type: &cType, Status: &cStatus, Priority: &cPrio, IsPlatformJob: &yes,
		}, page)
		check("CommandRepository.List", err)
		_, err = repo.ListPlatformJobsAdmin(ctx, &id, &tenantID, &cStatus, page)
		check("CommandRepository.ListPlatformJobsAdmin", err)
	}
	{
		cat := compliance.FrameworkCategoryRegulatory
		_, err := NewComplianceFrameworkRepository(db).List(ctx, compliance.FrameworkFilter{
			TenantID: &tenantID, Category: &cat, IsSystem: &yes, IsActive: &yes, Search: &search,
		}, page)
		check("ComplianceFrameworkRepository.List", err)
	}
	{
		f := vulnerability.FindingActivityFilter{
			ActivityTypes: []vulnerability.ActivityType{vulnerability.ActivityCreated, vulnerability.ActivityCreated},
			ActorTypes:    []vulnerability.ActorType{vulnerability.ActorTypeUser, vulnerability.ActorTypeUser},
			ActorIDs:      []shared.ID{id, shared.NewID()},
			Sources:       []vulnerability.ActivitySource{vulnerability.SourceAPI, vulnerability.SourceAPI},
			Since:         &since,
			Until:         &until,
		}
		repo := NewFindingActivityRepository(db)
		_, err := repo.ListByFinding(ctx, id, tenantID, f, page)
		check("FindingActivityRepository.ListByFinding", err)
		_, err = repo.CountByFinding(ctx, id, tenantID, f)
		check("FindingActivityRepository.CountByFinding", err)
		_, err = repo.ListByTenant(ctx, tenantID, f, page)
		check("FindingActivityRepository.ListByTenant", err)
	}
	{
		st, ty, pr := pentest.CampaignStatusPlanning, pentest.CampaignTypeExternal, pentest.CampaignPriorityCritical
		user := id.String()
		_, err := NewPentestCampaignRepository(db).List(ctx, pentest.CampaignFilter{
			TenantID: &tenantID, Status: &st, Type: &ty, Priority: &pr, Search: &search, UserID: &user,
		}, page)
		check("PentestCampaignRepository.List", err)
	}
	{
		ty, fm, st := pentest.ReportTypeExecutiveSummary, pentest.ReportFormatPDF, pentest.ReportStatusDraft
		_, err := NewPentestReportRepository(db).List(ctx, pentest.ReportFilter{
			TenantID: &tenantID, CampaignID: &id, Type: &ty, Format: &fm, Status: &st,
		}, page)
		check("PentestReportRepository.List", err)
	}
	{
		cat, sev := pentest.TemplateCategoryInjection, pentest.FindingSeverityCritical
		_, err := NewPentestTemplateRepository(db).List(ctx, pentest.TemplateFilter{
			TenantID: &tenantID, Category: &cat, Severity: &sev, IsSystem: &yes, Search: &search,
		}, page)
		check("PentestTemplateRepository.List", err)
	}
	{
		repo := NewScanWorkflowRepository(db)
		_, err := repo.List(ctx, scanworkflow.Filter{
			TenantID: &tenantID, IsActive: &yes, IsSystemTemplate: &yes, Search: search,
		}, page)
		check("ScanWorkflowRepository.List", err)
		_, err = repo.ListWithSystemTemplates(ctx, tenantID, scanworkflow.Filter{IsActive: &yes, Search: search}, page)
		check("ScanWorkflowRepository.ListWithSystemTemplates", err)
	}
	{
		st, tt := scanrun.RunStatusPending, scanworkflow.TriggerTypeManual
		_, err := NewScanRunRepository(db).List(ctx, scanrun.RunFilter{
			TenantID: &tenantID, ScanWorkflowID: &id, AssetID: &id, Status: &st, TriggerType: &tt,
		}, page)
		check("ScanRunRepository.List", err)

		srs := scanrun.StepRunStatusPending
		_, err = NewStepRunRepository(db).List(ctx, scanrun.StepRunFilter{ScanRunID: &id, Status: &srs})
		check("StepRunRepository.List", err)
	}
	{
		statuses := []scope.Status{scope.StatusActive}
		_, err := NewScopeExclusionRepository(db).Count(ctx, scope.ExclusionFilter{TenantID: &tenant, Statuses: statuses})
		check("ScopeExclusionRepository.Count", err)
		_, err = NewScopeTargetRepository(db).Count(ctx, scope.TargetFilter{TenantID: &tenant, Statuses: statuses})
		check("ScopeTargetRepository.Count", err)
	}
	{
		catName := "recon"
		_, err := NewTenantToolConfigRepository(db).ListToolsWithConfig(ctx, tenantID, tool.ToolFilter{
			CategoryID: &id, CategoryName: &catName, IsActive: &yes, IsBuiltin: &yes, Search: search,
		}, page)
		check("TenantToolConfigRepository.ListToolsWithConfig", err)
	}
	{
		st := automation.NodeRunStatusPending
		_, err := NewAutomationRunStepRepository(db).List(ctx, automation.NodeRunFilter{
			WorkflowRunID: &id, NodeID: &id, Status: &st,
		})
		check("AutomationRunStepRepository.List", err)
	}
	{
		_, err := NewAutomationRepository(db).List(ctx, automation.WorkflowFilter{
			TenantID: &tenantID, IsActive: &yes, Search: search,
		}, page)
		check("AutomationRepository.List", err)
	}
	{
		st, tt := automation.RunStatusPending, automation.TriggerTypeManual
		_, err := NewAutomationRunRepository(db).List(ctx, automation.RunFilter{
			TenantID: &tenantID, WorkflowID: &id, Status: &st, TriggerType: &tt, TriggeredBy: &id,
			StartedFrom: &since, StartedTo: &until,
		}, page)
		check("AutomationRunRepository.List", err)
	}
}
