package app

// Compatibility shim — real impl lives in internal/app/module/.

import "github.com/openctemio/api/internal/app/module"

type (
	ModuleService                = module.ModuleService
	DashboardService             = module.DashboardService
	ReportScheduleService        = module.ReportScheduleService
	ActivityItem                 = module.ActivityItem
	AssetStatsData               = module.AssetStatsData
	CreateReportScheduleInput    = module.CreateReportScheduleInput
	DashboardAllStats            = module.DashboardAllStats
	DashboardStats               = module.DashboardStats
	DashboardStatsRepository     = module.DashboardStatsRepository
	DataQualityScorecard         = module.DataQualityScorecard
	ExecutiveSummary             = module.ExecutiveSummary
	FindingStatsData             = module.FindingStatsData
	FindingTrendPoint            = module.FindingTrendPoint
	GetTenantEnabledModulesOutput = module.GetTenantEnabledModulesOutput
	ModuleRepository             = module.ModuleRepository
	MTTRAnalytics                = module.MTTRAnalytics
	ProcessMetrics               = module.ProcessMetrics
	RepositoryStatsData          = module.RepositoryStatsData
	RiskTrendPoint               = module.RiskTrendPoint
	RiskVelocityPoint            = module.RiskVelocityPoint
	SubModuleInfo                = module.SubModuleInfo
	TenantModuleConfigOutput     = module.TenantModuleConfigOutput
	TenantModuleInfo             = module.TenantModuleInfo
	TenantModuleRepository       = module.TenantModuleRepository
	TenantModuleSummary          = module.TenantModuleSummary
	TopRisk                      = module.TopRisk
	DependencyEdgeOutput         = module.DependencyEdgeOutput
	DependencyGraphOutput        = module.DependencyGraphOutput
)

var (
	NewDashboardService      = module.NewDashboardService
	NewModuleService         = module.NewModuleService
	NewReportScheduleService = module.NewReportScheduleService
)
