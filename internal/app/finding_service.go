package app

// Compatibility shim — real impl lives in internal/app/finding/.
// Covers vulnerability + finding + priority + bulk-guard bounded
// context (11 files, biggest cluster).

import "github.com/openctemio/api/internal/app/finding"

type (
	VulnerabilityService            = finding.VulnerabilityService
	FindingActionsService           = finding.FindingActionsService
	FindingCommentService           = finding.FindingCommentService
	FindingImportService            = finding.FindingImportService
	FindingLifecycleScheduler       = finding.FindingLifecycleScheduler
	FindingLifecycleSchedulerConfig = finding.FindingLifecycleSchedulerConfig
	FindingSourceService            = finding.FindingSourceService
	FindingSourceCacheService       = finding.FindingSourceCacheService
	PriorityClassificationService   = finding.PriorityClassificationService
	PriorityFloodGuard              = finding.PriorityFloodGuard
	PriorityFloodConfig             = finding.PriorityFloodConfig
	BulkGuard                       = finding.BulkGuard
	BulkGuardConfig                 = finding.BulkGuardConfig

	AddCommentInput               = finding.AddCommentInput
	AddStatusChangeCommentInput   = finding.AddStatusChangeCommentInput
	ApproveStatusInput            = finding.ApproveStatusInput
	AutoAssignToOwnersResult      = finding.AutoAssignToOwnersResult
	BulkAssignInput               = finding.BulkAssignInput
	BulkFixAppliedInput           = finding.BulkFixAppliedInput
	BulkFixAppliedResult          = finding.BulkFixAppliedResult
	BulkUpdateResult              = finding.BulkUpdateResult
	BulkUpdateStatusInput         = finding.BulkUpdateStatusInput
	BurpIssue                     = finding.BurpIssue
	BurpIssues                    = finding.BurpIssues
	CachedCategory                = finding.CachedCategory
	CachedFindingSource           = finding.CachedFindingSource
	CachedFindingSources          = finding.CachedFindingSources
	CancelApprovalInput           = finding.CancelApprovalInput
	ClassifyFindingInput          = finding.ClassifyFindingInput
	CompensatingControlLookup     = finding.CompensatingControlLookup
	CreateFindingInput            = finding.CreateFindingInput
	CreateVulnerabilityInput      = finding.CreateVulnerabilityInput
	EPSSData                      = finding.EPSSData
	EPSSRepository                = finding.EPSSRepository
	FindingNotifier               = finding.FindingNotifier
	GetFindingStatsInput          = finding.GetFindingStatsInput
	ImportResult                  = finding.ImportResult
	KEVData                       = finding.KEVData
	KEVRepository                 = finding.KEVRepository
	ListFindingsInput             = finding.ListFindingsInput
	ListVulnerabilitiesInput      = finding.ListVulnerabilitiesInput
	PriorityAuditEntry            = finding.PriorityAuditEntry
	PriorityAuditRepository       = finding.PriorityAuditRepository
	PriorityChangeEvent           = finding.PriorityChangeEvent
	PriorityChangePublisher       = finding.PriorityChangePublisher
	PriorityRuleRepository        = finding.PriorityRuleRepository
	RejectApprovalInput           = finding.RejectApprovalInput
	RejectByFilterInput           = finding.RejectByFilterInput
	RequestApprovalInput          = finding.RequestApprovalInput
	RequestVerificationScanInput  = finding.RequestVerificationScanInput
	RequestVerificationScanResult = finding.RequestVerificationScanResult
	TenantLister                  = finding.TenantLister
	UpdateCommentInput            = finding.UpdateCommentInput
	UpdateFindingStatusInput      = finding.UpdateFindingStatusInput
	UpdateVulnerabilityInput      = finding.UpdateVulnerabilityInput
	VerificationScanTrigger       = finding.VerificationScanTrigger
	VerifyByFilterInput           = finding.VerifyByFilterInput
)

var (
	NewVulnerabilityService                = finding.NewVulnerabilityService
	NewFindingActionsService               = finding.NewFindingActionsService
	NewFindingCommentService               = finding.NewFindingCommentService
	NewFindingImportService                = finding.NewFindingImportService
	NewFindingLifecycleScheduler           = finding.NewFindingLifecycleScheduler
	NewFindingSourceCacheService           = finding.NewFindingSourceCacheService
	NewFindingSourceService                = finding.NewFindingSourceService
	NewPriorityClassificationService       = finding.NewPriorityClassificationService
	NewPriorityFloodGuard                  = finding.NewPriorityFloodGuard
	NewBulkGuard                           = finding.NewBulkGuard
	DefaultFindingLifecycleSchedulerConfig = finding.DefaultFindingLifecycleSchedulerConfig

	ErrBulkBudgetExceeded      = finding.ErrBulkBudgetExceeded
	ErrBulkNegativeSize        = finding.ErrBulkNegativeSize
	ErrBulkTooLarge            = finding.ErrBulkTooLarge
	ErrPriorityFloodSuppressed = finding.ErrPriorityFloodSuppressed
)
