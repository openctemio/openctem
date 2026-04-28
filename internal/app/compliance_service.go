package app

// Compatibility shim — real impl lives in internal/app/compliance/.
// NOTE: pentest_service.go intentionally stays in package app because
// it depends on NotificationService + FindingActivityService that have
// not been extracted yet. Once those move, pentest can rejoin compliance/.

import "github.com/openctemio/api/internal/app/compliance"

type (
	ComplianceService             = compliance.ComplianceService
	SimulationService             = compliance.SimulationService
	PentestService                = compliance.PentestService
	ComplianceStatsResponse       = compliance.ComplianceStatsResponse
	CreateControlTestInput        = compliance.CreateControlTestInput
	CreateSimulationInput         = compliance.CreateSimulationInput
	RecordControlTestResultInput  = compliance.RecordControlTestResultInput
	UpdateAssessmentInput         = compliance.UpdateAssessmentInput
	UpdateSimulationInput         = compliance.UpdateSimulationInput
	CampaignAddMemberInput        = compliance.CampaignAddMemberInput
	CampaignRemoveMemberInput     = compliance.CampaignRemoveMemberInput
	CampaignTeamChangeResult      = compliance.CampaignTeamChangeResult
	CampaignUpdateMemberRoleInput = compliance.CampaignUpdateMemberRoleInput
	CreateCampaignInput           = compliance.CreateCampaignInput
	CreateReportInput             = compliance.CreateReportInput
	CreateRetestInput             = compliance.CreateRetestInput
	CreateTemplateInput           = compliance.CreateTemplateInput
	PentestFindingInput           = compliance.PentestFindingInput
	PentestSourceMetadata         = compliance.PentestSourceMetadata
	StatusChangeResult            = compliance.StatusChangeResult
	TenantMemberChecker           = compliance.TenantMemberChecker
	UpdateCampaignInput           = compliance.UpdateCampaignInput
)

var (
	NewComplianceService   = compliance.NewComplianceService
	NewSimulationService   = compliance.NewSimulationService
	NewPentestService      = compliance.NewPentestService
	WithCachedCampaignRole = compliance.WithCachedCampaignRole
)
