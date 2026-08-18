package app

// Compatibility shim — real impl lives in internal/app/exposure/.

import "github.com/openctemio/api/internal/app/exposure"

type (
	ExposureService                = exposure.ExposureService
	RemediationCampaignService     = exposure.RemediationCampaignService
	ChangeStateInput               = exposure.ChangeStateInput
	CreateExposureInput            = exposure.CreateExposureInput
	CreateRemediationCampaignInput = exposure.CreateRemediationCampaignInput
	ListExposuresInput             = exposure.ListExposuresInput
	UpdateRemediationCampaignInput = exposure.UpdateRemediationCampaignInput
	CampaignTicketLink             = exposure.CampaignTicketLink
	CampaignResolveInput           = exposure.CampaignResolveInput
	BulkIngestResult               = exposure.BulkIngestResult
	IngestItemError                = exposure.IngestItemError
	ExposureEnricher               = exposure.ExposureEnricher
	ExposureEnrichment             = exposure.Enrichment
)

var (
	NewExposureEnricher = exposure.NewExposureEnricher
)

var (
	NewExposureService            = exposure.NewExposureService
	NewRemediationCampaignService = exposure.NewRemediationCampaignService
)
