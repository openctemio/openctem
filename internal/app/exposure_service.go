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
)

var (
	NewExposureService            = exposure.NewExposureService
	NewRemediationCampaignService = exposure.NewRemediationCampaignService
)
