package app

// Compatibility shim — real impl lives in internal/app/capability/.

import "github.com/openctemio/api/internal/app/capability"

type (
	CapabilityService          = capability.CapabilityService
	CapabilityUsageStatsOutput = capability.CapabilityUsageStatsOutput
	CreateCapabilityInput      = capability.CreateCapabilityInput
	DeleteCapabilityInput      = capability.DeleteCapabilityInput
	ListCapabilitiesInput      = capability.ListCapabilitiesInput
	UpdateCapabilityInput      = capability.UpdateCapabilityInput
)

var (
	NewCapabilityService = capability.NewCapabilityService
)
