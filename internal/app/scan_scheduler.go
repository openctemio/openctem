package app

// Compatibility shim — the concrete scan-orchestration services
// (scheduler, session, profile) moved into the existing
// internal/app/scan/ package.
//
// scanner_template_service stays in package app due to a pre-existing
// cycle: template/ imports scan/, and scanner_template_service needs
// to import template/ — so moving it into scan/ would create a cycle.
// Revisit when the template→scan adapter is refactored.

import "github.com/openctemio/api/internal/app/scan"

type (
	ScanScheduler            = scan.ScanScheduler
	ScanSchedulerConfig      = scan.ScanSchedulerConfig
	ScanSessionService       = scan.ScanSessionService
	ScanProfileService       = scan.ScanProfileService
	CloneScanProfileInput    = scan.CloneScanProfileInput
	CreateScanProfileInput   = scan.CreateScanProfileInput
	EvaluateQualityGateInput = scan.EvaluateQualityGateInput
	ListScanProfilesInput    = scan.ListScanProfilesInput
	ListScanSessionsInput    = scan.ListScanSessionsInput
	RegisterScanInput        = scan.RegisterScanInput
	RegisterScanOutput       = scan.RegisterScanOutput
	UpdateQualityGateInput   = scan.UpdateQualityGateInput
	UpdateScanProfileInput   = scan.UpdateScanProfileInput
	UpdateScanSessionInput   = scan.UpdateScanSessionInput
)

var (
	NewScanScheduler      = scan.NewScanScheduler
	NewScanSessionService = scan.NewScanSessionService
	NewScanProfileService = scan.NewScanProfileService
)
