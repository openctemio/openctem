package app

// Compatibility shim — real impl lives in internal/app/validation/.

import "github.com/openctemio/api/internal/app/validation"

type (
	ValidationCoverage = validation.ValidationCoverage
	CoverageThresholds = validation.CoverageThresholds
)

var (
	Enforce             = validation.Enforce
	DefaultThresholds   = validation.DefaultThresholds
	ErrCoverageBelowSLO = validation.ErrCoverageBelowSLO
)
