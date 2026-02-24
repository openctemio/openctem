package ingest

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Input.GetBranchInfo tests
// =============================================================================

func TestInput_GetBranchInfo_FromInput(t *testing.T) {
	branch := &ctis.BranchInfo{Name: "main"}
	input := Input{
		BranchInfo: branch,
		Report: &ctis.Report{
			Metadata: ctis.ReportMetadata{
				Branch: &ctis.BranchInfo{Name: "from-report"},
			},
		},
	}
	// Input.BranchInfo takes precedence
	assert.Equal(t, "main", input.GetBranchInfo().Name)
}

func TestInput_GetBranchInfo_FromReport(t *testing.T) {
	input := Input{
		Report: &ctis.Report{
			Metadata: ctis.ReportMetadata{
				Branch: &ctis.BranchInfo{Name: "from-report"},
			},
		},
	}
	assert.Equal(t, "from-report", input.GetBranchInfo().Name)
}

func TestInput_GetBranchInfo_NilWhenNoBranchInfo(t *testing.T) {
	input := Input{Report: &ctis.Report{}}
	assert.Nil(t, input.GetBranchInfo())
}

func TestInput_GetBranchInfo_NilReport(t *testing.T) {
	input := Input{}
	assert.Nil(t, input.GetBranchInfo())
}

// =============================================================================
// Input.IsDefaultBranchScan tests
// =============================================================================

func TestInput_IsDefaultBranchScan_True(t *testing.T) {
	input := Input{
		BranchInfo: &ctis.BranchInfo{
			Name:            "main",
			IsDefaultBranch: true,
		},
	}
	assert.True(t, input.IsDefaultBranchScan())
}

func TestInput_IsDefaultBranchScan_False(t *testing.T) {
	input := Input{
		BranchInfo: &ctis.BranchInfo{
			Name:            "feature/new-thing",
			IsDefaultBranch: false,
		},
	}
	assert.False(t, input.IsDefaultBranchScan())
}

func TestInput_IsDefaultBranchScan_NoBranch(t *testing.T) {
	input := Input{Report: &ctis.Report{}}
	assert.False(t, input.IsDefaultBranchScan())
}

// =============================================================================
// Input.ShouldAutoResolve tests
// =============================================================================

func TestInput_ShouldAutoResolve_FullScanDefaultBranch(t *testing.T) {
	input := Input{
		CoverageType: CoverageTypeFull,
		BranchInfo: &ctis.BranchInfo{
			Name:            "main",
			IsDefaultBranch: true,
		},
	}
	assert.True(t, input.ShouldAutoResolve())
}

func TestInput_ShouldAutoResolve_IncrementalScan(t *testing.T) {
	input := Input{
		CoverageType: CoverageTypeIncremental,
		BranchInfo: &ctis.BranchInfo{
			Name:            "main",
			IsDefaultBranch: true,
		},
	}
	assert.False(t, input.ShouldAutoResolve())
}

func TestInput_ShouldAutoResolve_FeatureBranch(t *testing.T) {
	input := Input{
		CoverageType: CoverageTypeFull,
		BranchInfo: &ctis.BranchInfo{
			Name:            "feature/new-thing",
			IsDefaultBranch: false,
		},
	}
	assert.False(t, input.ShouldAutoResolve())
}

func TestInput_ShouldAutoResolve_NoBranch(t *testing.T) {
	input := Input{
		CoverageType: CoverageTypeFull,
	}
	assert.False(t, input.ShouldAutoResolve())
}

func TestInput_ShouldAutoResolve_NoCoverageType(t *testing.T) {
	input := Input{
		BranchInfo: &ctis.BranchInfo{
			Name:            "main",
			IsDefaultBranch: true,
		},
	}
	assert.False(t, input.ShouldAutoResolve())
}

func TestInput_ShouldAutoResolve_CoverageTypeFromReport(t *testing.T) {
	input := Input{
		Report: &ctis.Report{
			Metadata: ctis.ReportMetadata{
				CoverageType: "full",
				Branch: &ctis.BranchInfo{
					Name:            "main",
					IsDefaultBranch: true,
				},
			},
		},
	}
	assert.True(t, input.ShouldAutoResolve())
}

func TestInput_ShouldAutoResolve_PartialScan(t *testing.T) {
	input := Input{
		CoverageType: CoverageTypePartial,
		BranchInfo: &ctis.BranchInfo{
			Name:            "main",
			IsDefaultBranch: true,
		},
	}
	assert.False(t, input.ShouldAutoResolve())
}
