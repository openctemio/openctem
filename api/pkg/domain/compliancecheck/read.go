package compliancecheck

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Counts are the controls per result (Excepted is a part of Fail: failures
// whose finding is accepted or a false positive).
type Counts struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Manual        int `json:"manual"`
	NotApplicable int `json:"not_applicable"`
	Error         int `json:"error"`
	Excepted      int `json:"excepted"`
}

// Applicable is passed + failed: the denominator of the pass rate.
func (c Counts) Applicable() int { return c.Pass + c.Fail }

// PassRate is passed / applicable in [0, 1], or nil when nothing applies.
func (c Counts) PassRate() *float64 {
	if c.Applicable() == 0 {
		return nil
	}
	r := float64(c.Pass) / float64(c.Applicable())
	return &r
}

// BenchmarkPosture is one benchmark across the assets a viewer may see.
type BenchmarkPosture struct {
	Key           string
	Name          string
	Version       string
	Framework     string
	Assets        int
	FailingAssets int
	Counts        Counts
	LastCheckedAt time.Time
}

// ControlSummary is one control of a benchmark across the viewer's assets.
type ControlSummary struct {
	ControlID     string
	ControlName   string
	Level         int16
	Counts        Counts
	LastCheckedAt time.Time
}

// ControlAsset is the state of one control on one asset.
type ControlAsset struct {
	AssetID          shared.ID
	AssetName        string
	AssetType        string
	Result           Result
	BenchmarkVersion string
	Evidence         Evidence
	ScannerSeverity  string
	FindingID        *shared.ID
	FindingStatus    string
	LastCheckedAt    time.Time
	LastChangedAt    time.Time
}

// HistoryEntry is one row of a control's history.
type HistoryEntry struct {
	Result           Result
	PreviousResult   Result
	Evidence         Evidence
	BenchmarkVersion string
	ToolName         string
	Source           string
	ObservedAt       time.Time
	RecordedAt       time.Time
}

// ControlHistory is the state and history of the control a finding fails.
type ControlHistory struct {
	BenchmarkKey  string
	BenchmarkName string
	ControlID     string
	ControlName   string
	Level         int16
	Result        Result
	LastCheckedAt time.Time
	Entries       []HistoryEntry
}

// ControlFilter narrows a benchmark's controls.
type ControlFilter struct {
	// Results keeps controls that have at least one asset in one of them.
	Results []Result
	// Search matches the control id or name (case-insensitive, literal).
	Search string
}

// MaxHistory bounds the history entries one read returns.
const MaxHistory = 200

// Reader reads check states. Every method is pinned to the tenant and, with
// a non-nil scope, to the assets of the scope (shared.DataScope).
type Reader interface {
	ListBenchmarks(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, assetID *shared.ID) ([]BenchmarkPosture, error)
	ListControls(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, benchmarkKey string, f ControlFilter,
		page pagination.Pagination) (pagination.Result[ControlSummary], error)
	ListControlAssets(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, benchmarkKey, controlID string,
		results []Result, page pagination.Pagination) (pagination.Result[ControlAsset], error)
	// FindingControlHistory is the history of the control whose state links
	// the finding (nil when none). The caller has checked the finding is in
	// the viewer's scope.
	FindingControlHistory(ctx context.Context, tenantID, findingID shared.ID, limit int) (*ControlHistory, error)
}
