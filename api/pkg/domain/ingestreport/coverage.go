package ingestreport

import (
	"encoding/json"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CommandCoverage is what is known about one scan command's run, for
// coverage-scoped auto-resolve: the command's own state and every v2 report
// the sensor filed under it.
type CommandCoverage struct {
	CommandType   string
	CommandStatus string
	// Result is the command's completion result as the sensor sent it (may
	// carry exit_code).
	Result json.RawMessage
	// ProfileID is the scan profile of the scan configuration that queued the
	// command, "" when there is none (ad-hoc and workflow-step commands).
	ProfileID string
	Reports   []CoverageReport
}

// CoverageReport is one v2 report filed under a command.
type CoverageReport struct {
	ReportID        string
	SensorID        shared.ID
	State           State
	ToolName        string
	Header          json.RawMessage
	SegmentOutcomes map[string]SegmentOutcome
	TouchedAssetIDs []shared.ID
}

// CoverageQuery selects the open, non-repository findings that a covered run
// could close: the tool's findings on the assets the run covered, last seen by
// a run of the same scan profile, and not seen by this run.
type CoverageQuery struct {
	AssetIDs  []shared.ID
	ToolName  string
	ProfileID string
	// SeenScanIDs are this run's report ids: a finding whose scan_id is one of
	// them was reported by this run and stays open.
	SeenScanIDs []string
	// TemplatesDigest is the template release digest every report of the
	// run scanned with (tool.properties.content, nuclei-templates); "" when
	// none was reported or the reports disagree. A candidate whose last
	// sighting recorded another release is not proven fixed (research/18
	// O6): it becomes not_observed instead.
	TemplatesDigest string
}
