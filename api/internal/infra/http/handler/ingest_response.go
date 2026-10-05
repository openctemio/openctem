package handler

import (
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
)

// IngestResponse is the outcome of a CTIS report upload (the CI run upload,
// RFC-051).
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	AssetsCreated   int      `json:"assets_created"`
	AssetsUpdated   int      `json:"assets_updated"`
	FindingsCreated int      `json:"findings_created"`
	FindingsUpdated int      `json:"findings_updated"`
	FindingsSkipped int      `json:"findings_skipped"`
	CVEsCreated     int      `json:"cves_created"`
	CVEsUpdated     int      `json:"cves_updated"`
	Errors          []string `json:"errors,omitempty"`
	// AssetsSkippedExcluded counts new assets not added because they match
	// an active scope exclusion; their findings are in findings_skipped.
	AssetsSkippedExcluded int `json:"assets_skipped_excluded,omitempty"`
	// Binding is "command" when the report is bound to a command,
	// "unsolicited" otherwise (RFC-040 §5.3).
	Binding string `json:"binding,omitempty"`
	// AssetsLimited counts existing assets the report matched but was not
	// allowed to change, because no command covering them stood behind it.
	AssetsLimited int `json:"assets_limited,omitempty"`
	// ReopensWithheld counts findings a person had resolved that the report
	// saw again but was not allowed to reopen.
	ReopensWithheld int `json:"reopens_withheld,omitempty"`
	// UnsolicitedWarned: the report was applied only because the tenant's
	// policy for results without a command is "warn".
	UnsolicitedWarned bool `json:"unsolicited_warned,omitempty"`
}

// newIngestResponse is the response for an ingest output.
func newIngestResponse(output *ingest.Output) IngestResponse {
	return IngestResponse{
		ScanID:                output.ReportID,
		AssetsCreated:         output.AssetsCreated,
		AssetsUpdated:         output.AssetsUpdated,
		FindingsCreated:       output.FindingsCreated,
		FindingsUpdated:       output.FindingsUpdated,
		FindingsSkipped:       output.FindingsSkipped,
		AssetsSkippedExcluded: output.AssetsSkippedExcluded,
		CVEsCreated:           output.CVEsCreated,
		CVEsUpdated:           output.CVEsUpdated,
		Errors:                output.Errors,
		Binding:               output.Binding,
		AssetsLimited:         output.AssetsLimited,
		ReopensWithheld:       output.ReopensWithheld,
		UnsolicitedWarned:     output.UnsolicitedWarned,
	}
}

// CTISIngestRequest is a CTIS report wrapped as {"report": {...}}.
type CTISIngestRequest struct {
	Report ctis.Report `json:"report"`
}
