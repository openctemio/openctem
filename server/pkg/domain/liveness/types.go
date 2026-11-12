package liveness

import (
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// AssetObservation is one observation of one asset.
type AssetObservation struct {
	AssetID shared.ID
	Observation
}

// Row is one asset's stored liveness with the guard facts a pass reads
// beside it.
type Row struct {
	AssetID   shared.ID
	AssetType string
	// HostID is a service's host name asset (zero when none or not a
	// service).
	HostID   shared.ID
	Evidence Evidence
	Guards   Guards
	// OpenFindings counts the asset's open findings: only an asset with
	// some counts against the daily gone bound.
	OpenFindings int
}

// CloseResult is what a close pass did.
type CloseResult struct {
	IDs []shared.ID
	// Critical counts the closed findings of the critical tier (critical
	// severity, P0 or KEV).
	Critical int
}

// Preview is what a pass would change, counted without writing.
type Preview struct {
	// States counts the organization's assets per stored state.
	States map[string]int `json:"states"`
	// WouldCloseFindings counts open findings on gone assets (closed when
	// closing is on); WouldCloseCritical the critical-tier ones.
	WouldCloseFindings int `json:"would_close_findings"`
	WouldCloseCritical int `json:"would_close_critical"`
	// WouldReopenFindings counts findings the pass closed whose asset is no
	// longer gone.
	WouldReopenFindings int `json:"would_reopen_findings"`
	// OpenOnUnreachable and OpenOnUnresolvable count open findings that
	// stay open with the "cannot verify" label.
	OpenOnUnreachable  int `json:"open_on_unreachable"`
	OpenOnUnresolvable int `json:"open_on_unresolvable"`
	// CloseFindingsWhenGone is the organization's setting: false means the
	// would-close findings stay open (gone is a label only).
	CloseFindingsWhenGone bool `json:"close_findings_when_gone"`
}

// View is one asset's liveness as the API shows it.
type View struct {
	State         string     `json:"state"`
	Reason        string     `json:"reason,omitempty"`
	Since         *time.Time `json:"since,omitempty"`
	LastCheckedAt *time.Time `json:"last_checked_at,omitempty"`
	// LastCheckedBy is the name of the scan zone or sensor of the last
	// check ("" when unknown or no longer there).
	LastCheckedBy  string     `json:"last_checked_by,omitempty"`
	LastCapability string     `json:"last_capability,omitempty"`
	LastOutcome    string     `json:"last_outcome,omitempty"`
	LastAliveAt    *time.Time `json:"last_alive_at,omitempty"`
}
