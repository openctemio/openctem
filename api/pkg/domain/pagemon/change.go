package pagemon

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Change is one detected change of a watched URL.
type Change struct {
	ID         shared.ID  `json:"id"`
	WatchID    shared.ID  `json:"watch_id"`
	AssetID    shared.ID  `json:"asset_id"`
	URL        string     `json:"url"`
	ParentID   *shared.ID `json:"parent_id,omitempty"`
	ParentURL  string     `json:"parent_url,omitempty"`
	DetectedAt time.Time  `json:"detected_at"`
	Severity   Severity   `json:"severity"`
	Muted      bool       `json:"muted"`
	Summary    Summary    `json:"summary"`
	// Diff is set on the detail read only.
	Diff *Diff `json:"diff,omitempty"`
}

// ChangeFilter narrows the change list.
type ChangeFilter struct {
	WatchID     *shared.ID
	MinSeverity Severity
	IncludeMute bool
	Since       *time.Time
	Limit       int
	Offset      int
}

// Suggestion is a URL worth watching that is not watched yet.
type Suggestion struct {
	URL       string    `json:"url"`
	AssetID   shared.ID `json:"asset_id"`
	AssetName string    `json:"asset_name"`
	// Reason: root, login, admin or script.
	Reason string `json:"reason"`
	Mode   Mode   `json:"mode"`
}

// Suggestion reasons.
const (
	ReasonRoot   = "root"
	ReasonLogin  = "login"
	ReasonAdmin  = "admin"
	ReasonScript = "script"
)

// FetchOutcome is what one capture does to its watch, written in one
// transaction by the store.
type FetchOutcome struct {
	WatchID   shared.ID
	FetchedAt time.Time
	Status    int
	// Failed: the fetch answered with an error status; no snapshot.
	Failed bool
	// Snapshot is set when the content hash changed (or on the baseline).
	Snapshot *Snapshot
	// Change is set when a previous snapshot existed and the hash changed.
	Change *Change
	Diff   *Diff
	// ChangeStreak and Dynamic are the watch's new values.
	ChangeStreak int
	Dynamic      bool
}
