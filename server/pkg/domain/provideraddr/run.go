package provideraddr

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Run states.
const (
	StateRunning    = "running"
	StateDone       = "done"
	StateFailed     = "failed"
	StateSuperseded = "superseded"
)

// ErrBusy is returned when another runner holds the organization's batch
// lock (two replicas never run the same organization at once).
var ErrBusy = errors.New("provider addresses: another run holds this organization; retry later")

// ErrNotRunning is returned for a batch of a run that is no longer running.
var ErrNotRunning = errors.New("provider addresses: the run is not running")

// ErrFindingStatusChanged aborts a batch whose writes changed the status of
// a finding: the move never changes a finding.
var ErrFindingStatusChanged = errors.New("provider addresses: a finding status changed inside the batch; batch rolled back")

// ErrTransient marks a batch that failed on a lock wait, a statement time
// limit or a serialization conflict: nothing was written and the batch may
// be retried.
var ErrTransient = errors.New("provider addresses: transient database conflict")

// Run is one run of the move for one organization.
type Run struct {
	ID             string
	TenantID       shared.ID
	Mode           Mode
	JobVersion     int
	DatasetVersion string
	Counts         Counts
	Cursor         string
	Resumed        bool
	StartedAt      time.Time
}

// BatchRequest asks for one batch of address assets after a cursor.
type BatchRequest struct {
	TenantID   shared.ID
	RunID      string // apply: the run whose cursor and counts the batch moves
	Apply      bool
	After      string // dry run: the cursor (an apply reads the run's)
	Limit      int    // address assets read per batch
	MaxShared  int    // end the batch once it holds this many shared addresses (0 = no cap): their writes set its time
	Classifier *edgeaddr.Classifier
	Entries    *Entries
	Sim        *Simulation
	Now        time.Time
}

// BatchResult is what one batch did (or would do).
type BatchResult struct {
	Counts  Counts
	Cursor  string
	Scanned int
	Done    bool
}

// AppliedItem is a journal item whose changes are in place.
type AppliedItem struct {
	ID      string
	AssetID string
	Address string
}

// RestoreRequest asks to restore journal items of an organization: every
// applied item after the run's cursor, or only ItemIDs when set.
type RestoreRequest struct {
	TenantID shared.ID
	RunID    string
	ItemIDs  []string
	Limit    int
	// Outcome is restored (a person's restore) or reclassified (the
	// address's range was withdrawn from the dataset).
	Outcome string
}

// RestoreResult counts one restore batch.
type RestoreResult struct {
	Restored int
	Changed  int
	Cursor   string
	Done     bool
}

// Notice is the one-time organization notice of the move.
type Notice struct {
	Addresses int    `json:"addresses"`
	Names     int    `json:"names"`
	Entries   int    `json:"entries"`
	TitleEn   string `json:"title_en"`
	En        string `json:"en"`
	TitleVi   string `json:"title_vi"`
	Vi        string `json:"vi"`
}

// NewNotice builds the notice text in English and Vietnamese. The
// notification feed stores the English text; both are kept on the run row
// for the console.
func NewNotice(addresses, names, entries int, providers []string) Notice {
	n := Notice{Addresses: addresses, Names: names, Entries: entries,
		TitleEn: "Shared provider addresses moved to your names",
		TitleVi: "Địa chỉ dùng chung của nhà cung cấp đã được chuyển vào tên miền của bạn"}
	list := ""
	if len(providers) > 0 {
		list = " (" + strings.Join(providers, ", ") + ")"
	}
	n.En = fmt.Sprintf("We moved %d shared provider addresses%s into the address history of %d of your names. "+
		"They were never yours to scan; the names stay monitored. Nothing was deleted: open a name and choose Addresses to see them.", addresses, list, names)
	n.Vi = fmt.Sprintf("Chúng tôi đã chuyển %d địa chỉ dùng chung của nhà cung cấp%s vào lịch sử địa chỉ của %d tên miền của bạn. "+
		"Đó không phải địa chỉ của bạn để quét; các tên miền vẫn được theo dõi. Không có gì bị xoá: mở một tên miền và chọn Địa chỉ để xem.", addresses, list, names)
	if entries > 0 {
		n.En += fmt.Sprintf(" %d scope entries need your decision.", entries)
		n.Vi += fmt.Sprintf(" %d mục phạm vi cần bạn quyết định.", entries)
	}
	return n
}
