// Package ingestreceipt holds the receipts of uploads and sensor runs: what
// each one did to the tenant's findings, and the per-finding action log
// (docs/rfcs/RFC-122-ingest-receipts.md).
package ingestreceipt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SourceKind is what a receipt counts.
type SourceKind string

const (
	// SourceUpload is one POST /findings/imports request (all its files).
	SourceUpload SourceKind = "upload"
	// SourceScanRun is a scan run: every command of its steps.
	SourceScanRun SourceKind = "scan_run"
	// SourceCommand is a command outside a scan run.
	SourceCommand SourceKind = "command"
	// SourceCIRun is a CI run (RFC-051).
	SourceCIRun SourceKind = "ci_run"
	// SourceConnector is a server-side ingest: a connector sync, a feed.
	SourceConnector SourceKind = "connector"
	// SourceSensor is a report a sensor pushed without a command.
	SourceSensor SourceKind = "sensor"
)

// AllSourceKinds lists the kinds a list filter accepts.
func AllSourceKinds() []SourceKind {
	return []SourceKind{SourceUpload, SourceScanRun, SourceCommand, SourceCIRun, SourceConnector, SourceSensor}
}

// IsValid reports whether k is a known kind.
func (k SourceKind) IsValid() bool {
	for _, v := range AllSourceKinds() {
		if k == v {
			return true
		}
	}
	return false
}

// FactKind is the dash_ingest_day source kind of a receipt source.
func (k SourceKind) FactKind() string {
	switch k {
	case SourceUpload:
		return "import"
	case SourceCIRun:
		return "ci"
	case SourceConnector:
		return "connector"
	default:
		return "sensor"
	}
}

// Action is what a receipt did to one finding.
type Action string

const (
	ActionCreated       Action = "created"
	ActionStillDetected Action = "still_detected"
	ActionReopened      Action = "reopened"
	ActionClosed        Action = "closed"
)

// AllActions lists the actions in the order a receipt records them: the
// first action recorded for a finding wins, so a finding a run created is
// not later counted as still detected by another batch of the same run.
func AllActions() []Action {
	return []Action{ActionCreated, ActionReopened, ActionClosed, ActionStillDetected}
}

// IsValid reports whether a is a known action.
func (a Action) IsValid() bool {
	for _, v := range AllActions() {
		if a == v {
			return true
		}
	}
	return false
}

// Coverage values.
const (
	CoveragePartial = "partial"
	CoverageFull    = "full"
)

// Status values.
const (
	StatusProcessing = "processing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

// Limits.
const (
	// MaxActionsPerReceipt bounds the action rows of one receipt; the
	// counts stay exact (from the batch sizes) and ActionsTruncated is set.
	MaxActionsPerReceipt = 50_000
	// MaxErrors bounds the error entries stored on a receipt.
	MaxErrors = 100
	// ActionRetention is how long action rows are kept.
	ActionRetention = 90 * 24 * time.Hour
	// RunReceiptRetention is how long receipts of runs (not uploads) are
	// kept; an upload receipt is the producer record of what it wrote and
	// stays.
	RunReceiptRetention = 400 * 24 * time.Hour
	// FactRetention is how long dash_ingest_day rows are kept.
	FactRetention = 400 * 24 * time.Hour
)

// Error codes stored on a receipt (fixed values: a report's own text never
// reaches a receipt).
const (
	ErrorStoreFailed  = "store_failed"
	ErrorFileRejected = "file_rejected"
)

// ErrorEntry is one problem of a receipt: the index of the finding (or of
// the file, for an upload) and a fixed code.
type ErrorEntry struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

// Counts is what a receipt did.
type Counts struct {
	Created       int `json:"created"`
	StillDetected int `json:"updated"`
	Reopened      int `json:"reactivated"`
	Closed        int `json:"closed"`
	// Untouched is nil when the source declared no scope (partial
	// coverage): then nothing in particular was expected of it.
	Untouched  *int `json:"untouched"`
	Skipped    int  `json:"skipped"`
	Failed     int  `json:"failed"`
	Suppressed int  `json:"suppressed"`
}

// Receipt is the stored receipt.
type Receipt struct {
	ID               shared.ID
	TenantID         shared.ID
	SourceKind       SourceKind
	SourceRef        string
	ActorUserID      *shared.ID
	ToolName         string
	Format           string
	FilenameSHA256   string
	Coverage         string
	CoverageNote     string
	Status           string
	Reports          int
	Received         int
	AssetsCreated    int
	AssetsUpdated    int
	Components       int
	Statements       int
	VEXStored        int
	VEXRequested     int
	Counts           Counts
	ActionsRecorded  int
	ActionsTruncated bool
	Errors           []ErrorEntry
	CreatedAt        time.Time
	UpdatedAt        time.Time
	FinishedAt       *time.Time
}

// Source names the receipt a delta belongs to. For a command, CommandID is
// set and the repository resolves it to its scan run (or the command itself
// when it is not part of one).
type Source struct {
	Kind      SourceKind
	Ref       string
	CommandID *shared.ID
}

// Delta is what one ingest (one report or batch) or one coverage decision
// adds to a receipt. The id lists are the findings acted on; the counts of
// the receipt grow by the rows the delta actually added, so a finding two
// batches of one run both report is counted once.
type Delta struct {
	TenantID shared.ID
	Source   Source
	Tool     string
	// Reports is 1 for an ingest, 0 for a coverage decision.
	Reports       int
	Received      int
	AssetsCreated int
	AssetsUpdated int
	Skipped       int
	Failed        int
	Suppressed    int

	Created  []shared.ID
	Reopened []shared.ID
	Closed   []shared.ID
	// StillDetected are the stored fingerprints the source reported; the
	// repository resolves them to the tenant's findings.
	StillDetected []string

	// Coverage is set ("full") only by a decision that proved coverage of
	// an explicit scope; Untouched with it.
	Coverage     string
	CoverageNote string
	Untouched    *int

	Errors []ErrorEntry
	At     time.Time
}

// Empty reports whether the delta changes nothing.
func (d *Delta) Empty() bool {
	return d.Reports == 0 && d.Received == 0 && d.AssetsCreated == 0 && d.AssetsUpdated == 0 &&
		d.Skipped == 0 && d.Failed == 0 && d.Suppressed == 0 && len(d.Created) == 0 &&
		len(d.Reopened) == 0 && len(d.Closed) == 0 && len(d.StillDetected) == 0 &&
		d.Coverage == "" && d.Untouched == nil && len(d.Errors) == 0
}

// Upload is the start of an upload receipt.
type Upload struct {
	ID             shared.ID
	TenantID       shared.ID
	ActorUserID    *shared.ID
	Format         string
	FilenameSHA256 string
}

// UploadResult is what an upload adds when it finishes, beyond what its
// ingests recorded.
type UploadResult struct {
	Status       string
	Format       string
	Skipped      int
	Components   int
	Statements   int
	VEXStored    int
	VEXRequested int
	Errors       []ErrorEntry
	// Coverage and Untouched are set when the upload declared full
	// coverage of an explicit scope.
	Coverage     string
	CoverageNote string
	Untouched    *int
}

// Filter narrows a receipt list.
type Filter struct {
	SourceKind SourceKind
	SourceRef  string
	// ActorUserID, when set, keeps only the receipts that person started
	// (a reader without an organization view).
	ActorUserID *shared.ID
}

// ActionRow is one finding a receipt acted on, as listed to a reader.
type ActionRow struct {
	FindingID shared.ID
	Action    Action
	Title     string
	Severity  string
	At        time.Time
}

// FindingAction is one receipt that acted on a finding, newest first.
type FindingAction struct {
	ReceiptID  shared.ID
	SourceKind SourceKind
	SourceRef  string
	ToolName   string
	Action     Action
	At         time.Time
}

// Repository stores receipts. Every method is scoped by tenant.
type Repository interface {
	// Record applies a delta in one transaction: the receipt (created on
	// first use), its action rows (capped), its counts and the day's
	// dash_ingest_day row. It returns the receipt id.
	Record(ctx context.Context, d *Delta) (shared.ID, error)
	// CreateUpload records the start of an upload (status processing).
	CreateUpload(ctx context.Context, u *Upload) error
	// FinishUpload stores what an upload adds when it is done.
	FinishUpload(ctx context.Context, tenantID, id shared.ID, r *UploadResult) error
}

// ReportRef is the receipt key of a report without a run: the submitter
// (a sensor, or the zero id for a server-side ingest) and the report id,
// hashed to a fixed width so a long or hostile report id is never stored.
func ReportRef(submitter shared.ID, reportID string) string {
	sum := sha256.Sum256([]byte(submitter.String() + "\x00" + reportID))
	return hex.EncodeToString(sum[:20])
}
