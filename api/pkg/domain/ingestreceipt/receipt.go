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
	// SourcePlatform is what the platform derived itself (the inventory
	// version matcher's findings): its own receipt, never a sensor's.
	SourcePlatform SourceKind = "platform"
)

// AllSourceKinds lists the kinds a list filter accepts.
func AllSourceKinds() []SourceKind {
	return []SourceKind{SourceUpload, SourceScanRun, SourceCommand, SourceCIRun, SourceConnector, SourceSensor, SourcePlatform}
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
	case SourcePlatform:
		return "platform"
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
	// ActionSuppressed: a new finding an approved suppression rule decided
	// (stored as a finding with a false positive or accepted status).
	ActionSuppressed Action = "suppressed"
	// ActionHeld: a new finding held for review (the opt-in review gate).
	ActionHeld Action = "held"
)

// AllActions lists the actions in the order a receipt records them: the
// first action recorded for a finding wins, so a finding a run created is
// not later counted as still detected by another batch of the same run, and
// a suppressed new finding is not counted as created.
func AllActions() []Action {
	return []Action{ActionSuppressed, ActionHeld, ActionCreated, ActionReopened, ActionClosed, ActionStillDetected}
}

// Disposition is what a receipt did with an item it did not turn into a
// finding.
type Disposition string

const (
	// DispositionFiltered: an ingest filter dropped a low-value item.
	DispositionFiltered Disposition = "filtered"
	// DispositionOutOfScope: the item's asset is excluded, outside the
	// binding or outside the uploader's scope.
	DispositionOutOfScope Disposition = "out_of_scope"
	// DispositionRejected: the item could not be stored (no asset, invalid).
	DispositionRejected Disposition = "rejected"
	// DispositionQuarantined: the whole report waits in the quarantine.
	DispositionQuarantined Disposition = "quarantined"
)

// AllDispositions lists the item dispositions.
func AllDispositions() []Disposition {
	return []Disposition{DispositionFiltered, DispositionOutOfScope, DispositionRejected, DispositionQuarantined}
}

// IsValid reports whether d is a known disposition.
func (d Disposition) IsValid() bool {
	for _, v := range AllDispositions() {
		if d == v {
			return true
		}
	}
	return false
}

// Policy kinds that decide an item.
const (
	PolicySuppressionRule = "suppression_rule"
	PolicyScopeExclusion  = "scope_exclusion"
	PolicyUploaderScope   = "uploader_scope"
	PolicyBinding         = "binding"
	PolicyValidation      = "validation"
	PolicyQuarantine      = "quarantine"
)

// Reason codes of item dispositions (fixed values).
const (
	ReasonExcluded      = "excluded"
	ReasonOutsideScope  = "outside_uploader_scope"
	ReasonNoTargetAsset = "no_target_asset"
	ReasonNoCommand     = "no_command"
	// ReasonOutsideJob: the item's asset lies outside the targets of the
	// command the report is bound to.
	ReasonOutsideJob = "outside_job_targets"
	// ReasonOverCap: the item's asset lies outside the bound command's
	// targets and the report had already recorded as many such assets as
	// one report may (research 436).
	ReasonOverCap = "over_cap"
	// ReasonHeldForReview: the output-type binding held the item (its type,
	// or its asset's, is not one the command's tool produces); it waits in
	// the results quarantine.
	ReasonHeldForReview = "held_for_review"
	// ReasonQuarantineFull: held, but the quarantine could not keep it.
	ReasonQuarantineFull = "quarantine_full"
	// ReasonUnresolvedRef: the finding names no asset of its segment.
	ReasonUnresolvedRef = "unresolved_ref"
)

// Item is one item a receipt did not turn into a finding. Key is a stable
// identity hash of the item (never its content); no evidence is kept.
type Item struct {
	Key           string
	Disposition   Disposition
	ReasonCode    string
	AssetID       *shared.ID
	Tool          string
	Title         string
	Severity      string
	Policy        string
	PolicyID      *shared.ID
	PolicyVersion int64
}

// PolicyAction is a new finding a policy decided (suppressed, held), with
// the policy and its version.
type PolicyAction struct {
	FindingID     shared.ID
	Action        Action
	Policy        string
	PolicyID      *shared.ID
	PolicyVersion int64
}

// ItemKey is the identity hash of an item: tenant-independent, fixed width.
func ItemKey(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:20])
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
	// StatusQueued: an upload accepted and waiting for the ingest worker.
	StatusQueued     = "queued"
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
	// ErrorContractMismatch: the finding's tool reported a type its signed
	// descriptor does not declare; the finding was ingested and flagged.
	ErrorContractMismatch = "contract_mismatch"
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
	// Outcomes counts the received findings that went elsewhere than the
	// action counts (Outcome* codes).
	Outcomes map[string]int
	// ReleasedFromQuarantine: a report held in the results quarantine and
	// applied later is part of this receipt (its sender is the original
	// sensor).
	ReleasedFromQuarantine bool
	// Closing is what a scan file's own coverage closed (nil: none did).
	Closing    *Closing
	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt *time.Time
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
	// ToolVersion is the reporting tool's version, kept on the sightings.
	ToolVersion string
	// Instance is what sent the report (a sensor, a CI repository, a
	// connector, the platform); empty for a coverage decision, which adds to
	// the receipt's own counts only.
	Instance Instance
	// Reports is 1 for an ingest, 0 for a coverage decision.
	Reports       int
	Received      int
	AssetsCreated int
	AssetsUpdated int
	Skipped       int
	Failed        int
	Suppressed    int
	// Outcomes counts where the received findings went beyond the action
	// counts (Outcome* codes). The repository adds OutcomeMerged for the
	// findings an earlier delta of the receipt already acted on.
	Outcomes map[string]int
	// Released marks a report applied from the results quarantine: the
	// receipt and the sender's row carry the marker, nothing else changes.
	Released bool

	Created  []shared.ID
	Reopened []shared.ID
	Closed   []shared.ID
	// StillDetected are the stored fingerprints the source reported; the
	// repository resolves them to the tenant's findings.
	StillDetected []string
	// Decided are new findings a policy decided (suppressed, held): they
	// are recorded with that action and the policy instead of created.
	Decided []PolicyAction
	// Items are the reported items that did not become findings.
	Items []Item

	// Coverage is set ("full") only by a decision that proved coverage of
	// an explicit scope; Untouched with it.
	Coverage     string
	CoverageNote string
	Untouched    *int

	Errors []ErrorEntry
	At     time.Time
}

// Outcome codes: where a received finding went when it is none of created,
// still detected, reopened, suppressed, failed or skipped. A receipt
// reconciles: received + split = created + still detected + reopened +
// suppressed + failed + skipped + every other outcome (research 436).
const (
	// OutcomeSplit: extra findings a finding naming several CVEs became
	// (one per CVE); the only outcome that adds to received.
	OutcomeSplit = "split"
	// OutcomeMerged: a repeat of a finding the same report or an earlier
	// report of the receipt already named (one observation, last seen
	// updated).
	OutcomeMerged = "merged"
	// OutcomeExposure: a template scanner's info match, filed as an
	// exposure instead of a finding.
	OutcomeExposure = "exposure"
	// OutcomeSourceMitigated: the source reported it mitigated; it resolves
	// a finding instead of sighting one.
	OutcomeSourceMitigated = "source_mitigated"
	// OutcomeUnresolvedRef: the finding named no asset of its document
	// (malformed; refused before ingest).
	OutcomeUnresolvedRef = "unresolved_ref"
	// OutcomeOutOfContract: the finding was held with its asset by the
	// output contract of the report's tool (quarantined for review).
	OutcomeOutOfContract = "out_of_contract"
	// OutcomeReservedTool: the report claimed the tool name of the
	// platform's own inventory matcher; its findings are refused.
	OutcomeReservedTool = "reserved_tool"
	// OutcomeCompliancePassed: a compliance check that passed. It is no
	// finding and no sighting of the failed result of the same check; an
	// upload resolves that open failure with it.
	OutcomeCompliancePassed = "compliance_passed"
	// OutcomeQuarantined: the report came without a command and waits in
	// the results quarantine; a person releases or discards it.
	OutcomeQuarantined = "quarantined"
)

// AllOutcomes lists the outcome codes, in display order.
func AllOutcomes() []string {
	return []string{OutcomeMerged, OutcomeExposure, OutcomeSourceMitigated, OutcomeUnresolvedRef,
		OutcomeOutOfContract, OutcomeReservedTool, OutcomeCompliancePassed, OutcomeQuarantined, OutcomeSplit}
}

// Unaccounted is how many received findings no count and no outcome
// explains: received + split - (created + still detected + reopened +
// suppressed + failed + skipped + the other outcomes). A reconciled receipt
// has 0; closed and untouched findings are decisions about findings the
// source did not report, so they are not part of the sum.
func Unaccounted(received int, c Counts, outcomes map[string]int) int {
	n := received - c.Created - c.StillDetected - c.Reopened - c.Suppressed - c.Failed - c.Skipped
	for code, v := range outcomes {
		if code == OutcomeSplit {
			n += v
			continue
		}
		n -= v
	}
	return n
}

// IsOutcome reports whether c is an outcome code.
func IsOutcome(c string) bool {
	for _, o := range AllOutcomes() {
		if o == c {
			return true
		}
	}
	return false
}

// Instance kinds: what sent a report.
const (
	InstanceSensor    = "sensor"
	InstanceCI        = "ci"
	InstanceConnector = "connector"
	InstancePlatform  = "platform"
	InstanceImport    = "import"
)

// IsInstanceKind reports whether k is one of the Instance* kinds.
func IsInstanceKind(k string) bool {
	switch k {
	case InstanceSensor, InstanceCI, InstanceConnector, InstancePlatform, InstanceImport:
		return true
	}
	return false
}

// Instance is the sender of a report: Kind is one of the Instance* kinds, ID
// its key (a sensor id, a CI repository, a connector source name,
// "platform", "import"), Name a display name when the ID is not one
// (untrusted text, clipped by the repository).
type Instance struct {
	Kind string
	ID   string
	Name string
}

// Empty reports whether the delta changes nothing.
func (d *Delta) Empty() bool {
	return d.Reports == 0 && d.Received == 0 && d.AssetsCreated == 0 && d.AssetsUpdated == 0 &&
		d.Skipped == 0 && d.Failed == 0 && d.Suppressed == 0 && len(d.Outcomes) == 0 && !d.Released && len(d.Created) == 0 &&
		len(d.Reopened) == 0 && len(d.Closed) == 0 && len(d.StillDetected) == 0 &&
		len(d.Decided) == 0 && len(d.Items) == 0 &&
		d.Coverage == "" && d.Untouched == nil && len(d.Errors) == 0
}

// Upload is the start of an upload receipt.
type Upload struct {
	ID             shared.ID
	TenantID       shared.ID
	ActorUserID    *shared.ID
	Format         string
	FilenameSHA256 string
	// Status is the receipt's first state: queued for an upload the ingest
	// worker applies, processing (the default) otherwise.
	Status string
}

// UploadResult is what an upload adds when it finishes, beyond what its
// ingests recorded.
type UploadResult struct {
	Status string
	Format string
	// Skipped is the records the parser skipped and the files of a bundle
	// it did not read: received with the upload and not imported, so they
	// count as received and skipped.
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
	// Closing is what a scan file's own coverage closed and why the rest
	// stayed open (nil when no file carried its coverage).
	Closing *Closing
}

// Closing reasons: why an open finding a scan file did not report was
// closed, or kept open (docs/architecture/finding-import.md, "What a Nessus
// import closes").
const (
	// ClosedNotInScan: the check ran on the finished host and did not find it.
	ClosedNotInScan = "not_in_scan"
	// ClosedCompliancePassed: the same compliance check passed.
	ClosedCompliancePassed = "compliance_passed"

	// KeptHostNotFinished: the file does not record the end of the host's scan.
	KeptHostNotFinished = "host_not_finished"
	// KeptLocalChecksNotRun: a local check, and the scan did not log in to
	// the host or authentication failed.
	KeptLocalChecksNotRun = "local_checks_not_run"
	// KeptCheckNotRun: the check (plugin or its family) was not part of the scan.
	KeptCheckNotRun = "check_not_run"
	// KeptSeenLater: the finding was seen after the file's scan of the host.
	KeptSeenLater = "seen_later"
	// KeptFileIncomplete: the file cannot prove an absence (no plugin
	// selection or plugin details), or a file or row of the upload failed.
	KeptFileIncomplete = "file_incomplete"
	// KeptNeedsVerify: the uploader may not verify fixes (findings:verify).
	KeptNeedsVerify = "needs_verify"
	// KeptGuard: a guard keeps it (critical or known exploited, a leaked
	// secret, last seen by a platform sensor, a compliance result missing
	// from the file, the organization's closing mode, or it changed meanwhile).
	KeptGuard = "guard"
)

// Closing counts the outcome of every open finding a scan file's coverage
// considered. It reconciles: Considered = sum(Closed) + Proposed + sum(Kept).
type Closing struct {
	Considered int            `json:"considered"`
	Closed     map[string]int `json:"closed"`
	// Proposed went to Ready to close for a person to confirm (the closing
	// mode, or the mass-close guard held them).
	Proposed int            `json:"proposed"`
	Kept     map[string]int `json:"kept"`
	// Hosts of the files; HostsUnfinished have no recorded scan end,
	// HostsLocalChecksFailed were not logged in to (or authentication failed).
	Hosts                  int `json:"hosts"`
	HostsUnfinished        int `json:"hosts_unfinished"`
	HostsLocalChecksFailed int `json:"hosts_local_checks_failed"`
}

// NewClosing returns an empty Closing.
func NewClosing() *Closing {
	return &Closing{Closed: map[string]int{}, Kept: map[string]int{}}
}

// Reconciles reports whether every considered finding has one outcome.
func (c *Closing) Reconciles() bool {
	n := c.Proposed
	for _, v := range c.Closed {
		n += v
	}
	for _, v := range c.Kept {
		n += v
	}
	return n == c.Considered
}

// ClosedTotal is the number of findings closed.
func (c *Closing) ClosedTotal() int {
	n := 0
	for _, v := range c.Closed {
		n += v
	}
	return n
}

// Filter narrows a receipt list.
type Filter struct {
	SourceKind SourceKind
	SourceRef  string
	// Origin keeps the receipts of one source group (FactKind: sensor,
	// import, connector, ci), the grouping the dashboards count by.
	Origin string
	// Tool keeps the receipts of one tool; UnknownTool matches the
	// receipts that named none.
	Tool string
	// Since keeps the receipts with activity (updated_at) at or after it.
	Since *time.Time
	// ActorUserID, when set, keeps only the receipts that person started
	// (a reader without an organization view).
	ActorUserID *shared.ID
}

// UnknownTool is the tool key of a receipt that named no tool, in lists,
// filters and dash_ingest_day.
const UnknownTool = "unknown"

// Origins lists the source groups a list filter and the dashboards accept
// (the FactKind of every source kind).
func Origins() []string { return []string{"sensor", "import", "connector", "ci", "platform"} }

// IsOrigin reports whether o is a known source group.
func IsOrigin(o string) bool {
	for _, v := range Origins() {
		if v == o {
			return true
		}
	}
	return false
}

// Totals sums the receipts of a filter: the figures a dashboard shows for
// the same filter, so a dashboard number equals the list it opens.
type Totals struct {
	Receipts      int64
	Received      int64
	Created       int64
	StillDetected int64
	Reopened      int64
	Closed        int64
	Skipped       int64
	Failed        int64
	Suppressed    int64
}

// ActionRow is one finding a receipt acted on, as listed to a reader.
type ActionRow struct {
	FindingID     shared.ID
	Action        Action
	Title         string
	Severity      string
	At            time.Time
	Policy        string
	PolicyID      *shared.ID
	PolicyVersion *int64
}

// ItemRow is one item a receipt did not turn into a finding, as listed.
type ItemRow struct {
	Item
	At time.Time
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
