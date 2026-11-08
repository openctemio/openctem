// Package sourceretire models retiring an import source: "stop using this
// source" (api/docs/architecture/source-retirement.md).
//
// A source is a sighting key without the scan definition: a sensor of the
// organization and a tool, an uploaded tool, or a server-side connector
// source name. Retiring it blocks its new data (ingest refuses its reports
// and counts them on the receipt) and archives the open findings only it
// reported as source retired: resolved, closure reason obsolete_source,
// never counted as fixed. A journal keeps the archived set, so using the
// source again restores exactly that set.
package sourceretire

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Kind is what kind of source is retired.
type Kind string

const (
	// KindSensorTool: a tool run by one of the organization's sensors
	// (scan runs, tasks, unsolicited reports, a connector that syncs
	// through a sensor).
	KindSensorTool Kind = "sensor_tool"
	// KindUpload: files of one tool uploaded by people.
	KindUpload Kind = "upload"
	// KindConnector: a server-side connector source name.
	KindConnector Kind = "connector"
)

// Mode says what happens to the findings only the source reported.
type Mode string

const (
	// ModeArchive archives them as source retired (the default).
	ModeArchive Mode = "archive"
	// ModeKeepOpen leaves every finding open: only new data is blocked.
	ModeKeepOpen Mode = "keep_open"
)

// State is where a retirement is.
type State string

const (
	StateApplying  State = "applying"
	StateActive    State = "active"
	StateRestoring State = "restoring"
	StateRestored  State = "restored"
)

// Live reports whether the source is retired in this state (its data is
// blocked).
func (s State) Live() bool { return s == StateApplying || s == StateActive }

// Field limits.
const (
	MaxTool        = 100
	MaxSender      = 128
	MaxLabel       = 200
	MinReason      = 10
	MaxReason      = 500
	MaxAuditedIDs  = 200
	BatchSize      = 1000
	MaxSightingCap = ingestreceipt.MaxSightingsPerFinding
)

// Errors.
var (
	ErrNotFound                = fmt.Errorf("%w: source retirement not found", shared.ErrNotFound)
	ErrSourceNotFound          = fmt.Errorf("%w: source not found", shared.ErrNotFound)
	ErrConfirmCriticalRequired = shared.NewDomainError("CONFIRM_CRITICAL_REQUIRED",
		"critical or known-exploited findings would be archived: confirm them separately", shared.ErrConflict)
	ErrFullDataAccessRequired = shared.NewDomainError("FULL_DATA_ACCESS_REQUIRED",
		"retiring a source changes findings of the whole organization: it needs full data access", shared.ErrForbidden)
	ErrNotRestorable = shared.NewDomainError("NOT_RESTORABLE",
		"this source is not retired any more", shared.ErrConflict)
)

// Selector names one source.
type Selector struct {
	Kind     Kind
	SensorID *shared.ID
	Sender   string
	Tool     string
}

// Normalize trims the values and maps a retired tool name to its current
// one, the way ingest names tools.
func (s Selector) Normalize() Selector {
	s.Sender = strings.TrimSpace(s.Sender)
	s.Tool = strings.TrimSpace(tooldom.CanonicalName(strings.TrimSpace(s.Tool)))
	return s
}

// Validate checks the selector's shape for its kind.
func (s Selector) Validate() error {
	switch s.Kind {
	case KindSensorTool:
		if s.SensorID == nil || s.SensorID.IsZero() || s.Tool == "" || s.Sender != "" {
			return fmt.Errorf("%w: a sensor tool source needs sensor_id and tool", shared.ErrValidation)
		}
	case KindUpload:
		if s.SensorID != nil || s.Tool == "" || s.Sender != "" {
			return fmt.Errorf("%w: an upload source needs tool only", shared.ErrValidation)
		}
	case KindConnector:
		if s.SensorID != nil || s.Sender == "" || s.Tool != "" {
			return fmt.Errorf("%w: a connector source needs sender only", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: kind must be sensor_tool, upload or connector", shared.ErrValidation)
	}
	if len(s.Tool) > MaxTool || len(s.Sender) > MaxSender {
		return fmt.Errorf("%w: tool or sender too long", shared.ErrValidation)
	}
	return nil
}

// Report is what ingest knows about the sender of a report.
type Report struct {
	// Channel is the sighting channel of the report.
	Channel ingestreceipt.Channel
	// Instance is the receipt instance (sensor, connector, import, ...).
	Instance ingestreceipt.Instance
	// Tool is the report's tool name.
	Tool string
}

// Matches reports whether a report comes from the source s. It is the
// ingest side of source_retirement_matches (the migration's SQL function).
func (s Selector) Matches(r Report) bool {
	switch s.Kind {
	case KindSensorTool:
		return s.SensorID != nil && r.Instance.Kind == ingestreceipt.InstanceSensor &&
			strings.EqualFold(r.Instance.ID, s.SensorID.String()) && tooldom.SameTool(r.Tool, s.Tool)
	case KindUpload:
		return r.Channel == ingestreceipt.ChannelUpload && tooldom.SameTool(r.Tool, s.Tool)
	case KindConnector:
		return r.Channel == ingestreceipt.ChannelConnector && r.Instance.Kind == ingestreceipt.InstanceConnector &&
			strings.TrimSpace(r.Instance.ID) == s.Sender
	}
	return false
}

// Options are the choices of the dialog. The zero value plus Mode archive
// is the default: every severity, findings in remediation stay open.
type Options struct {
	Mode Mode
	// Severities to archive; empty means every severity.
	Severities []vulnerability.Severity
	// IncludeEngaged archives new or confirmed findings that have a ticket,
	// an open remediation task or an assignee too.
	IncludeEngaged bool
}

// Normalize fills the defaults and validates.
func (o Options) Normalize() (Options, error) {
	if o.Mode == "" {
		o.Mode = ModeArchive
	}
	if o.Mode != ModeArchive && o.Mode != ModeKeepOpen {
		return o, fmt.Errorf("%w: mode must be archive or keep_open", shared.ErrValidation)
	}
	out := make([]vulnerability.Severity, 0, len(o.Severities))
	for _, s := range o.Severities {
		if !s.IsValid() {
			return o, fmt.Errorf("%w: unknown severity %q", shared.ErrValidation, s)
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	o.Severities = out
	return o, nil
}

// SeverityStrings returns the severities as strings (empty = every one).
func (o Options) SeverityStrings() []string {
	out := make([]string, 0, len(o.Severities))
	for _, s := range o.Severities {
		out = append(out, string(s))
	}
	return out
}

// Preview is what retiring a source would do, computed by the same query
// the archive runs.
type Preview struct {
	// Total findings the source reported (any status).
	Total int `json:"total"`
	// Archive: open findings only this source reported that would be
	// archived as source retired.
	Archive int `json:"archive"`
	// ArchiveBySeverity breaks Archive down.
	ArchiveBySeverity map[string]int `json:"archive_by_severity"`
	// CriticalOrKEV of Archive: they need a separate confirmation.
	CriticalOrKEV int `json:"critical_or_kev"`
	// WithSLA of Archive: they leave their SLA.
	WithSLA int `json:"with_sla"`
	// Corroborated: another source (not retired) reported them too; they
	// are not changed.
	Corroborated int `json:"corroborated"`
	// Kept open, only this source reported them:
	KeptEngaged         int `json:"kept_engaged"`          // ticket, task or assignee (new/confirmed)
	KeptInProgress      int `json:"kept_in_progress"`      // in_progress, fix_applied
	KeptSecret          int `json:"kept_secret"`           // a secret stays open until rotated
	KeptSeveritySkipped int `json:"kept_severity_skipped"` // severity not selected
	// AlreadyClosed: only this source reported them and they are closed.
	AlreadyClosed int `json:"already_closed"`
}

// Retirement is one retirement of a source.
type Retirement struct {
	ID             shared.ID
	TenantID       shared.ID
	Selector       Selector
	IntegrationID  *shared.ID
	Label          string
	Options        Options
	State          State
	Reason         string
	PlannedCount   int
	ArchivedCount  int
	RestoredCount  int
	ChangedCount   int
	RetiredBy      *shared.ID
	RetiredAt      time.Time
	RestoredBy     *shared.ID
	RestoreReason  string
	RestoredAt     *time.Time
	UpdatedAt      time.Time
	AlreadyRetired bool // set by Create when the source was already retired
}

// Done reports whether no batch is left to run.
func (r *Retirement) Done() bool { return r.State == StateActive || r.State == StateRestored }

// BatchResult is what one batch did.
type BatchResult struct {
	Moved    int
	Changed  int
	IDs      []shared.ID
	Finished bool
}

// Repository persists retirements. Every method is pinned to tenantID.
type Repository interface {
	// Preview classifies the findings the source reported.
	Preview(ctx context.Context, tenantID shared.ID, sel Selector, opts Options, exclude *shared.ID) (*Preview, error)
	// Create inserts a retirement in state applying (active for keep_open),
	// or returns the live one of the same source with AlreadyRetired set.
	Create(ctx context.Context, r *Retirement) (*Retirement, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*Retirement, error)
	List(ctx context.Context, tenantID shared.ID, includeRestored bool, limit int) ([]*Retirement, error)
	// ArchiveBatch archives up to BatchSize findings of an applying
	// retirement, journals them, and marks it active when none is left.
	ArchiveBatch(ctx context.Context, tenantID, id shared.ID, at time.Time) (*BatchResult, error)
	// StartRestore moves a live retirement to restoring (the source is
	// usable again at once) and returns how many findings it will restore.
	StartRestore(ctx context.Context, tenantID, id shared.ID, by *shared.ID, reason string) (*Retirement, error)
	// RestoreBatch restores up to BatchSize journalled findings and marks
	// the retirement restored when none is left.
	RestoreBatch(ctx context.Context, tenantID, id shared.ID, at time.Time) (*BatchResult, error)
	// Live returns the tenant's live retirements (ingest policy snapshot).
	Live(ctx context.Context, tenantID shared.ID) ([]Selector, error)
	// Pending lists retirements with batches left (any tenant: the
	// controller), oldest first.
	Pending(ctx context.Context, limit int) ([]PendingRef, error)
}

// PendingRef names a retirement with batches left.
type PendingRef struct {
	TenantID shared.ID
	ID       shared.ID
	State    State
}
