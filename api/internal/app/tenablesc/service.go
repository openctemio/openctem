package tenablesc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Sync modes.
const (
	ModeIncremental = "incremental"
	ModeFull        = "full"
)

// Triggers recorded with a sync request.
const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
)

// Limits.
const (
	// SyncCommandTTL bounds how long a connector_sync command may wait and
	// run before the platform expires it.
	SyncCommandTTL = 6 * time.Hour
	// MaxWindowDays is the widest incremental window; beyond it a full sync
	// runs instead.
	MaxWindowDays = 365
	// failureRetry is how soon a failed scheduled sync is tried again, at
	// most (never sooner than the interval would allow when that is shorter).
	failureRetry = 30 * time.Minute
	// maxSyncErrorLen caps the sensor-supplied error kept on the integration.
	maxSyncErrorLen = 512
)

// metadataKey is the integration metadata key holding the sync state.
const metadataKey = "tenable_sync"

// Errors.
var (
	// ErrSensorUnavailable: the integration's sensor cannot run the connector
	// now (not active, or it does not report the tenable_sc tool).
	ErrSensorUnavailable = shared.NewDomainError("CONNECTOR_SENSOR_UNAVAILABLE",
		"the integration's sensor is not active or does not run the Tenable.sc connector (tool tenable_sc)", shared.ErrConflict)
	// ErrPlatformSensor: shared platform sensors never run a tenant's
	// connector (they would hold one tenant's Tenable keys while serving
	// others).
	ErrPlatformSensor = shared.NewDomainError("CONNECTOR_PLATFORM_SENSOR",
		"a shared platform sensor cannot run a tenant's Tenable.sc connector; use one of your own sensors", shared.ErrValidation)
)

// ErrDisabled: a disabled integration does not sync.
var ErrDisabled = shared.NewDomainError("INTEGRATION_DISABLED",
	"the integration is disabled; enable it to sync", shared.ErrConflict)

// IntegrationStore is the slice of the integration repository the service uses.
type IntegrationStore interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*integration.Integration, error)
	Update(ctx context.Context, i *integration.Integration) error
}

// SensorReader reads a tenant's sensor.
type SensorReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error)
}

// CommandStore creates and reads a tenant's commands.
type CommandStore interface {
	Create(ctx context.Context, cmd *command.Command) error
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*command.Command, error)
}

// ReportReader returns a command's status and the v2 reports filed under it
// (satisfied by the postgres finding repository).
type ReportReader interface {
	CommandCoverage(ctx context.Context, tenantID, commandID shared.ID) (*ingestreport.CommandCoverage, error)
}

// Service queues connector_sync commands and follows them.
type Service struct {
	integrations IntegrationStore
	sensors      SensorReader
	commands     CommandStore
	reports      ReportReader
	claimer      SyncClaimer
	audit        *auditapp.AuditService
	logger       *logger.Logger
	now          func() time.Time
}

// NewService creates the service. audit may be nil.
func NewService(integrations IntegrationStore, sensors SensorReader, commands CommandStore, reports ReportReader,
	audit *auditapp.AuditService, log *logger.Logger) *Service {
	return &Service{
		integrations: integrations,
		sensors:      sensors,
		commands:     commands,
		reports:      reports,
		audit:        audit,
		logger:       log.With("service", "tenable_sc_connector"),
		now:          time.Now,
	}
}

// SyncPayload is the connector_sync command payload (RFC-047 §5.1).
type SyncPayload struct {
	Scanner       string   `json:"scanner"`
	Instance      string   `json:"instance"`
	IntegrationID string   `json:"integration_id"`
	Mode          string   `json:"mode"`
	WindowDays    int      `json:"window_days,omitempty"`
	Include       []string `json:"include"`
	MinSeverity   int      `json:"min_severity"`
	Repositories  []int    `json:"repositories,omitempty"`
}

// SyncState is the connector's state on the integration (metadata
// "tenable_sync"). Written only by this service; read by the UI.
type SyncState struct {
	OpenCommandID      string     `json:"open_command_id,omitempty"`
	OpenMode           string     `json:"open_mode,omitempty"`
	OpenRequestedAt    *time.Time `json:"open_requested_at,omitempty"`
	LastSuccessfulSync *time.Time `json:"last_successful_sync,omitempty"`
	LastFullSync       *time.Time `json:"last_full_sync,omitempty"`
	LastCommandID      string     `json:"last_command_id,omitempty"`
	LastOutcome        string     `json:"last_outcome,omitempty"`
	TenableVersion     string     `json:"tenable_version,omitempty"`
	LicensedIPs        int        `json:"licensed_ips,omitempty"`
	ActiveIPs          int        `json:"active_ips,omitempty"`
	Hosts              int        `json:"hosts,omitempty"`
	OpenVulns          int        `json:"open,omitempty"`
	MitigatedVulns     int        `json:"mitigated,omitempty"`
	Plugins            int        `json:"plugins,omitempty"`
	// Catalog is what the sensor last reported it allows (names for the
	// scan pickers); nil until a sync reports one.
	Catalog *Catalog `json:"catalog,omitempty"`
}

// Outcomes recorded in SyncState.LastOutcome.
const (
	OutcomeCompleted = "completed"
	OutcomeFailed    = "failed"
)

// RequestResult is what a sync request did.
type RequestResult struct {
	CommandID shared.ID
	Mode      string
	// AlreadyOpen: a sync of this integration was still open; it is returned
	// instead of queuing another.
	AlreadyOpen bool
	// Integration is the integration as stored after the request.
	Integration *integration.Integration
}

// RequestSync queues a connector_sync for a tenant's connector integration,
// or returns the one still open. The integration and the sensor are read
// tenant-scoped: another tenant's integration is not found, another tenant's
// sensor is not found.
func (s *Service) RequestSync(ctx context.Context, tenantID, integrationID shared.ID, trigger string,
	actx *auditapp.AuditContext) (RequestResult, error) {
	intg, err := s.integrations.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return RequestResult{}, err
	}
	return s.requestSync(ctx, intg, trigger, actx)
}

func (s *Service) requestSync(ctx context.Context, intg *integration.Integration, trigger string,
	actx *auditapp.AuditContext) (RequestResult, error) {
	cfg, err := ParseConnectorConfig(intg)
	if err != nil {
		return RequestResult{}, err
	}
	if intg.Status() == integration.StatusDisabled {
		return RequestResult{}, ErrDisabled
	}
	tenantID := intg.TenantID()

	// Settle a finished sync first, so its outcome and cursor are current.
	if _, err := s.reconcile(ctx, intg); err != nil {
		return RequestResult{}, err
	}
	state := readState(intg)
	if state.OpenCommandID != "" {
		id, perr := shared.IDFromString(state.OpenCommandID)
		if perr == nil {
			return RequestResult{CommandID: id, Mode: state.OpenMode, AlreadyOpen: true, Integration: intg}, nil
		}
	}

	sn, err := s.sensors.GetByTenantAndID(ctx, tenantID, cfg.SensorID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return RequestResult{}, invalid("sensor_id names no sensor of this organization")
		}
		return RequestResult{}, err
	}
	if sn.IsPlatformSensor || sn.TenantID == nil || *sn.TenantID != tenantID {
		return RequestResult{}, ErrPlatformSensor
	}
	if !SensorRunsConnector(sn) {
		return RequestResult{}, ErrSensorUnavailable
	}

	now := s.now().UTC()
	mode, window := syncWindow(state, cfg, now)
	payload, err := json.Marshal(SyncPayload{
		Scanner:       ToolName,
		Instance:      cfg.Instance,
		IntegrationID: intg.ID().String(),
		Mode:          mode,
		WindowDays:    window,
		Include:       []string{"hosts", "vulns", "mitigated", "plugins"},
		MinSeverity:   cfg.MinSeverity,
		Repositories:  cfg.Repositories,
	})
	if err != nil {
		return RequestResult{}, fmt.Errorf("encode connector_sync payload: %w", err)
	}
	cmd, err := command.NewCommand(tenantID, command.CommandTypeConnectorSync, command.CommandPriorityNormal, payload)
	if err != nil {
		return RequestResult{}, err
	}
	cmd.SetSensorID(sn.ID)
	cmd.SetExpiration(now.Add(SyncCommandTTL))
	if err := s.commands.Create(ctx, cmd); err != nil {
		return RequestResult{}, fmt.Errorf("create connector_sync command: %w", err)
	}

	state.OpenCommandID = cmd.ID.String()
	state.OpenMode = mode
	state.OpenRequestedAt = &now
	writeState(intg, state)
	if err := s.integrations.Update(ctx, intg); err != nil {
		// The command exists; the next request or reconcile finds no open id
		// and may queue another. Report the failure rather than hide it.
		return RequestResult{}, fmt.Errorf("record connector_sync on the integration: %w", err)
	}

	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionIntegrationSyncRequested, audit.ResourceTypeIntegration, intg.ID().String()).
		WithResourceName(intg.Name()).
		WithMessage(fmt.Sprintf("Tenable.sc sync requested for integration '%s'", intg.Name())).
		WithMetadata("command_id", cmd.ID.String()).
		WithMetadata("sensor_id", sn.ID.String()).
		WithMetadata("mode", mode).
		WithMetadata("window_days", window).
		WithMetadata("trigger", trigger))
	return RequestResult{CommandID: cmd.ID, Mode: mode, Integration: intg}, nil
}

// SyncClaimer moves an integration's next_sync_at from the value read to a
// new one, only if nobody moved it since (compare-and-set), so two API
// replicas never queue the same scheduled sync.
type SyncClaimer interface {
	ClaimSyncDue(ctx context.Context, tenantID, id shared.ID, expected *time.Time, next time.Time) (bool, error)
}

// SetSyncClaimer wires the scheduled-sync claim. Without it, ScheduledSync
// does not claim (single-replica deployments and tests).
func (s *Service) SetSyncClaimer(c SyncClaimer) { s.claimer = c }

// SyncInterval is the integration's sync interval: its sync_interval_minutes,
// DefaultSyncIntervalMinutes when unset, never under MinSyncIntervalMinutes.
func SyncInterval(intg *integration.Integration) time.Duration {
	m := intg.SyncIntervalMinutes()
	if m <= 0 {
		m = DefaultSyncIntervalMinutes
	}
	return time.Duration(max(m, MinSyncIntervalMinutes)) * time.Minute
}

// ScheduledSync settles a finished sync and queues the next one when it is
// due. It returns true when it queued a sync. A connector that cannot sync
// (bad config, sensor unavailable) records why on the integration and is
// tried again at the next interval.
func (s *Service) ScheduledSync(ctx context.Context, intg *integration.Integration) (bool, error) {
	if !IsConnector(intg) || intg.Status() == integration.StatusDisabled {
		return false, nil
	}
	if _, err := s.reconcile(ctx, intg); err != nil {
		return false, err
	}
	if readState(intg).OpenCommandID != "" {
		return false, nil
	}
	now := s.now().UTC()
	expected := intg.NextSyncAt()
	if expected != nil && expected.After(now) {
		return false, nil
	}
	next := now.Add(SyncInterval(intg))
	if s.claimer != nil {
		ok, err := s.claimer.ClaimSyncDue(ctx, intg.TenantID(), intg.ID(), expected, next)
		if err != nil || !ok {
			return false, err
		}
	}
	intg.SetNextSyncAt(&next)
	if _, err := s.requestSync(ctx, intg, TriggerSchedule, nil); err != nil {
		var de *shared.DomainError
		if !errors.As(err, &de) {
			return false, err
		}
		// A refusal the owner can fix: show it, retry at the next interval.
		intg.RecordSyncFailure(capText(de.Message, maxSyncErrorLen))
		intg.SetNextSyncAt(&next)
		if uerr := s.integrations.Update(ctx, intg); uerr != nil {
			return false, uerr
		}
		return false, nil
	}
	return true, nil
}

// ValidateConnector checks a Tenable integration config before it is stored:
// a valid connector config whose sensor is one of the tenant's own sensors
// (read tenant-scoped, so another tenant's sensor id is not found), never a
// shared platform sensor. The sensor need not be online or report the
// connector yet: that is checked when a sync is requested.
func (s *Service) ValidateConnector(ctx context.Context, tenantID shared.ID, cfg map[string]any) error {
	cc, err := ParseConnectorConfigMap(cfg)
	if err != nil {
		return err
	}
	sn, err := s.sensors.GetByTenantAndID(ctx, tenantID, cc.SensorID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return invalid("sensor_id names no sensor of this organization")
		}
		return err
	}
	if sn.IsPlatformSensor || sn.TenantID == nil || *sn.TenantID != tenantID {
		return ErrPlatformSensor
	}
	return nil
}

// SensorRunsConnector reports whether a sensor can be given connector_sync
// commands now: active, and it reports the tenable_sc tool installed and
// allowed (the same tools command routing hands it work for).
func SensorRunsConnector(sn *sensordom.Sensor) bool {
	if sn == nil || sn.Status != sensordom.SensorStatusActive {
		return false
	}
	if sn.Reported.InstalledToolNames() == nil {
		return false // never reported: dispatch reads no tool from it
	}
	return slices.Contains(sn.EffectiveTools(), ToolName)
}

// syncWindow decides the mode and window of the next sync: full when there was
// no successful sync, when the last full sync is older than FullSyncDays, or
// when the gap exceeds MaxWindowDays; otherwise incremental over the days since
// the last successful sync plus one day of overlap (Tenable filters by whole
// days).
func syncWindow(state SyncState, cfg ConnectorConfig, now time.Time) (string, int) {
	if state.LastSuccessfulSync == nil || state.LastFullSync == nil {
		return ModeFull, 0
	}
	if now.Sub(*state.LastFullSync) >= time.Duration(cfg.FullSyncDays)*24*time.Hour {
		return ModeFull, 0
	}
	gap := now.Sub(*state.LastSuccessfulSync)
	if gap < 0 {
		gap = 0
	}
	days := int(math.Ceil(gap.Hours()/24)) + 1
	if days > MaxWindowDays {
		return ModeFull, 0
	}
	return ModeIncremental, max(days, 1)
}

// Reconcile settles the integration's open sync if it finished: on success it
// moves the cursor and records the counts; on failure it records the error.
// It returns true when it changed the integration.
func (s *Service) Reconcile(ctx context.Context, intg *integration.Integration) (bool, error) {
	return s.reconcile(ctx, intg)
}

func (s *Service) reconcile(ctx context.Context, intg *integration.Integration) (bool, error) {
	state := readState(intg)
	if state.OpenCommandID == "" {
		return false, nil
	}
	cmdID, err := shared.IDFromString(state.OpenCommandID)
	if err != nil {
		state.OpenCommandID, state.OpenMode, state.OpenRequestedAt = "", "", nil
		writeState(intg, state)
		return true, s.integrations.Update(ctx, intg)
	}
	cmd, err := s.commands.GetByTenantAndID(ctx, intg.TenantID(), cmdID)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			return false, err
		}
		return true, s.finish(ctx, intg, state, nil, "the sync command no longer exists")
	}
	switch cmd.Status {
	case command.CommandStatusPending, command.CommandStatusAcknowledged, command.CommandStatusRunning:
		return false, nil
	case command.CommandStatusCompleted:
		done, failure, err := s.reportsSettled(ctx, intg.TenantID(), cmd.ID)
		if err != nil {
			return false, err
		}
		if !done {
			return false, nil // reports still being ingested: decide later
		}
		if failure != "" {
			return true, s.finish(ctx, intg, state, cmd, failure)
		}
		return true, s.finish(ctx, intg, state, cmd, "")
	default: // failed, canceled, expired
		reason := strings.TrimSpace(cmd.ErrorMessage)
		if reason == "" {
			reason = "the sync command " + string(cmd.Status)
		}
		return true, s.finish(ctx, intg, state, cmd, reason)
	}
}

// reportsSettled reports whether every v2 report filed under the command is
// in a final state, and the failure when one did not complete. A sync whose
// reports were pushed over protocol v1 has none here: v1 ingest finishes
// before the sensor completes the command.
func (s *Service) reportsSettled(ctx context.Context, tenantID, commandID shared.ID) (bool, string, error) {
	if s.reports == nil {
		return true, "", nil
	}
	cov, err := s.reports.CommandCoverage(ctx, tenantID, commandID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return true, "", nil
		}
		return false, "", err
	}
	for _, r := range cov.Reports {
		switch r.State {
		case protov2.StateCompleted:
		case protov2.StateFailed, protov2.StateExpired:
			return true, fmt.Sprintf("a report of the sync was not ingested (%s)", r.State), nil
		default:
			return false, "", nil
		}
		if !strings.EqualFold(strings.TrimSpace(r.ToolName), ToolName) {
			return true, "a report of the sync names another tool", nil
		}
	}
	return true, "", nil
}

// finish records a finished sync. failure "" means success.
func (s *Service) finish(ctx context.Context, intg *integration.Integration, state SyncState, cmd *command.Command, failure string) error {
	now := s.now().UTC()
	mode := state.OpenMode
	if cmd != nil {
		state.LastCommandID = cmd.ID.String()
	}
	state.OpenCommandID, state.OpenMode = "", ""
	requestedAt := state.OpenRequestedAt
	state.OpenRequestedAt = nil

	if failure == "" {
		res := parseSyncResult(cmd)
		// The window the sync covered ends when it started reading: the
		// command's start, else its creation. Never later than now.
		mark := now
		if cmd != nil {
			switch {
			case cmd.StartedAt != nil:
				mark = cmd.StartedAt.UTC()
			case requestedAt != nil:
				mark = requestedAt.UTC()
			default:
				mark = cmd.CreatedAt.UTC()
			}
		}
		if mark.After(now) {
			mark = now
		}
		state.LastSuccessfulSync = &mark
		if mode == ModeFull {
			state.LastFullSync = &mark
		}
		state.LastOutcome = OutcomeCompleted
		state.TenableVersion = res.Version
		state.LicensedIPs, state.ActiveIPs = res.LicensedIPs, res.ActiveIPs
		state.Hosts, state.OpenVulns, state.MitigatedVulns, state.Plugins = res.Hosts, res.Open, res.Mitigated, res.Plugins
		if res.Catalog != nil {
			state.Catalog = res.Catalog
		}
		writeState(intg, state)
		stats := intg.Stats()
		stats.TotalAssets, stats.TotalFindings = res.Hosts, res.Open
		intg.SetStats(stats)
		if intg.Status() != integration.StatusDisabled {
			intg.SetConnected()
		}
		intg.RecordSyncSuccess()
	} else {
		state.LastOutcome = OutcomeFailed
		writeState(intg, state)
		intg.RecordSyncFailure(capText(failure, maxSyncErrorLen))
		// Retry sooner than a long interval, never in a tight loop.
		retry := now.Add(failureRetry)
		if next := intg.NextSyncAt(); next == nil || next.After(retry) {
			intg.SetNextSyncAt(&retry)
		}
	}
	if err := s.integrations.Update(ctx, intg); err != nil {
		return fmt.Errorf("record connector_sync outcome: %w", err)
	}
	if failure != "" {
		s.logger.Warn("tenable.sc sync failed", "tenant_id", intg.TenantID().String(),
			"integration_id", intg.ID().String(), "reason", capText(failure, maxSyncErrorLen))
	}
	return nil
}

// syncResult is what the sensor reported on completion (untrusted; only
// counts and the Tenable version are read, clamped).
type syncResult struct {
	Version                         string
	LicensedIPs, ActiveIPs          int
	Hosts, Open, Mitigated, Plugins int
	Catalog                         *Catalog
}

func parseSyncResult(cmd *command.Command) syncResult {
	var out syncResult
	if cmd == nil || len(cmd.Result) == 0 {
		return out
	}
	var r struct {
		Metadata map[string]any `json:"metadata"`
	}
	if json.Unmarshal(cmd.Result, &r) != nil || r.Metadata == nil {
		return out
	}
	m := r.Metadata
	out.Version = capText(stringValue(m["tenable_version"]), 32)
	out.LicensedIPs = clampCount(m["licensed_ips"])
	out.ActiveIPs = clampCount(m["active_ips"])
	out.Hosts = clampCount(m["hosts"])
	out.Open = clampCount(m["open"])
	out.Mitigated = clampCount(m["mitigated"])
	out.Plugins = clampCount(m["plugins"])
	out.Catalog = parseCatalog(m["catalog"])
	return out
}

const maxCount = 100_000_000

func clampCount(v any) int {
	n, ok, err := intValue(v)
	if err != nil || !ok || n < 0 {
		return 0
	}
	return min(n, maxCount)
}

// capText keeps at most n bytes of s, on a rune boundary, without control
// characters.
func capText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// readState decodes the sync state from the integration metadata.
func readState(intg *integration.Integration) SyncState {
	var st SyncState
	raw, ok := intg.Metadata()[metadataKey]
	if !ok || raw == nil {
		return st
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	return st
}

// writeState stores the sync state in the integration metadata, keeping the
// other keys.
func writeState(intg *integration.Integration, st SyncState) {
	md := map[string]any{}
	for k, v := range intg.Metadata() {
		md[k] = v
	}
	b, _ := json.Marshal(st)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	md[metadataKey] = m
	intg.SetMetadata(md)
}

// State returns the connector's sync state of an integration.
func State(intg *integration.Integration) SyncState { return readState(intg) }

func (s *Service) logAudit(ctx context.Context, actx *auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil || actx == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, *actx, event); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Warn("connector audit event not recorded", "error", err)
	}
}
