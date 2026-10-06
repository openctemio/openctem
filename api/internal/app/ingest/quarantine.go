package ingest

// Unsolicited sensor results (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.3, owner decision Q6 (a)): the gate every sensor report without a
// command passes, the quarantine it may land in, and the review of what is
// there.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/ctis"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// CodeResultsQuarantined is the error code of a report held for review.
const CodeResultsQuarantined = "RESULTS_QUARANTINED"

// CodeCommandNotFound is the error code of a report that names a command
// that is not assigned to the sensor, or not open.
const CodeCommandNotFound = "COMMAND_NOT_FOUND"

// CodeToolNotPermitted is the error code of a bound report whose tool is not
// the command's tool.
const CodeToolNotPermitted = "TOOL_NOT_PERMITTED"

// ErrCommandNotFound: the named command is not assigned to this sensor, or
// is not open. Deliberately the same for every case, so a sensor learns
// nothing about other sensors' commands.
var ErrCommandNotFound = shared.NewDomainError(CodeCommandNotFound,
	"no open command with this id is assigned to this sensor", shared.ErrNotFound)

// ErrToolNotPermitted: a bound report's tool is not the command's tool.
var ErrToolNotPermitted = shared.NewDomainError(CodeToolNotPermitted,
	"the report's tool is not the tool of the command it names", shared.ErrValidation)

// CodePushIngestNotGranted is the error code of a report without a command
// from a sensor whose grant does not allow push ingest (RFC-052 §5.3).
const CodePushIngestNotGranted = "PUSH_INGEST_NOT_GRANTED"

// ErrPushIngestNotGranted: the report names no command and the sensor's
// effective grant does not allow results without a job (push ingest is off
// by default, and always off while the sensor is New). The report is
// refused, not quarantined.
var ErrPushIngestNotGranted = shared.NewDomainError(CodePushIngestNotGranted,
	"this sensor's grant does not allow results without a job assigned to it; the report was refused", shared.ErrForbidden)

// GrantReader reads a sensor's grant (RFC-052 §5).
type GrantReader interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensor.Grant, error)
}

// PushRefusalObserver is told about results without a job that a grant
// refused (timeline and audit). Satisfied by the sensor service.
type PushRefusalObserver interface {
	ObservePushRefusal(ctx context.Context, tenantID, sensorID shared.ID, route string)
}

// SetGrants makes the unsolicited gate check the sensor's grant first:
// without push ingest in the effective grant, a report that names no
// command is refused before the role and the tenant policy are consulted.
func (s *Service) SetGrants(g GrantReader, o PushRefusalObserver) { s.grants, s.pushRefusals = g, o }

// QuarantinedError is returned for a report that was stored for review and
// not applied.
type QuarantinedError struct {
	ID shared.ID
}

func (e *QuarantinedError) Error() string {
	return "results quarantined: this sensor's role may not send results without a command assigned to it; " +
		"the report was stored for review and not applied"
}

// commandReader is the slice of the command repository result binding needs.
type commandReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*command.Command, error)
}

// SetCommandReader wires the command store used to bind reports to commands.
func (s *Service) SetCommandReader(r commandReader) { s.commands = r }

// SetResultQuarantine wires the policy and quarantine store. Without it every
// tenant behaves as in "warn" mode.
func (s *Service) SetResultQuarantine(repo sensorresult.Repository, limits sensorresult.Limits) {
	s.results = repo
	s.resultLimits = limits
}

// ResultPolicy returns the tenant's policy for unsolicited results. Without a
// store it is "warn", so nothing is ever quarantined where it cannot be kept.
func (s *Service) ResultPolicy(ctx context.Context, tenantID shared.ID) sensorresult.Policy {
	if s.results == nil {
		return sensorresult.Policy{TenantID: tenantID, Mode: sensorresult.ModeWarn}
	}
	p, err := s.results.GetPolicy(ctx, tenantID)
	if err != nil {
		// Fail toward the stricter behavior the tenant would get by default.
		s.logger.Warn("could not read the sensor result policy; using the default", "tenant_id", tenantID.String(), "error", err)
		return sensorresult.DefaultPolicy(tenantID)
	}
	return p
}

// OpenCommand returns the command a sensor's report names when it is assigned
// to that sensor and open: claimed and not finished, or finished less than
// protov2.CommandGraceAfterFinish ago (RFC-023 C-8). Anything else, including
// a command of another sensor, is ErrCommandNotFound.
func OpenCommand(ctx context.Context, commands commandReader, agt *sensor.Sensor, commandID string, now time.Time) (*command.Command, error) {
	if commands == nil || agt == nil || agt.TenantID == nil {
		return nil, ErrCommandNotFound
	}
	id, err := shared.IDFromString(commandID)
	if err != nil {
		return nil, ErrCommandNotFound
	}
	tenantID := *agt.TenantID
	cmd, err := commands.GetByTenantAndID(ctx, tenantID, id)
	if err != nil || cmd == nil || cmd.TenantID != tenantID || cmd.SensorID == nil || *cmd.SensorID != agt.ID {
		return nil, ErrCommandNotFound
	}
	switch cmd.Status {
	case command.CommandStatusAcknowledged, command.CommandStatusRunning:
		return cmd, nil
	case command.CommandStatusCompleted, command.CommandStatusFailed:
		if cmd.CompletedAt != nil && now.Sub(*cmd.CompletedAt) <= protov2.CommandGraceAfterFinish {
			return cmd, nil
		}
	}
	return nil, ErrCommandNotFound
}

// bindingFromCommandID rebuilds the binding of a report the accept side bound
// to a command (v2 segments are processed later, the command may have
// finished since). A command that cannot be read keeps the binding but with
// no targets: the report then changes no existing asset.
func (s *Service) bindingFromCommandID(ctx context.Context, tenantID shared.ID, id *shared.ID) Binding {
	if id == nil {
		return Binding{}
	}
	cid := *id
	b := Binding{Kind: BindingCommand, CommandID: &cid}
	if s.commands != nil {
		if cmd, err := s.commands.GetByTenantAndID(ctx, tenantID, cid); err == nil && cmd != nil {
			b.Targets = CommandTargets(cmd)
			b.Tool = commandTool(cmd)
			b.StepRunID = cmd.StepRunID
		}
	}
	return b
}

// sensorTypeOf is the sensor's role: from the authenticated sensor, or its
// stored row when the caller built a minimal one (the async worker).
func (s *Service) sensorTypeOf(ctx context.Context, agt *sensor.Sensor) sensor.SensorType {
	if agt.Type != "" || s.sensorRepo == nil || agt.ID.IsZero() {
		return agt.Type
	}
	if stored, err := s.sensorRepo.GetByID(ctx, agt.ID); err == nil && stored != nil {
		return stored.Type
	}
	return agt.Type
}

// unsolicitedSubmission is a report that named no command, as it arrived.
type unsolicitedSubmission struct {
	Protocol sensorresult.Protocol
	Route    string
	ReportID string
	Segment  *int
	Report   *ctis.Report
}

// admitUnsolicited is the gate for a sensor report that names no command. A
// collector or CI runner, and any sensor of a tenant in "warn" mode, may
// proceed (warned says it was the latter). Otherwise the report is stored in
// the quarantine and a *QuarantinedError is returned (sensorresult.ErrFull
// when the quarantine is full: the report is refused).
func (s *Service) admitUnsolicited(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID, sub unsolicitedSubmission) (warned bool, err error) {
	if err := s.admitPush(ctx, agt.ID, tenantID, sub.Route); err != nil {
		return false, err
	}
	sensorType := s.sensorTypeOf(ctx, agt)
	if RoleMayPushUnsolicited(sensorType) {
		metrics.SensorUnsolicitedResultsTotal.WithLabelValues("applied").Inc()
		return false, nil
	}
	if s.ResultPolicy(ctx, tenantID).Mode == sensorresult.ModeWarn {
		metrics.SensorUnsolicitedResultsTotal.WithLabelValues("warned").Inc()
		s.logger.Warn("unsolicited sensor report applied (tenant mode warn; quarantine mode would hold it for review)",
			"sensor_id", agt.ID.String(), "sensor_type", string(sensorType), "tenant_id", tenantID.String(),
			"route", sub.Route, "report_id", sanitizeIngestLogField(sub.ReportID))
		return true, nil
	}

	payload, err := json.Marshal(sub.Report)
	if err != nil {
		return false, fmt.Errorf("encode quarantined report: %w", err)
	}
	item := &sensorresult.Item{
		TenantID:   tenantID,
		SensorID:   agt.ID,
		SensorType: string(sensorType),
		Protocol:   sub.Protocol,
		Route:      sub.Route,
		ReportID:   sub.ReportID,
		Segment:    sub.Segment,
		Reason:     sensorresult.ReasonNoCommand,
		Payload:    payload,
	}
	if sub.Report != nil {
		item.AssetsCount = len(sub.Report.Assets)
		item.FindingsCount = len(sub.Report.Findings)
		if sub.Report.Tool != nil {
			item.ToolName = sub.Report.Tool.Name
		}
		if item.ReportID == "" {
			item.ReportID = sub.Report.Metadata.ID
		}
	}
	if err := s.results.Create(ctx, item, s.resultLimits); err != nil {
		if errors.Is(err, sensorresult.ErrFull) {
			metrics.SensorUnsolicitedResultsTotal.WithLabelValues("refused").Inc()
			s.logger.Warn("unsolicited sensor report refused: the results quarantine is full",
				"sensor_id", agt.ID.String(), "tenant_id", tenantID.String(), "route", sub.Route)
		}
		return false, err
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("quarantined").Inc()
	s.logger.Info("unsolicited sensor report quarantined",
		"sensor_id", agt.ID.String(), "sensor_type", string(sensorType), "tenant_id", tenantID.String(),
		"route", sub.Route, "quarantine_id", item.ID.String(),
		"assets", item.AssetsCount, "findings", item.FindingsCount)
	s.auditAsync(auditapp.AuditContext{TenantID: tenantID.String()},
		auditapp.NewSuccessEvent(audit.ActionSensorResultsQuarantined, audit.ResourceTypeSensor, agt.ID.String()).
			WithResourceName(agt.Name).
			WithMessage("Sensor report without a command quarantined for review").
			WithSeverity(audit.SeverityMedium).
			WithMetadata("quarantine_id", item.ID.String()).
			WithMetadata("sensor_type", string(sensorType)).
			WithMetadata("route", sub.Route).
			WithMetadata("report_id", item.ReportID).
			WithMetadata("tool_name", item.ToolName).
			WithMetadata("assets_count", item.AssetsCount).
			WithMetadata("findings_count", item.FindingsCount))
	return false, &QuarantinedError{ID: item.ID}
}

// auditAsync writes a tenant audit event off the request path (see
// createIngestAuditLog for why it is detached and capped).
func (s *Service) auditAsync(actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.auditSvc == nil && s.auditRepo == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.writeIngestAuditLog(ctx, actx, event); err != nil {
			s.logger.Warn("failed to persist audit log", "action", event.Action.String(), "error", err)
		}
	}()
}

// recordWithheld counts the changes an ingest was not allowed to make.
func recordWithheld(out *Output) {
	if out.AssetsLimited > 0 {
		metrics.SensorResultChangesWithheldTotal.WithLabelValues("asset").Add(float64(out.AssetsLimited))
	}
	if out.ReopensWithheld > 0 {
		metrics.SensorResultChangesWithheldTotal.WithLabelValues("reopen").Add(float64(out.ReopensWithheld))
	}
}

// =============================================================================
// Review
// =============================================================================

// ErrQuarantineUnavailable: the quarantine store is not wired.
var ErrQuarantineUnavailable = errors.New("the results quarantine is not configured")

// ListQuarantined returns a page of the tenant's quarantined reports.
func (s *Service) ListQuarantined(ctx context.Context, tenantID shared.ID, f sensorresult.ListFilter) ([]sensorresult.Item, int, error) {
	if s.results == nil {
		return nil, 0, ErrQuarantineUnavailable
	}
	return s.results.List(ctx, tenantID, f)
}

// GetQuarantined returns one quarantined report with its payload.
func (s *Service) GetQuarantined(ctx context.Context, tenantID, id shared.ID) (*sensorresult.Item, error) {
	if s.results == nil {
		return nil, ErrQuarantineUnavailable
	}
	return s.results.Get(ctx, tenantID, id)
}

// AcceptQuarantined applies a quarantined report as a person's decision: it
// may change the existing assets it names and reopen findings, like a report
// bound to a command, but it never auto-resolves anything (no command says
// what was covered). The item is marked accepted first, so two concurrent
// accepts apply it once.
func (s *Service) AcceptQuarantined(ctx context.Context, actx auditapp.AuditContext, tenantID, id, by shared.ID) (*Output, error) {
	if s.results == nil {
		return nil, ErrQuarantineUnavailable
	}
	item, err := s.results.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if item.Status != sensorresult.StatusPending {
		return nil, sensorresult.ErrAlreadyReviewed
	}
	var report ctis.Report
	if err := json.Unmarshal(item.Payload, &report); err != nil {
		return nil, fmt.Errorf("%w: the stored report does not parse: %v", shared.ErrValidation, err) //nolint:errorlint // detail
	}
	if err := s.results.Review(ctx, tenantID, id, sensorresult.StatusAccepted, by); err != nil {
		return nil, err
	}

	opts := Options{Binding: TrustedBinding(), Admitted: true, DeferAutoResolve: true, DeferSensorStats: true}
	if item.Protocol == sensorresult.ProtocolV2 {
		opts.RequireAssetForFindings = true
		opts.NoCatalogWrites = true
	}
	agt := &sensor.Sensor{ID: item.SensorID, TenantID: &tenantID, Type: sensor.SensorType(item.SensorType), Status: sensor.SensorStatusActive}
	out, ingErr := s.Ingest(ctx, agt, Input{Report: &report, Options: opts})

	result := map[string]any{}
	if out != nil {
		result = map[string]any{
			"assets_created": out.AssetsCreated, "assets_updated": out.AssetsUpdated,
			"findings_created": out.FindingsCreated, "findings_updated": out.FindingsUpdated,
			"findings_auto_reopened": out.FindingsAutoReopened, "errors": len(out.Errors),
		}
	}
	if ingErr != nil {
		result["error"] = ingErr.Error()
	}
	if raw, err := json.Marshal(result); err == nil {
		if err := s.results.SetResult(ctx, tenantID, id, raw); err != nil {
			s.logger.Warn("could not store the result of an accepted report", "quarantine_id", id.String(), "error", err)
		}
	}

	event := auditapp.NewSuccessEvent(audit.ActionSensorResultsAccepted, audit.ResourceTypeSensor, item.SensorID.String()).
		WithResourceName(item.SensorName).
		WithMessage("Quarantined sensor report accepted and applied").
		WithMetadata("quarantine_id", id.String()).
		WithMetadata("report_id", item.ReportID).
		WithMetadata("tool_name", item.ToolName).
		WithMetadata("result", result)
	if ingErr != nil {
		event = auditapp.NewFailureEvent(audit.ActionSensorResultsAccepted, audit.ResourceTypeSensor, item.SensorID.String(), ingErr).
			WithMetadata("quarantine_id", id.String())
	}
	actx.TenantID = tenantID.String()
	s.auditAsync(actx, event)
	if ingErr != nil {
		return nil, ingErr
	}
	return out, nil
}

// DiscardQuarantined drops a quarantined report without applying it.
func (s *Service) DiscardQuarantined(ctx context.Context, actx auditapp.AuditContext, tenantID, id, by shared.ID) error {
	if s.results == nil {
		return ErrQuarantineUnavailable
	}
	item, err := s.results.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.results.Review(ctx, tenantID, id, sensorresult.StatusDiscarded, by); err != nil {
		return err
	}
	actx.TenantID = tenantID.String()
	s.auditAsync(actx, auditapp.NewSuccessEvent(audit.ActionSensorResultsDiscarded, audit.ResourceTypeSensor, item.SensorID.String()).
		WithResourceName(item.SensorName).
		WithMessage("Quarantined sensor report discarded").
		WithMetadata("quarantine_id", id.String()).
		WithMetadata("report_id", item.ReportID).
		WithMetadata("tool_name", item.ToolName))
	return nil
}

// UpdateResultPolicy replaces the tenant's policy for unsolicited results and
// audits the change.
func (s *Service) UpdateResultPolicy(ctx context.Context, actx auditapp.AuditContext, tenantID shared.ID, mode sensorresult.Mode, allowAdvisory bool, by shared.ID) (sensorresult.Policy, error) {
	if s.results == nil {
		return sensorresult.Policy{}, ErrQuarantineUnavailable
	}
	if _, err := sensorresult.ParseMode(string(mode)); err != nil {
		return sensorresult.Policy{}, err
	}
	before := s.ResultPolicy(ctx, tenantID)
	p := sensorresult.Policy{TenantID: tenantID, Mode: mode, AllowAdvisoryEvidence: allowAdvisory, UpdatedBy: &by}
	if err := s.results.SavePolicy(ctx, &p); err != nil {
		return sensorresult.Policy{}, err
	}
	actx.TenantID = tenantID.String()
	s.auditAsync(actx, auditapp.NewSuccessEvent(audit.ActionSensorResultPolicyUpdated, audit.ResourceTypeSettings, "sensor-result-policy").
		WithMessage("Policy for sensor results without a command updated").
		WithMetadata("mode_before", string(before.Mode)).
		WithMetadata("mode_after", string(p.Mode)).
		WithMetadata("allow_advisory_evidence_before", before.AllowAdvisoryEvidence).
		WithMetadata("allow_advisory_evidence_after", p.AllowAdvisoryEvidence))
	return p, nil
}

// admitV2Segment runs the unsolicited gate for one segment of a v2 report
// that names no command. held is true when the segment was not applied: its
// outcome counts every item as quarantined (stored for review) or, when the
// quarantine is full, rejected.
func (s *Service) admitV2Segment(ctx context.Context, prov Provenance, report *ctis.Report) (ingestreport.SegmentOutcome, bool, error) {
	agt := &sensor.Sensor{ID: prov.SensorID, TenantID: &prov.TenantID, Type: sensor.SensorType(prov.SensorType), Status: sensor.SensorStatusActive}
	seq := prov.SegmentSeq
	_, err := s.admitUnsolicited(ctx, agt, prov.TenantID, unsolicitedSubmission{
		Protocol: sensorresult.ProtocolV2, Route: "v2", ReportID: prov.ReportID, Segment: &seq, Report: report,
	})
	var qe *QuarantinedError
	switch {
	case err == nil:
		return ingestreport.SegmentOutcome{}, false, nil
	case errors.As(err, &qe):
		return ingestreport.SegmentOutcome{
			QuarantinedAssets: len(report.Assets), QuarantinedFindings: len(report.Findings),
			Errors: []protov2.ItemError{{Segment: &seq, Pointer: "", Code: protov2.CodeQuarantinedNoCommand, Detail: protov2.DetailQuarantined}},
		}, true, nil
	case errors.Is(err, sensorresult.ErrFull):
		return ingestreport.SegmentOutcome{
			RejectedAssets: len(report.Assets), RejectedFindings: len(report.Findings),
			Errors: []protov2.ItemError{{Segment: &seq, Pointer: "", Code: protov2.CodeQuarantineFull, Detail: protov2.DetailQuarantineFull}},
		}, true, nil
	case errors.Is(err, ErrPushIngestNotGranted):
		return ingestreport.SegmentOutcome{
			RejectedAssets: len(report.Assets), RejectedFindings: len(report.Findings),
			Errors: []protov2.ItemError{{Segment: &seq, Pointer: "", Code: protov2.CodePushIngestNotGranted, Detail: protov2.DetailPushIngestNotGranted}},
		}, true, nil
	default:
		return ingestreport.SegmentOutcome{}, false, err
	}
}

// AdmitQueued runs the unsolicited gate for a v1 report the accept side is
// about to queue (INGEST_MODE=async): nil lets it be queued, a
// *QuarantinedError means it was stored for review instead, and
// sensorresult.ErrFull that it was refused.
func (s *Service) AdmitQueued(ctx context.Context, agt *sensor.Sensor, report *ctis.Report) error {
	if err := s.validateSensor(agt); err != nil {
		return err
	}
	_, err := s.admitUnsolicited(ctx, agt, *agt.TenantID, unsolicitedSubmission{
		Protocol: sensorresult.ProtocolV1, Route: "ctis", ReportID: report.Metadata.ID, Report: report,
	})
	return err
}

// admitPush is the grant's half of the unsolicited gate: nil when the
// sensor's effective grant allows results without a job (or grants are not
// wired). A sensor without a grant row, which the schema does not allow, is
// refused too (fail closed); a read error is returned as is.
func (s *Service) admitPush(ctx context.Context, sensorID, tenantID shared.ID, route string) error {
	if s.grants == nil {
		return nil
	}
	g, err := s.grants.Get(ctx, tenantID, sensorID)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return fmt.Errorf("read sensor grant: %w", err)
	}
	if g != nil && g.Effective().AllowPushIngest {
		return nil
	}
	metrics.SensorUnsolicitedResultsTotal.WithLabelValues("refused_grant").Inc()
	if s.pushRefusals != nil {
		s.pushRefusals.ObservePushRefusal(ctx, tenantID, sensorID, route)
	}
	return ErrPushIngestNotGranted
}
