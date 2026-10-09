// Package command implements the application service for the command bounded context — orchestrates pkg/domain/command entities and cross-cutting concerns (audit, notifications, RBAC).
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/metrics"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Service handles command-related business operations.
type Service struct {
	repo      commanddom.Repository
	sensors   SensorLookup
	templates TemplateSigner
	// jobs signs every claimed command (job_signing.go); nil: claims
	// carry no signed job.
	jobs   JobSigner
	logger *logger.Logger
	// refusals hears about failed commands (local_policy.go); nil: none.
	refusals RefusalObserver
	// privatePolicy keeps private targets from sensors without a local
	// policy when the tenant asks (local_policy.go); nil: never.
	privatePolicy PrivateTargetPolicy
	// optIns withholds commands asking for an opt-in the tenant has not
	// enabled (local_policy.go, research/25 D3); nil: not applied.
	optIns OptInPolicy
	// grants enforces each sensor's grant (local_policy.go, RFC-052 §5);
	// nil: not enforced. grantRefusals hears about refused claims by id.
	grants GrantReader
	// contracts are the sensors' manifests, whose tool contracts set each
	// job's tier (local_policy.go, RFC-055).
	contracts     ToolContractSource
	grantRefusals GrantRefusalObserver
	// scopeGate re-checks the targets of every command a sensor gets
	// (scope_recheck.go); nil: not re-checked. failures hears about a
	// command the re-check failed.
	scopeGate ScopeGate
	failures  FailureObserver
	// now is the clock (tests replace it).
	now func() time.Time
	// httpPolicy is the tenant's tool HTTP layer (WithHTTPPolicy).
	httpPolicy HTTPPolicySource
}

// TemplateSigner signs the custom templates embedded in a command payload
// for the command's tenant, the sensor that polled it and the command, as
// the command leaves for that sensor (template.PayloadSigner).
type TemplateSigner interface {
	SignTemplates(tenantID, sensorID, commandID string, payload json.RawMessage) json.RawMessage
}

// WithTemplateSigner makes Poll sign the custom templates of every command
// it hands a sensor. Without it they go unsigned and sensors refuse them.
func WithTemplateSigner(t TemplateSigner) Option {
	return func(s *Service) { s.templates = t }
}

// HTTPPolicySource returns a tenant's tool HTTP layer (RFC-060 §4.1).
// Satisfied by the tenant service.
type HTTPPolicySource interface {
	ToolHTTPPolicy(ctx context.Context, tenantID shared.ID) (sensordom.ToolHTTPPolicy, error)
}

// WithHTTPPolicy makes Poll and Claim put the tenant's tool HTTP layer in
// every scan command they hand a sensor ("http_policy"), as it is at
// delivery: a queued job gets the policy in force when it leaves.
func WithHTTPPolicy(p HTTPPolicySource) Option {
	return func(s *Service) { s.httpPolicy = p }
}

// SensorLookup resolves a sensor inside one tenant. Satisfied by the sensor
// repository.
type SensorLookup interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error)
}

// Option configures a Service.
type Option func(*Service)

// WithSensorLookup makes Create check that a command's sensor belongs to the
// command's tenant.
func WithSensorLookup(l SensorLookup) Option {
	return func(s *Service) { s.sensors = l }
}

// NewService creates a new Service.
func NewService(repo commanddom.Repository, log *logger.Logger, opts ...Option) *Service {
	s := &Service{
		repo:   repo,
		logger: log.With("service", "command"),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CreateInput represents the input for creating a command.
type CreateInput struct {
	TenantID  string          `json:"tenant_id" validate:"required,uuid"`
	SensorID  string          `json:"sensor_id,omitempty" validate:"omitempty,uuid"`
	Type      string          `json:"type" validate:"required,oneof=scan collect health_check config_update cancel"`
	Priority  string          `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ExpiresIn int             `json:"expires_in,omitempty"` // Seconds until expiration
	// ScanZoneID restricts the command to one scan zone's sensors. Set by
	// the caller after it routed the command's targets (scan commands
	// from POST /api/v1/commands go through scan.Service.GateCommandPayload).
	ScanZoneID *shared.ID `json:"-"`
	// DispatchGate is what the caller gated the targets with; the claim
	// re-checks them with it (scope_recheck.go). Server-side only.
	DispatchGate *commanddom.DispatchGate `json:"-"`
}

// Create creates a new command.
func (s *Service) Create(ctx context.Context, input CreateInput) (*commanddom.Command, error) {
	s.logger.Info("creating command", "type", input.Type, "priority", input.Priority)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cmdType := commanddom.CommandType(input.Type)
	priority := commanddom.CommandPriority(input.Priority)
	if priority == "" {
		priority = commanddom.CommandPriorityNormal
	}

	cmd, err := commanddom.NewCommand(tenantID, cmdType, priority, input.Payload)
	if err != nil {
		return nil, err
	}

	if input.SensorID != "" {
		sensorID, err := shared.IDFromString(input.SensorID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
		}
		// The sensor must belong to this tenant. Without the check a command
		// could be pinned to another tenant's sensor (stored, never claimable),
		// and an unknown id failed on the foreign key with a 500 — together an
		// oracle for which sensor ids exist in other tenants.
		if s.sensors != nil {
			if _, err := s.sensors.GetByTenantAndID(ctx, tenantID, sensorID); err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					return nil, shared.NewDomainError("SENSOR_NOT_FOUND", "sensor_id: no such sensor in this tenant", shared.ErrValidation)
				}
				return nil, fmt.Errorf("look up sensor: %w", err)
			}
		}
		cmd.SetSensorID(sensorID)
	}
	if input.ScanZoneID != nil && !input.ScanZoneID.IsZero() {
		cmd.SetScanZone(*input.ScanZoneID)
	}
	cmd.DispatchGate = input.DispatchGate

	if input.ExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(input.ExpiresIn) * time.Second)
		cmd.SetExpiration(expiresAt)
	}

	if err := s.repo.Create(ctx, cmd); err != nil {
		return nil, err
	}

	return cmd, nil
}

// Get retrieves a command by ID.
func (s *Service) Get(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cid, err := shared.IDFromString(commandID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid command id", shared.ErrValidation)
	}

	return s.repo.GetByTenantAndID(ctx, tid, cid)
}

// ListInput represents the input for listing commands.
type ListInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	SensorID string `json:"sensor_id,omitempty" validate:"omitempty,uuid"`
	Type     string `json:"type" validate:"omitempty,oneof=scan collect health_check config_update cancel"`
	Status   string `json:"status" validate:"omitempty,oneof=pending acknowledged running completed failed canceled expired"`
	Priority string `json:"priority" validate:"omitempty,oneof=low normal high critical"`
	Page     int    `json:"page"`
	PerPage  int    `json:"per_page"`
}

// List lists commands with filters.
func (s *Service) List(ctx context.Context, input ListInput) (pagination.Result[*commanddom.Command], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*commanddom.Command]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := commanddom.Filter{
		TenantID: &tenantID,
	}

	if input.SensorID != "" {
		sensorID, err := shared.IDFromString(input.SensorID)
		if err != nil {
			return pagination.Result[*commanddom.Command]{}, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
		}
		filter.SensorID = &sensorID
	}

	if input.Type != "" {
		t := commanddom.CommandType(input.Type)
		filter.Type = &t
	}

	if input.Status != "" {
		st := commanddom.CommandStatus(input.Status)
		filter.Status = &st
	}

	if input.Priority != "" {
		p := commanddom.CommandPriority(input.Priority)
		filter.Priority = &p
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, page)
}

// PollInput represents the input for polling commands.
type PollInput struct {
	TenantID string `json:"tenant_id" validate:"required,uuid"`
	SensorID string `json:"sensor_id,omitempty" validate:"omitempty,uuid"`
	// Capabilities is the polling sensor's advertised capability set. It gates
	// which capability-scoped commands the sensor may claim (see
	// command.Repository.GetPendingForSensor). Empty = only unscoped commands.
	Capabilities []string `json:"capabilities,omitempty"`
	Limit        int      `json:"limit" validate:"min=1,max=100"`
	// MaxScanCommands caps how many scan commands the poll returns: the
	// sensor's free slots (sensor.FreeSlots), so a sensor is never offered
	// more scans than it can run — an SDK that claims everything it polls
	// cannot pile up acknowledged commands for the reaper to re-dispatch
	// (RFC-030 B6, D5). Other commands (validate, collect, config) are not
	// capped. nil: no cap.
	MaxScanCommands *int `json:"-"`
}

// Poll retrieves pending commands for a sensor.
func (s *Service) Poll(ctx context.Context, input PollInput) ([]*commanddom.Command, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	var sensorID *shared.ID
	if input.SensorID != "" {
		aid, err := shared.IDFromString(input.SensorID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
		}
		sensorID = &aid
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	cmds, err := s.repo.GetPendingForSensor(ctx, tenantID, sensorID, input.Capabilities, candidateLimit(limit))
	if err != nil {
		return nil, err
	}
	// A sensor never gets a command its reported local policy refuses, nor
	// one with private targets when the tenant requires a local policy for
	// them (RFC-040 §5.7, research/25 §3.6): those stay pending for a
	// sensor that accepts them.
	cmds = s.gateFor(ctx, tenantID, sensorID, cmds).accepted(cmds)
	if len(cmds) > limit {
		cmds = cmds[:limit]
	}
	if input.MaxScanCommands != nil {
		cmds = capScanCommands(cmds, *input.MaxScanCommands)
	}
	// Scope may have changed since the jobs were queued (scope_recheck.go).
	cmds = s.recheckScope(ctx, tenantID, sensorID, cmds)
	return s.deliver(ctx, input.SensorID, cmds)
}

// ClaimInput is a claim-N poll: the sensor takes its work in one request.
type ClaimInput struct {
	TenantID     string
	SensorID     string
	Capabilities []string
	// Limit caps the commands returned (1..100, default 10).
	Limit int
	// MaxJobs is the sensor's effective job limit; the scan commands
	// claimed never exceed MaxJobs minus the scans it already holds, counted
	// from the commands themselves rather than from its last heartbeat.
	MaxJobs int
	// ReportedFree, when set, is the free slots the sensor last reported;
	// the claim takes the smaller of the two.
	ReportedFree *int
}

// Claim is the claim-N poll (RFC-046 §11, RFC-030 §5.3): it selects what the
// sensor may run in the fair dispatch order (priority class with aging,
// round-robin across runs), withholds what the sensor's reported local
// policy refuses (and private targets from a sensor without one), caps scans at the sensor's free slots, and claims the lot in
// one statement. The commands returned are already acknowledged to the
// sensor with a lease; its later claim of each is a replay. Commands another
// sensor took in the meantime are simply not returned.
//
// Falls back to Poll (nothing claimed) when the repository cannot claim in
// batch.
func (s *Service) Claim(ctx context.Context, input ClaimInput) ([]*commanddom.Command, error) {
	claimer, ok := s.repo.(commanddom.BatchClaimer)
	if !ok || input.SensorID == "" {
		return s.Poll(ctx, PollInput{TenantID: input.TenantID, SensorID: input.SensorID,
			Capabilities: input.Capabilities, Limit: input.Limit, MaxScanCommands: input.ReportedFree})
	}
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	sensorID, err := shared.IDFromString(input.SensorID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid sensor id", shared.ErrValidation)
	}

	held, err := claimer.CountHeldScans(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	slots := freeScanSlots(input.MaxJobs, held, input.ReportedFree)

	limit := input.Limit
	if limit <= 0 {
		limit = 10
	}
	limit = min(limit, 100)
	cands, err := s.repo.GetPendingForSensor(ctx, tenantID, &sensorID, input.Capabilities, candidateLimit(limit))
	if err != nil {
		return nil, err
	}
	cands = s.gateFor(ctx, tenantID, &sensorID, cands).accepted(cands)
	if len(cands) > limit {
		cands = cands[:limit]
	}
	cands = capScanCommands(cands, slots)
	// The scope may have changed since the jobs were queued: their targets
	// pass the dispatch gate again before the claim (scope_recheck.go).
	cands = s.recheckScope(ctx, tenantID, &sensorID, cands)
	if len(cands) == 0 {
		return nil, nil
	}

	ids := make([]shared.ID, len(cands))
	pinned := make(map[shared.ID]bool, len(cands))
	for i, c := range cands {
		ids[i] = c.ID
		pinned[c.ID] = c.SensorID != nil
	}
	claimed, err := claimer.ClaimManyForSensor(ctx, tenantID, sensorID, input.Capabilities, ids)
	if err != nil {
		return nil, err
	}
	won := make(map[shared.ID]bool, len(claimed))
	for _, id := range claimed {
		won[id] = true
	}
	out := make([]*commanddom.Command, 0, len(claimed))
	for _, c := range cands {
		if !won[c.ID] {
			continue
		}
		// Re-read: the claim set the sensor, the lease and its epoch.
		cmd, err := s.repo.GetByTenantAndID(ctx, tenantID, c.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, cmd)
	}
	// The organization's HTTP policy and the template signatures go into the
	// payload first, so the job signature covers them.
	delivered, err := s.deliver(ctx, input.SensorID, out)
	if err != nil {
		return nil, err
	}
	return s.signClaimed(ctx, tenantID, input.SensorID, delivered, pinned), nil
}

// freeScanSlots is how many more scans a sensor may take: its job limit
// (at least 1) minus what it holds, and no more than it reported free.
func freeScanSlots(maxJobs, held int, reportedFree *int) int {
	if maxJobs <= 0 {
		maxJobs = 1
	}
	free := maxJobs - held
	if reportedFree != nil {
		free = min(free, *reportedFree)
	}
	return max(free, 0)
}

// deliver prepares the commands a sensor gets: the tenant's tool HTTP layer
// on every scan command, then the custom template signatures. Both work on
// copies; the stored commands are never changed. A tenant policy that
// cannot be read fails the delivery (the claimed commands go back when
// their lease ends): a job never leaves without the organization's layer.
func (s *Service) deliver(ctx context.Context, sensorID string, cmds []*commanddom.Command) ([]*commanddom.Command, error) {
	if s.httpPolicy != nil {
		for i, c := range cmds {
			if c.Type != commanddom.CommandTypeScan {
				continue
			}
			pol, err := s.httpPolicy.ToolHTTPPolicy(ctx, c.TenantID)
			if err != nil {
				return nil, fmt.Errorf("read the organization's tool HTTP policy: %w", err)
			}
			payload, err := withHTTPPolicy(c.Payload, pol)
			if err != nil {
				return nil, err
			}
			cp := *c
			cp.Payload = payload
			cmds[i] = &cp
		}
	}
	return s.signTemplates(sensorID, cmds), nil
}

// withHTTPPolicy sets the payload's http_policy to the tenant's layer, or
// removes it when the tenant sets none: the field belongs to the platform,
// whatever a command's creator put there.
func withHTTPPolicy(payload json.RawMessage, pol sensordom.ToolHTTPPolicy) (json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(payload) == 0 || string(payload) == "null" {
		fields = map[string]json.RawMessage{}
	} else if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("scan command payload: %w", err)
	}
	if pol.IsZero() {
		if _, ok := fields["http_policy"]; !ok {
			return payload, nil
		}
		delete(fields, "http_policy")
	} else {
		b, err := json.Marshal(pol)
		if err != nil {
			return nil, err
		}
		fields["http_policy"] = b
	}
	return json.Marshal(fields)
}

// signTemplates signs the custom templates of each command for sensorID, on
// a copy: the stored command is never changed, and every delivery is
// signed afresh (a new issue and expiry time, the polling sensor's id).
func (s *Service) signTemplates(sensorID string, cmds []*commanddom.Command) []*commanddom.Command {
	if s.templates == nil {
		return cmds
	}
	for i, c := range cmds {
		signed := s.templates.SignTemplates(c.TenantID.String(), sensorID, c.ID.String(), c.Payload)
		if bytes.Equal(signed, c.Payload) {
			continue
		}
		cp := *c
		cp.Payload = signed
		cmds[i] = &cp
	}
	return cmds
}

// capScanCommands keeps every non-scan command and at most n scan commands,
// in poll order.
func capScanCommands(cmds []*commanddom.Command, n int) []*commanddom.Command {
	out := cmds[:0:0]
	for _, c := range cmds {
		if c.Type == commanddom.CommandTypeScan {
			if n <= 0 {
				continue
			}
			n--
		}
		out = append(out, c)
	}
	return out
}

// Acknowledge marks a command as acknowledged.
func (s *Service) Acknowledge(ctx context.Context, tenantID, sensorID, commandID string) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}
	if err := ensureSensorOwnsCommand(cmd, sensorID); err != nil {
		return nil, err
	}

	if !cmd.CanBeAcknowledged() {
		return nil, shared.NewDomainError("INVALID_STATE", "command cannot be acknowledged", shared.ErrValidation)
	}
	if sid, err := shared.IDFromString(sensorID); err == nil {
		cmds := []*commanddom.Command{cmd}
		gate := s.gateFor(ctx, cmd.TenantID, &sid, cmds)
		if err := gate.claimError(cmd); err != nil {
			if errors.Is(err, ErrOutOfGrant) && s.grantRefusals != nil {
				s.grantRefusals.ObserveGrantRefusal(ctx, cmd.TenantID, sid, cmd.ID.String(), gate.grantRefusal(cmd))
			}
			return nil, err
		}
		// Scope may have changed since the job was queued, or polled
		// (scope_recheck.go): its targets pass the dispatch gate again.
		if cmd, err = s.recheckOne(ctx, sid, cmd); err != nil {
			return nil, err
		}
	}

	// Atomic claim: only one concurrent poller can transition a pending
	// command to acknowledged. A read-modify-write via Update would let two
	// sensors that both polled the same unassigned command each "win",
	// double-dispatching it. cmd was just fetched tenant-scoped, so reuse its
	// already-parsed IDs.
	claimed, err := s.repo.ClaimForSensor(ctx, cmd.TenantID, cmd.ID, sensorID)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, shared.NewDomainError("CONFLICT", "command already claimed by another sensor", shared.ErrConflict)
	}
	metrics.CommandClaimsTotal.WithLabelValues("claim").Inc()

	// Return the freshly-claimed state.
	return s.Get(ctx, tenantID, commandID)
}

// Start marks a command as running.
func (s *Service) Start(ctx context.Context, tenantID, sensorID, commandID string) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}
	if err := ensureSensorOwnsCommand(cmd, sensorID); err != nil {
		return nil, err
	}

	if cmd.Status != commanddom.CommandStatusAcknowledged {
		return nil, shared.NewDomainError("INVALID_STATE", "command must be acknowledged before starting", shared.ErrValidation)
	}

	fence := fenceOf(cmd, sensorID)
	cmd.Start()
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, err
	}

	return cmd, nil
}

// fenceOf is what a sensor-side change of cmd, as just read, expects to
// still hold when it is written.
func fenceOf(cmd *commanddom.Command, sensorID string) commanddom.Fence {
	return commanddom.Fence{SensorID: sensorID, Status: cmd.Status, Epoch: cmd.LeaseEpoch}
}

// ErrLeaseLost: the command changed hands between the read and the write of
// a sensor-side change (its lease ran out and it was re-queued, maybe
// claimed again). The change is not applied.
var ErrLeaseLost = shared.NewDomainError("CONFLICT", "the command is no longer held under this lease", shared.ErrConflict)

// saveSensorChange writes a sensor-side state change (start, complete,
// fail) of a command the sensor holds, under the fence: with a repository
// that supports it, the write applies only if the command is still held by
// that sensor in the state and lease epoch that were read. A command
// re-queued after its lease ran out can therefore never be completed by the
// sensor that lost it (RFC-035 D6). Commands nobody holds use Update.
func (s *Service) saveSensorChange(ctx context.Context, cmd *commanddom.Command, fence commanddom.Fence) error {
	f, ok := s.repo.(commanddom.FencedUpdater)
	if !ok || cmd.SensorID == nil {
		return s.repo.Update(ctx, cmd)
	}
	applied, err := f.FencedUpdate(ctx, cmd, fence)
	if err != nil {
		return err
	}
	if !applied {
		return ErrLeaseLost
	}
	return nil
}

// ensureSensorOwnsCommand rejects lifecycle operations on a command assigned to
// a DIFFERENT sensor (anti-tampering: otherwise any sensor in the tenant could
// acknowledge/complete/fail another sensor's command and inject forged
// results). Unassigned/broadcast commands (SensorID == nil) remain operable by
// any sensor in the tenant. Returns a not-found-style error to avoid leaking
// the command's existence to a non-owning sensor.
func ensureSensorOwnsCommand(cmd *commanddom.Command, sensorID string) error {
	if cmd.SensorID != nil && cmd.SensorID.String() != sensorID {
		return shared.NewDomainError("NOT_FOUND", "command not found", shared.ErrNotFound)
	}
	return nil
}

// CompleteInput represents the input for completing a command.
type CompleteInput struct {
	TenantID  string          `json:"tenant_id" validate:"required,uuid"`
	SensorID  string          `json:"sensor_id" validate:"required,uuid"`
	CommandID string          `json:"command_id" validate:"required,uuid"`
	Result    json.RawMessage `json:"result,omitempty"`
	// LeaseEpoch, when the sensor sent it, is the lease epoch it ran the
	// command under; a different current epoch refuses the change.
	LeaseEpoch *int `json:"-"`
}

// Complete marks a command as completed.
func (s *Service) Complete(ctx context.Context, input CompleteInput) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, input.TenantID, input.CommandID)
	if err != nil {
		return nil, err
	}
	if err := ensureSensorOwnsCommand(cmd, input.SensorID); err != nil {
		return nil, err
	}

	if cmd.Status != commanddom.CommandStatusRunning {
		return nil, shared.NewDomainError("INVALID_STATE", "command must be running to complete", shared.ErrValidation)
	}
	if input.LeaseEpoch != nil && *input.LeaseEpoch != cmd.LeaseEpoch {
		return nil, ErrLeaseLost
	}

	fence := fenceOf(cmd, input.SensorID)
	cmd.Complete(input.Result)
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, err
	}

	return cmd, nil
}

// FailInput represents the input for failing a command.
type FailInput struct {
	TenantID     string `json:"tenant_id" validate:"required,uuid"`
	SensorID     string `json:"sensor_id" validate:"required,uuid"`
	CommandID    string `json:"command_id" validate:"required,uuid"`
	ErrorMessage string `json:"error_message"`
	// LeaseEpoch: see CompleteInput.LeaseEpoch.
	LeaseEpoch *int `json:"-"`
	// Refusal is the structured policy refusal a v2 sensor reported, or
	// nil (then a failure reason with the local-policy prefix still counts
	// as one). research/25 §3.6.
	Refusal *sensordom.DispatchRefusal `json:"-"`
}

// MaxFailErrorMessageBytes caps the sensor-supplied error message stored on a
// failed command (it is persisted and rendered in the UI / scan runs).
const MaxFailErrorMessageBytes = 4 << 10 // 4 KiB

// Fail marks a command as failed.
//
// Only a command the sensor is actually working on can be failed: acknowledged
// or running, or still pending when it is explicitly assigned to the calling
// sensor (a sensor rejecting a job it was handed before claiming it). Before,
// Fail had no state check, so any tenant sensor could flip an unassigned
// pending command — or a completed one — to failed.
func (s *Service) Fail(ctx context.Context, input FailInput) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, input.TenantID, input.CommandID)
	if err != nil {
		return nil, err
	}
	if err := ensureSensorOwnsCommand(cmd, input.SensorID); err != nil {
		return nil, err
	}

	switch cmd.Status {
	case commanddom.CommandStatusAcknowledged, commanddom.CommandStatusRunning:
	case commanddom.CommandStatusPending:
		if cmd.SensorID == nil || cmd.SensorID.String() != input.SensorID {
			return nil, shared.NewDomainError("INVALID_STATE", "command must be claimed before it can be failed", shared.ErrValidation)
		}
	default:
		return nil, shared.NewDomainError("INVALID_STATE", "command is already finished", shared.ErrConflict)
	}

	if input.LeaseEpoch != nil && *input.LeaseEpoch != cmd.LeaseEpoch {
		return nil, ErrLeaseLost
	}

	// A policy refusal (research/25 D8): routed work goes to another
	// eligible sensor, the refuser is excluded; the timeline and audit
	// hear about every refusal.
	if ref := sensordom.RefusalOf(input.Refusal, input.ErrorMessage); ref != nil {
		sensorID := cmd.SensorID
		if s.refusals != nil && sensorID != nil {
			s.refusals.ObserveLocalPolicyRefusal(ctx, cmd.TenantID, *sensorID, cmd.ID.String(), ref.Message())
		}
		out, done, err := s.handleRefusal(ctx, cmd, input, ref)
		if done {
			return out, err
		}
		fence := fenceOf(cmd, input.SensorID)
		cmd.Fail(truncateUTF8(ref.Message(), MaxFailErrorMessageBytes))
		if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
			return nil, err
		}
		return cmd, nil
	}

	fence := fenceOf(cmd, input.SensorID)
	cmd.Fail(truncateUTF8(input.ErrorMessage, MaxFailErrorMessageBytes))
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, err
	}

	return cmd, nil
}

// truncateUTF8 cuts s to at most maxBytes without splitting a UTF-8 rune.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// CancelCommand cancels an open command (pending, acknowledged, running).
// Canceling a canceled command is a no-op; a finished one (completed,
// failed, expired) cannot be canceled. The write is conditional, so a
// result the sensor got accepted after the read is not overwritten. The
// sensor learns about it on its next heartbeat (cancel_command_ids).
func (s *Service) CancelCommand(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error) {
	cmd, err := s.Get(ctx, tenantID, commandID)
	if err != nil {
		return nil, err
	}

	switch cmd.Status {
	case commanddom.CommandStatusCanceled:
		return cmd, nil
	case commanddom.CommandStatusPending, commanddom.CommandStatusAcknowledged, commanddom.CommandStatusRunning:
	default:
		return nil, cannotCancel(cmd.Status)
	}

	cmd.Cancel()
	c, ok := s.repo.(commanddom.OpenCanceler)
	if !ok {
		if err := s.repo.Update(ctx, cmd); err != nil {
			return nil, err
		}
		return cmd, nil
	}
	applied, err := c.CancelIfOpen(ctx, cmd)
	if err != nil {
		return nil, err
	}
	if !applied {
		// It finished between the read and the write.
		now, err := s.Get(ctx, tenantID, commandID)
		if err != nil {
			return nil, err
		}
		if now.Status == commanddom.CommandStatusCanceled {
			return now, nil
		}
		return nil, cannotCancel(now.Status)
	}
	return cmd, nil
}

func cannotCancel(st commanddom.CommandStatus) error {
	return shared.NewDomainError("INVALID_STATE", "cannot cancel a "+string(st)+" command", shared.ErrValidation)
}

// DeleteCommand deletes a command.
func (s *Service) DeleteCommand(ctx context.Context, tenantID, commandID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cid, err := shared.IDFromString(commandID)
	if err != nil {
		return fmt.Errorf("%w: invalid command id", shared.ErrValidation)
	}

	// Verify command belongs to tenant
	if _, err := s.repo.GetByTenantAndID(ctx, tid, cid); err != nil {
		return err
	}

	return s.repo.Delete(ctx, tid, cid)
}
