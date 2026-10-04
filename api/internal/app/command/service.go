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
	logger    *logger.Logger
	// refusals hears about failed commands (local_policy.go); nil: none.
	refusals RefusalObserver
	// privatePolicy keeps private targets from sensors without a local
	// policy when the tenant asks (local_policy.go); nil: never.
	privatePolicy PrivateTargetPolicy
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

	cmds, err := s.repo.GetPendingForSensor(ctx, tenantID, sensorID, input.Capabilities, limit)
	if err != nil {
		return nil, err
	}
	// The tenant keeps private targets away from sensors without a local
	// policy (RFC-040 Q3 (a)): they stay pending for one that has it.
	if anyPrivateTarget(cmds) && s.withholdPrivate(ctx, tenantID, sensorID) {
		cmds = withoutPrivateTargets(cmds)
	}
	if input.MaxScanCommands != nil {
		cmds = capScanCommands(cmds, *input.MaxScanCommands)
	}
	return s.signTemplates(input.SensorID, cmds), nil
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
	if sid, err := shared.IDFromString(sensorID); err == nil && HasPrivateTarget(cmd.Payload) && s.withholdPrivate(ctx, cmd.TenantID, &sid) {
		return nil, ErrLocalPolicyRequired
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
}

// MaxFailErrorMessageBytes caps the sensor-supplied error message stored on a
// failed command (it is persisted and rendered in the UI / pipeline runs).
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

	fence := fenceOf(cmd, input.SensorID)
	cmd.Fail(truncateUTF8(input.ErrorMessage, MaxFailErrorMessageBytes))
	if err := s.saveSensorChange(ctx, cmd, fence); err != nil {
		return nil, err
	}
	if s.refusals != nil && cmd.SensorID != nil {
		s.refusals.ObserveLocalPolicyRefusal(ctx, cmd.TenantID, *cmd.SensorID, cmd.ID.String(), cmd.ErrorMessage)
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
