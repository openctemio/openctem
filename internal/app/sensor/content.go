package sensor

// Scanner content (docs/rfcs/RFC-031-managed-sensor-updates.md): the tenant's
// content policy, and refresh_content commands to one sensor or the fleet.
// What a sensor reports about its content arrives on the heartbeat inside its
// tool inventory (sensordom.ReportedTool.Content).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/command"
	sensordom "github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// RefreshContentTTL is how long a refresh_content command waits for its
// sensor: a sensor offline for a day gets the next one.
const RefreshContentTTL = 24 * time.Hour

// maxRefreshContentNames bounds the content names of one refresh request.
const maxRefreshContentNames = 32

// ErrContentRefreshUnsupported: the sensor reports no content it manages (an
// older sensor), or it is disabled or revoked.
var ErrContentRefreshUnsupported = fmt.Errorf("%w: sensor does not support content refresh", shared.ErrConflict)

// contentSensorReader is the part of the sensor repository the content
// service reads.
type contentSensorReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensordom.Sensor, error)
}

// contentCommandStore creates refresh_content commands and finds the open
// ones (the dedup).
type contentCommandStore interface {
	Create(ctx context.Context, cmd *command.Command) error
	OpenCommandsOfType(ctx context.Context, tenantID shared.ID, cmdType string) (map[string]string, error)
}

// contentFleetLister lists every sensor of a tenant.
type contentFleetLister interface {
	ListAllSensors(ctx context.Context, tenantID string) ([]*sensordom.Sensor, error)
}

// ContentService manages the tenant content policy and refresh requests.
type ContentService struct {
	sensors  contentSensorReader
	fleet    contentFleetLister
	policies sensordom.ContentPolicyRepository
	commands contentCommandStore
	audit    *auditapp.AuditService
	defaults sensordom.ContentPolicy
	now      func() time.Time
	logger   *logger.Logger
}

// NewContentService creates the service. audit may be nil.
func NewContentService(sensors contentSensorReader, fleet contentFleetLister, policies sensordom.ContentPolicyRepository,
	commands contentCommandStore, auditService *auditapp.AuditService, log *logger.Logger) *ContentService {
	return &ContentService{
		sensors: sensors, fleet: fleet, policies: policies, commands: commands, audit: auditService,
		defaults: sensordom.DefaultContentPolicy(), now: time.Now,
		logger: log.With("service", "sensor_content"),
	}
}

// ContentPolicyView is a tenant's policy as the API shows it.
type ContentPolicyView struct {
	// Policy is the effective policy: the stored one with defaults filled.
	Policy sensordom.ContentPolicy
	// Defaults is the platform default.
	Defaults  sensordom.ContentPolicy
	UpdatedAt *time.Time
	UpdatedBy *shared.ID
}

// GetPolicy returns the tenant's effective policy.
func (s *ContentService) GetPolicy(ctx context.Context, tenantID shared.ID) (*ContentPolicyView, error) {
	stored, err := s.policies.GetContentPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	view := &ContentPolicyView{Policy: s.defaults.WithDefaults(s.defaults), Defaults: s.defaults.WithDefaults(s.defaults)}
	if stored != nil {
		view.Policy = stored.Policy.WithDefaults(s.defaults)
		at := stored.UpdatedAt
		view.UpdatedAt = &at
		view.UpdatedBy = stored.UpdatedBy
	}
	return view, nil
}

// EffectivePolicy is the policy health and the read model judge content by.
// A read error falls back to the platform default (logged): the sensor list
// must not fail because of it.
func (s *ContentService) EffectivePolicy(ctx context.Context, tenantID shared.ID) sensordom.ContentPolicy {
	view, err := s.GetPolicy(ctx, tenantID)
	if err != nil {
		s.logger.Warn("content policy unavailable, using the default", "tenant_id", tenantID.String(), "error", err)
		return s.defaults.WithDefaults(s.defaults)
	}
	return view.Policy
}

// RefreshResult counts the commands a fleet-wide request created.
type RefreshResult struct {
	CommandsCreated int
	// Skipped: sensors that cannot take the command (no managed content,
	// disabled, revoked) or already have one open.
	Skipped int
}

// UpdatePolicy validates and saves the tenant's policy. With applyNow every
// eligible sensor gets a refresh_content command (not forced) carrying it.
func (s *ContentService) UpdatePolicy(ctx context.Context, tenantID shared.ID, policy sensordom.ContentPolicy,
	applyNow bool, actx *auditapp.AuditContext) (*ContentPolicyView, RefreshResult, error) {
	if err := policy.Validate(); err != nil {
		return nil, RefreshResult{}, fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
	}
	stored := &sensordom.StoredContentPolicy{TenantID: tenantID, Policy: policy}
	if actx != nil {
		if id, err := shared.IDFromString(actx.ActorID); err == nil {
			stored.UpdatedBy = &id
		}
	}
	if err := s.policies.SaveContentPolicy(ctx, stored); err != nil {
		return nil, RefreshResult{}, err
	}
	view, err := s.GetPolicy(ctx, tenantID)
	if err != nil {
		return nil, RefreshResult{}, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorContentPolicyUpdated, audit.ResourceTypeSettings, "sensor-content-policy").
		WithResourceName("Sensor content policy").
		WithMessage("Scanner content policy updated").
		WithMetadata("policy", view.Policy).
		WithMetadata("apply_now", applyNow))

	var res RefreshResult
	if applyNow {
		res, err = s.refreshFleet(ctx, tenantID, nil, false, view.Policy)
		if err != nil {
			return view, res, err
		}
	}
	return view, res, nil
}

// RefreshSensor queues a refresh_content command for one sensor. When one is
// already open it is returned instead (alreadyPending).
func (s *ContentService) RefreshSensor(ctx context.Context, tenantID, sensorID shared.ID, names []string, force bool,
	actx *auditapp.AuditContext) (commandID shared.ID, alreadyPending bool, err error) {
	if err := validateContentNames(names); err != nil {
		return shared.ID{}, false, err
	}
	a, err := s.sensors.GetByTenantAndID(ctx, tenantID, sensorID)
	if err != nil {
		return shared.ID{}, false, err
	}
	if !eligibleForRefresh(a) {
		return shared.ID{}, false, ErrContentRefreshUnsupported
	}
	open, err := s.commands.OpenCommandsOfType(ctx, tenantID, string(command.CommandTypeRefreshContent))
	if err != nil {
		return shared.ID{}, false, err
	}
	if id, ok := open[a.ID.String()]; ok {
		cid, perr := shared.IDFromString(id)
		if perr != nil {
			return shared.ID{}, false, perr
		}
		return cid, true, nil
	}
	cmd, err := s.queue(ctx, tenantID, a.ID, names, force, s.EffectivePolicy(ctx, tenantID))
	if err != nil {
		return shared.ID{}, false, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorContentRefreshRequested, audit.ResourceTypeSensor, a.ID.String()).
		WithResourceName(a.Name).
		WithMessage(fmt.Sprintf("Content refresh requested for sensor '%s'", a.Name)).
		WithMetadata("command_id", cmd.ID.String()).
		WithMetadata("content", names).
		WithMetadata("force", force))
	return cmd.ID, false, nil
}

// RefreshFleet queues a refresh_content command for every eligible sensor of
// the tenant that has none open.
func (s *ContentService) RefreshFleet(ctx context.Context, tenantID shared.ID, names []string, force bool,
	actx *auditapp.AuditContext) (RefreshResult, error) {
	if err := validateContentNames(names); err != nil {
		return RefreshResult{}, err
	}
	res, err := s.refreshFleet(ctx, tenantID, names, force, s.EffectivePolicy(ctx, tenantID))
	if err != nil {
		return res, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionSensorContentRefreshRequested, audit.ResourceTypeSensor, "fleet").
		WithResourceName("All sensors").
		WithMessage(fmt.Sprintf("Content refresh requested for %d sensors", res.CommandsCreated)).
		WithMetadata("commands_created", res.CommandsCreated).
		WithMetadata("skipped", res.Skipped).
		WithMetadata("content", names).
		WithMetadata("force", force))
	return res, nil
}

func (s *ContentService) refreshFleet(ctx context.Context, tenantID shared.ID, names []string, force bool,
	policy sensordom.ContentPolicy) (RefreshResult, error) {
	var res RefreshResult
	sensors, err := s.fleet.ListAllSensors(ctx, tenantID.String())
	if err != nil {
		return res, err
	}
	open, err := s.commands.OpenCommandsOfType(ctx, tenantID, string(command.CommandTypeRefreshContent))
	if err != nil {
		return res, err
	}
	for _, a := range sensors {
		if _, busy := open[a.ID.String()]; busy || !eligibleForRefresh(a) {
			res.Skipped++
			continue
		}
		if _, err := s.queue(ctx, tenantID, a.ID, names, force, policy); err != nil {
			return res, err
		}
		res.CommandsCreated++
	}
	return res, nil
}

// refreshContentPayload is the refresh_content command payload (sdk-go
// core.RefreshContentRequest).
type refreshContentPayload struct {
	Content []string                 `json:"content,omitempty"`
	Force   bool                     `json:"force,omitempty"`
	Policy  *sensordom.ContentPolicy `json:"policy,omitempty"`
}

func (s *ContentService) queue(ctx context.Context, tenantID, sensorID shared.ID, names []string, force bool,
	policy sensordom.ContentPolicy) (*command.Command, error) {
	payload, err := json.Marshal(refreshContentPayload{Content: names, Force: force, Policy: &policy})
	if err != nil {
		return nil, fmt.Errorf("encode refresh_content payload: %w", err)
	}
	cmd, err := command.NewCommand(tenantID, command.CommandTypeRefreshContent, command.CommandPriorityNormal, payload)
	if err != nil {
		return nil, err
	}
	cmd.SetSensorID(sensorID)
	cmd.SetExpiration(s.now().Add(RefreshContentTTL))
	if err := s.commands.Create(ctx, cmd); err != nil {
		return nil, fmt.Errorf("create refresh_content command: %w", err)
	}
	return cmd, nil
}

// eligibleForRefresh: active, and it manages some content (an older sensor
// would never claim the command, which would sit pending until it expires).
func eligibleForRefresh(a *sensordom.Sensor) bool {
	return a.Status == sensordom.SensorStatusActive && a.SupportsContentRefresh()
}

func validateContentNames(names []string) error {
	if len(names) > maxRefreshContentNames {
		return fmt.Errorf("%w: at most %d content names", shared.ErrValidation, maxRefreshContentNames)
	}
	for _, n := range names {
		if !sensordom.IsKnownContentName(n) {
			return fmt.Errorf("%w: unknown content %q", shared.ErrValidation, n)
		}
	}
	return nil
}

func (s *ContentService) logAudit(ctx context.Context, actx *auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil || actx == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, *actx, event); err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Warn("content audit event not recorded", "error", err)
	}
}
