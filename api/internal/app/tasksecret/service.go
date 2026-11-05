// Package tasksecret delivers the secrets a sensor's tools use for a task of
// a claimed job: at claim it lists the refs the job may use (names only,
// covered by the job signature) and records them for that claim; per task
// it answers the sensor's signed fetch with the values, sealed with HPKE to
// a single-use key in the request. Every gate lives in Fetch; every refusal
// is the same ErrRefused, which the route answers as command-not-found.
//
// Design: docs/architecture/task-secrets.md.
package tasksecret

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/openctemio/contract/secretref"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	toolsourceapp "github.com/openctemio/openctem/api/internal/app/toolsource"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/tasksecret"
	"github.com/openctemio/openctem/api/pkg/domain/toolsource"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/sealed"
)

// ErrRefused is every refusal of a fetch. The sensor is told
// command-not-found and nothing else: the answer never tells a missing
// command from another tenant's, a lost lease, an untrusted grant or an
// exhausted count.
var ErrRefused = errors.New("task secrets: refused")

// Refusal reasons (audit metadata only, never sent to the sensor).
const (
	reasonNotKeyBound     = "not_key_bound"
	reasonInvalidRequest  = "invalid_request"
	reasonCommandNotFound = "command_not_found"
	reasonLease           = "lease"
	reasonNotConfined     = "not_confined"
	reasonNotTrusted      = "not_trusted"
	reasonNoGrant         = "no_grant"
	reasonRefNotGranted   = "ref_not_granted"
	reasonClass           = "class_not_allowed"
	reasonMaxFetches      = "max_fetches"
)

// sensorAuditActor names the sensor channel as the actor of a fetch.
const sensorAuditActor = "sensor"

// MaxRequestBytes bounds a fetch body.
const MaxRequestBytes = 16 << 10

// Commands reads the command a fetch names (*command.Service): an
// organization sensor's command in its own tenant, or the shared job a
// shared sensor holds, read in the job's tenant.
type Commands interface {
	Get(ctx context.Context, tenantID, commandID string) (*commanddom.Command, error)
	HeldSharedJob(ctx context.Context, a *sensordom.Sensor, commandID string) (*commanddom.Command, error)
}

// SensorGrants reads a sensor's grant (postgres.SensorGrantRepository).
type SensorGrants interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error)
	GetShared(ctx context.Context, sensorID shared.ID) (*sensordom.Grant, error)
}

// ProviderKeys reads an organization's provider keys
// (*toolsourceapp.Service).
type ProviderKeys interface {
	EnabledSources(ctx context.Context, tenantID shared.ID, sources []string) ([]string, error)
	ForDelivery(ctx context.Context, tenantID shared.ID, sources []string) (map[string]toolsourceapp.Resolved, error)
	MarkDelivered(ctx context.Context, tenantID shared.ID, sources []string)
}

// ProxyPools reads proxy pool credentials (*proxypoolapp.Service).
type ProxyPools interface {
	PoolHasCredentials(ctx context.Context, tenantID shared.ID, poolID string) (bool, error)
	PoolCredentials(ctx context.Context, tenantID shared.ID, poolID string) ([]proxypoolapp.Credential, error)
	TestCredentialsFor(ctx context.Context, c *commanddom.Command, poolID string) ([]proxypoolapp.Credential, error)
}

// AuditLogger records audit events (*auditapp.AuditService).
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service lists and delivers task secrets. Any source may be nil: no
// provider keys, or no proxy pools, then nothing of that kind is listed.
type Service struct {
	grants   dom.Repository
	commands Commands
	sensors  SensorGrants
	keys     ProviderKeys
	pools    ProxyPools
	audit    AuditLogger
	logger   *logger.Logger
	now      func() time.Time
}

// NewService creates the service.
func NewService(grants dom.Repository, commands Commands, sensors SensorGrants, keys ProviderKeys, pools ProxyPools,
	audit AuditLogger, log *logger.Logger,
) *Service {
	return &Service{grants: grants, commands: commands, sensors: sensors, keys: keys, pools: pools, audit: audit,
		logger: log.With("service", "task_secrets"), now: time.Now}
}

// SetCommands sets the command reader (the command service, which itself
// takes this service as its secrets granter).
func (s *Service) SetCommands(c Commands) { s.commands = c }

// =============================================================================
// At claim
// =============================================================================

// GrantSecrets lists the secrets cmd may use and records them for its claim
// by sensorID under cmd.LeaseEpoch (command.SecretsGranter). It never reads
// a value. A shared job (a shared sensor's) gets the local policy never and
// no organization pool.
func (s *Service) GrantSecrets(ctx context.Context, cmd *commanddom.Command, sensorID shared.ID) (secretref.Set, error) {
	sharedJob := cmd.IsPlatformJob
	set := secretref.Set{V: secretref.Version, Local: secretref.LocalAllow, Refs: []secretref.Ref{}}
	if sharedJob {
		set.Local = secretref.LocalNever
	}
	if s.keys != nil {
		job := sensordom.JobOf(string(cmd.Type), cmd.Payload)
		if providers := toolsource.ProvidersForJob(job.Tool, job.Capability); len(providers) > 0 {
			enabled, err := s.keys.EnabledSources(ctx, cmd.TenantID, providers)
			if err != nil {
				return secretref.Set{}, fmt.Errorf("read the organization's provider keys: %w", err)
			}
			// Room for the pool's ref; ids k1..kN in provider id order.
			if len(enabled) > secretref.MaxRefs-1 {
				enabled = enabled[:secretref.MaxRefs-1]
			}
			for i, id := range enabled {
				set.Refs = append(set.Refs, secretref.Ref{
					ID: "k" + strconv.Itoa(i+1), Kind: secretref.KindProviderKey, Class: secretref.ClassProvider,
					Ref: id, Slot: id, Audience: []string{secretref.AudienceProvider(id)},
					Consumer: secretref.ConsumerTool, Local: set.Local,
				})
			}
		}
	}
	if !sharedJob && s.pools != nil {
		pool, err := s.credentialedPool(ctx, cmd)
		if err != nil {
			return secretref.Set{}, err
		}
		if pool != "" {
			set.Refs = append(set.Refs, secretref.Ref{
				ID: "p1", Kind: secretref.KindEgressProxy, Class: secretref.ClassProvider, Ref: pool,
				Audience: []string{secretref.AudiencePool}, Consumer: secretref.ConsumerForwarder,
				Required: true, Local: secretref.LocalNever,
			})
		}
	}
	if err := set.Validate(); err != nil {
		return secretref.Set{}, fmt.Errorf("job secrets: %w", err)
	}
	tasks := len(commanddom.PayloadTargets(cmd.Payload))
	if cmd.Type == commanddom.CommandTypeProxyTest {
		tasks = 1
	}
	g := &dom.Grant{TenantID: cmd.TenantID, CommandID: cmd.ID, SensorID: sensorID, LeaseEpoch: cmd.LeaseEpoch,
		Set: set, MaxFetches: dom.MaxFetches(tasks)}
	if err := s.grants.Record(ctx, g); err != nil {
		return secretref.Set{}, err
	}
	return set, nil
}

// credentialedPool is the pool whose credentials the job uses: the pool its
// egress member names (exactly that one, stamped at this claim) when one
// of the listed endpoints needs credentials, or a proxy test's own pool
// when it has an endpoint with credentials; "" for none.
func (s *Service) credentialedPool(ctx context.Context, cmd *commanddom.Command) (string, error) {
	var p struct {
		PoolID string               `json:"pool_id"`
		Egress *proxypool.JobEgress `json:"egress"`
	}
	if len(cmd.Payload) == 0 {
		return "", nil
	}
	if err := json.Unmarshal(cmd.Payload, &p); err != nil {
		return "", fmt.Errorf("command payload: %w", err)
	}
	if cmd.Type == commanddom.CommandTypeProxyTest {
		if p.PoolID == "" {
			return "", nil
		}
		has, err := s.pools.PoolHasCredentials(ctx, cmd.TenantID, p.PoolID)
		if err != nil {
			return "", fmt.Errorf("read the test's proxy pool: %w", err)
		}
		if !has {
			return "", nil
		}
		return p.PoolID, nil
	}
	if p.Egress == nil || p.Egress.Mode != proxypool.ModePool || p.Egress.PoolID == "" {
		return "", nil
	}
	if !slices.ContainsFunc(p.Egress.Endpoints, func(e proxypool.JobEndpoint) bool { return e.Auth }) {
		return "", nil
	}
	return p.Egress.PoolID, nil
}

// =============================================================================
// Fetch
// =============================================================================

// FetchInput is one fetch, as the route received it.
type FetchInput struct {
	// Sensor is the authenticated sensor.
	Sensor *sensordom.Sensor
	// KeyBound: the request was authenticated by an RFC 9421 signature of
	// the sensor's key-bound identity (so the body, its reply key and its
	// lease epoch are the sensor's own).
	KeyBound bool
	// CommandID is the path's command id.
	CommandID string
	// Body is the exact request body (the signed bytes).
	Body []byte
}

// refusal is a refused fetch with its reason and, when known, the tenant
// it is audited in.
type refusal struct {
	reason string
	tenant *shared.ID
	cmd    string
}

func (r *refusal) Error() string { return "task secrets refused: " + r.reason }

func (r *refusal) Unwrap() error { return ErrRefused }

// Fetch answers a fetch with the sealed values of the asked refs, or an
// error wrapping ErrRefused. The gates, in order: a key-bound signed
// request; a valid body; the command read in its own tenant (never one the
// sensor names); held by this sensor under the body's lease epoch, live; a
// shared sensor confined; the sensor's grant trusted (for every kind); the
// claim's recorded grant; every asked ref in it, and allowed for its class;
// the fetch count below its bound.
func (s *Service) Fetch(ctx context.Context, in FetchInput) (*secretref.SealedAnswer, error) {
	sn := in.Sensor
	if sn == nil {
		return nil, ErrRefused
	}
	ref := &refusal{tenant: sn.TenantID, cmd: in.CommandID}
	refuse := func(reason string) error {
		ref.reason = reason
		s.auditRefusal(ctx, sn, ref)
		return ref
	}
	if !in.KeyBound || !sn.KeyBound() {
		return nil, refuse(reasonNotKeyBound)
	}
	req, replyKey, ok := decodeRequest(in.Body)
	if !ok {
		return nil, refuse(reasonInvalidRequest)
	}
	cmd, err := s.heldCommand(ctx, sn, in.CommandID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, refuse(reasonCommandNotFound)
	}
	if err != nil {
		return nil, err
	}
	ref.tenant, ref.cmd = &cmd.TenantID, cmd.ID.String()
	live := cmd.Status == commanddom.CommandStatusAcknowledged || cmd.Status == commanddom.CommandStatusRunning
	if cmd.SensorID == nil || *cmd.SensorID != sn.ID || int64(cmd.LeaseEpoch) != req.LeaseEpoch || !live {
		return nil, refuse(reasonLease)
	}
	if sn.IsShared() && !Confined(sn) {
		return nil, refuse(reasonNotConfined)
	}
	eff, ok, err := s.effectiveGrant(ctx, sn, cmd.TenantID)
	if err != nil {
		return nil, err
	}
	if !ok || eff.TrustLevel != sensordom.TrustTrusted {
		return nil, refuse(reasonNotTrusted)
	}
	g, err := s.grants.Get(ctx, cmd.TenantID, cmd.ID, cmd.LeaseEpoch)
	if errors.Is(err, shared.ErrNotFound) {
		return nil, refuse(reasonNoGrant)
	}
	if err != nil {
		return nil, err
	}
	if g.SensorID != sn.ID {
		return nil, refuse(reasonNoGrant)
	}
	asked := make([]secretref.Ref, 0, len(req.Refs))
	for _, id := range req.Refs {
		r, ok := g.Set.Lookup(id)
		if !ok {
			return nil, refuse(reasonRefNotGranted)
		}
		if !classAllowed(r, sn, eff) {
			return nil, refuse(reasonClass)
		}
		asked = append(asked, r)
	}
	counted, err := s.grants.Consume(ctx, cmd.TenantID, cmd.ID, cmd.LeaseEpoch, sn.ID)
	if err != nil {
		return nil, err
	}
	if !counted {
		return nil, refuse(reasonMaxFetches)
	}

	answer, delivered, err := s.values(ctx, cmd, req, asked)
	if err != nil {
		return nil, err
	}
	pt, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	info := secretref.Info(sn.ID.String(), cmd.ID.String(), req.LeaseEpoch, in.Body)
	ct, err := sealed.SealToKey(replyKey, info, pt)
	clear(pt)
	if err != nil {
		return nil, fmt.Errorf("seal task secrets: %w", err)
	}
	if len(delivered) > 0 {
		s.keys.MarkDelivered(ctx, cmd.TenantID, delivered)
	}
	s.auditDelivery(ctx, sn, cmd, req, asked, answer)
	return &secretref.SealedAnswer{Suite: secretref.SuiteHybridV1, KeyID: secretref.KeyID(replyKey),
		Sealed: base64.RawURLEncoding.EncodeToString(ct)}, nil
}

// decodeRequest reads a fetch body strictly: exactly a FetchRequest, valid,
// with a reply key of the suite's KEM.
func decodeRequest(body []byte) (secretref.FetchRequest, []byte, bool) {
	var req secretref.FetchRequest
	if len(body) == 0 || len(body) > MaxRequestBytes {
		return req, nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.More() || req.Validate() != nil {
		return req, nil, false
	}
	key, err := req.ReplyKeyBytes()
	if err != nil {
		return req, nil, false
	}
	if _, err := sealed.ParsePublicKey(key); err != nil {
		return req, nil, false
	}
	return req, key, true
}

// heldCommand reads the command a fetch names in the tenant it belongs to:
// an organization sensor's own tenant, or the shared job a shared sensor
// holds. Nothing the sensor sends names the tenant.
func (s *Service) heldCommand(ctx context.Context, sn *sensordom.Sensor, commandID string) (*commanddom.Command, error) {
	if s.commands == nil {
		return nil, shared.ErrNotFound
	}
	if _, err := shared.IDFromString(commandID); err != nil {
		return nil, shared.ErrNotFound
	}
	if sn.IsShared() {
		return s.commands.HeldSharedJob(ctx, sn, commandID)
	}
	if sn.TenantID == nil {
		return nil, shared.ErrNotFound
	}
	cmd, err := s.commands.Get(ctx, sn.TenantID.String(), commandID)
	if err != nil {
		return nil, err
	}
	if !cmd.TenantID.Equals(*sn.TenantID) {
		return nil, shared.ErrNotFound
	}
	return cmd, nil
}

// effectiveGrant is the sensor's effective grant (an untrusted grant has
// none of its dimensions). ok is false when there is none: nothing is
// delivered without a grant.
func (s *Service) effectiveGrant(ctx context.Context, sn *sensordom.Sensor, tenantID shared.ID) (sensordom.Grant, bool, error) {
	if s.sensors == nil {
		return sensordom.Grant{}, false, nil
	}
	var (
		g   *sensordom.Grant
		err error
	)
	if sn.IsShared() {
		g, err = s.sensors.GetShared(ctx, sn.ID)
	} else {
		if sn.TenantID == nil || !sn.TenantID.Equals(tenantID) {
			return sensordom.Grant{}, false, nil
		}
		g, err = s.sensors.Get(ctx, tenantID, sn.ID)
	}
	if errors.Is(err, shared.ErrNotFound) || (err == nil && g == nil) {
		return sensordom.Grant{}, false, nil
	}
	if err != nil {
		return sensordom.Grant{}, false, fmt.Errorf("read the sensor's grant: %w", err)
	}
	return g.Effective(), true, nil
}

// Confined reports whether a shared sensor's tools run fully confined: it
// reports network confinement and its manifest posture says the sandbox is
// required, in use and enforces the network. A shared sensor without that
// receives no secret.
func Confined(sn *sensordom.Sensor) bool {
	if sn == nil || !slices.Contains(sn.Reported.Capabilities, sensordom.CapabilityNetConfined) {
		return false
	}
	p := sensordom.SanitizeManifestPosture(sn.Posture)
	return p != nil && p.Sandbox != nil && p.Sandbox.Mode == sensordom.SandboxModeRequired &&
		p.Sandbox.Sandboxed && p.Sandbox.NetworkEnforced
}

// classAllowed is the class gate of one ref. A provider secret (a data
// service's key, the job's proxy pool) needs the trusted grant only. A
// target credential (the organization's own systems) also needs the grant's
// credentials dimension and an organization sensor: a shared sensor is
// refused until an organization can allow a named one.
func classAllowed(r secretref.Ref, sn *sensordom.Sensor, eff sensordom.Grant) bool {
	switch r.Class {
	case secretref.ClassProvider:
		return true
	case secretref.ClassTarget:
		return eff.AllowCredentials && !sn.IsShared()
	default:
		return false
	}
}

// values resolves the asked refs. It returns the answer and the provider
// ids whose keys it holds (marked used once the answer is sealed).
func (s *Service) values(ctx context.Context, cmd *commanddom.Command, req secretref.FetchRequest, asked []secretref.Ref,
) (secretref.Answer, []string, error) {
	ans := secretref.Answer{CommandID: cmd.ID.String(), LeaseEpoch: req.LeaseEpoch,
		IssuedAt: s.now().UTC().Truncate(time.Second), Secrets: []secretref.Secret{}}
	var providers []string
	for _, r := range asked {
		if r.Kind == secretref.KindProviderKey {
			providers = append(providers, r.Ref)
		}
	}
	var keys map[string]toolsourceapp.Resolved
	if len(providers) > 0 && s.keys != nil {
		var err error
		if keys, err = s.keys.ForDelivery(ctx, cmd.TenantID, providers); err != nil {
			return ans, nil, err
		}
	}
	var delivered []string
	missing := func(id, reason string) { ans.Missing = append(ans.Missing, secretref.Missing{ID: id, Reason: reason}) }
	for _, r := range asked {
		var raw json.RawMessage
		switch r.Kind {
		case secretref.KindProviderKey:
			k, ok := keys[r.Ref]
			if !ok {
				missing(r.ID, secretref.MissingNotSet)
				continue
			}
			if k.Missing != "" {
				missing(r.ID, k.Missing)
				continue
			}
			b, err := json.Marshal(secretref.ProviderKey{Key: k.Value})
			if err != nil {
				return ans, nil, err
			}
			raw = b
		case secretref.KindEgressProxy:
			v, ok, err := s.poolValue(ctx, cmd, r.Ref)
			if err != nil {
				return ans, nil, err
			}
			if !ok {
				missing(r.ID, secretref.MissingNotSet)
				continue
			}
			raw = v
		default:
			missing(r.ID, secretref.MissingNotSet)
			continue
		}
		// The sensor refuses the whole answer for one value its validator
		// refuses: a stored value that no longer meets the kind's rules is
		// not sent.
		if err := secretref.ValidateValue(r, raw); err != nil {
			s.logger.Warn("stored secret no longer meets its kind's rules; not delivered",
				"tenant_id", cmd.TenantID.String(), "command_id", cmd.ID.String(), "ref", r.ID, "kind", r.Kind)
			missing(r.ID, secretref.MissingNotSet)
			continue
		}
		ans.Secrets = append(ans.Secrets, secretref.Secret{ID: r.ID, Kind: r.Kind, Value: raw, Provenance: secretref.ProvenanceTenant})
		if r.Kind == secretref.KindProviderKey {
			delivered = append(delivered, r.Ref)
		}
	}
	return ans, delivered, nil
}

// poolValue is the credentials of the recorded pool poolID: a proxy test's
// own pool (every endpoint with credentials), or a job's pool (the endpoints
// that may carry traffic now; a disabled pool gives none). ok is false when
// the pool is gone.
func (s *Service) poolValue(ctx context.Context, cmd *commanddom.Command, poolID string) (json.RawMessage, bool, error) {
	if s.pools == nil {
		return nil, false, nil
	}
	var (
		creds []proxypoolapp.Credential
		err   error
	)
	if cmd.Type == commanddom.CommandTypeProxyTest {
		creds, err = s.pools.TestCredentialsFor(ctx, cmd, poolID)
	} else {
		creds, err = s.pools.PoolCredentials(ctx, cmd.TenantID, poolID)
	}
	if errors.Is(err, shared.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	v := secretref.EgressProxy{Endpoints: make([]secretref.ProxyEndpoint, 0, len(creds))}
	for _, c := range creds {
		e := secretref.ProxyEndpoint{ID: c.EndpointID, Username: c.Username, Password: c.Password}
		one, _ := json.Marshal(secretref.EgressProxy{Endpoints: []secretref.ProxyEndpoint{e}})
		if _, err := secretref.DecodeEgressProxy(one); err != nil || len(v.Endpoints) == secretref.MaxProxyEndpoints {
			continue // never sent; the endpoint fails on the sensor like any unusable one
		}
		v.Endpoints = append(v.Endpoints, e)
	}
	b, err := json.Marshal(v)
	return b, err == nil, err
}

// =============================================================================
// Audit
// =============================================================================

func (s *Service) auditDelivery(ctx context.Context, sn *sensordom.Sensor, cmd *commanddom.Command, req secretref.FetchRequest,
	asked []secretref.Ref, ans secretref.Answer,
) {
	ids := make([]string, 0, len(asked))
	kinds := make([]string, 0, len(asked))
	classes := make([]string, 0, len(asked))
	for _, r := range asked {
		ids = append(ids, r.ID)
		kinds = append(kinds, r.Kind)
		classes = append(classes, r.Class)
	}
	delivered := make([]string, 0, len(ans.Secrets))
	for _, v := range ans.Secrets {
		delivered = append(delivered, v.ID)
	}
	missing := make(map[string]string, len(ans.Missing))
	for _, m := range ans.Missing {
		missing[m.ID] = m.Reason
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionSecretDelivered, auditdom.ResourceTypeCommand, cmd.ID.String()).
		WithMessage(fmt.Sprintf("%d of %d task secrets delivered, sealed, to a sensor", len(delivered), len(asked))).
		WithMetadata("sensor_id", sn.ID.String()).WithMetadata("shared_sensor", sn.IsShared()).
		WithMetadata("command_id", cmd.ID.String()).WithMetadata("lease_epoch", req.LeaseEpoch).
		WithMetadata("task", req.Task).WithMetadata("refs", ids).WithMetadata("kinds", kinds).
		WithMetadata("classes", classes).WithMetadata("delivered", delivered).WithMetadata("missing", missing).
		WithMetadata("provenance", secretref.ProvenanceTenant)
	s.logAudit(ctx, cmd.TenantID, ev)
}

func (s *Service) auditRefusal(ctx context.Context, sn *sensordom.Sensor, r *refusal) {
	s.logger.Info("task secrets fetch refused", "sensor_id", sn.ID.String(), "command_id", r.cmd, "reason", r.reason)
	if r.tenant == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionSecretRefused, auditdom.ResourceTypeCommand, r.cmd).
		WithMessage("A sensor's task secrets fetch was refused").
		WithMetadata("sensor_id", sn.ID.String()).WithMetadata("shared_sensor", sn.IsShared()).
		WithMetadata("command_id", r.cmd).WithMetadata("reason", r.reason)
	s.logAudit(ctx, *r.tenant, ev)
}

func (s *Service) logAudit(ctx context.Context, tenantID shared.ID, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: sensorAuditActor}, ev); err != nil {
		s.logger.Error("failed to write task secrets audit event", "action", string(ev.Action), "error", err)
	}
}
