// Package proxypool is the application service for sensor proxy pools: pool
// and endpoint management with encrypted, write-only credentials, the
// network path of each sensor, the egress a scan job gets at delivery, the
// credentials a leasing sensor fetches, and the health the platform scores
// from sensor reports. Design: docs/rfcs/RFC-034-sensor-network-egress.md;
// architecture: docs/architecture/sensor-proxies.md.
package proxypool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service manages a tenant's proxy pools.
type Service struct {
	repo   pooldom.Repository
	enc    crypto.Encryptor
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
	// test is the proxy test (EnableTest); nil: not available.
	test *testSetup
	// exits records and lists scanner addresses (EnableScannerAddresses);
	// nil: none recorded.
	exits pooldom.ExitStore
	// platformEgress is the shared sensors' published egress; nil: none.
	platformEgress PlatformEgressSource
}

// NewService creates the proxy pool service. enc encrypts credentials; a
// nil or no-op encryptor refuses every credential (nothing is ever stored
// in clear). audit may be nil (tests).
func NewService(repo pooldom.Repository, enc crypto.Encryptor, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, enc: enc, audit: audit, logger: log.With("service", "proxy_pool"), now: time.Now}
}

func (s *Service) canEncrypt() bool {
	if s.enc == nil {
		return false
	}
	_, noop := s.enc.(*crypto.NoOpEncryptor)
	return !noop
}

func parseTenant(tenantID string) (shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

// parseRef parses an id from a path: a malformed one names nothing of this
// tenant.
func parseRef(id string, notFound error) (shared.ID, error) {
	v, err := shared.IDFromString(id)
	if err != nil {
		return shared.ID{}, notFound
	}
	return v, nil
}

func actorID(actx auditapp.AuditContext) *shared.ID {
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		return &id
	}
	return nil
}

// ListPools returns the tenant's pools with their endpoints.
func (s *Service) ListPools(ctx context.Context, tenantID string) ([]*pooldom.Pool, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListPools(ctx, tid)
}

// GetPool returns one pool of the tenant.
func (s *Service) GetPool(ctx context.Context, tenantID, poolID string) (*pooldom.Pool, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	pid, err := parseRef(poolID, pooldom.ErrPoolNotFound)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPool(ctx, tid, pid)
}

// PoolName is the name of one of the tenant's pools ("" when it cannot be
// read: another tenant's pool is never named).
func (s *Service) PoolName(ctx context.Context, tenantID shared.ID, poolID string) string {
	p, err := s.GetPool(ctx, tenantID.String(), poolID)
	if err != nil || p == nil {
		return ""
	}
	return p.Name
}

// CreatePoolInput is the input of CreatePool.
type CreatePoolInput struct {
	TenantID    string
	Name        string
	Description string
	Strategy    string
	Enabled     *bool
	IsDefault   bool
	// EndpointsText, when set, is a pasted endpoint list stored with the pool.
	EndpointsText *string
}

// CreatePool validates and stores a new pool, and its endpoints when given.
func (s *Service) CreatePool(ctx context.Context, in CreatePoolInput, actx auditapp.AuditContext) (*pooldom.Pool, error) {
	tid, err := parseTenant(in.TenantID)
	if err != nil {
		return nil, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	p, err := pooldom.NewPool(tid, in.Name, in.Description, in.Strategy, enabled, in.IsDefault, actorID(actx))
	if err != nil {
		return nil, err
	}
	var entries []pooldom.ListEntry
	if in.EndpointsText != nil {
		if entries, err = pooldom.ParseList(*in.EndpointsText); err != nil {
			return nil, err
		}
	}
	// A sensor on an enabled pool with no proxy gets no scan jobs (scans
	// never fall back to a direct connection), so refuse that state.
	if enabled && len(entries) == 0 {
		return nil, pooldom.ErrEnabledNeedsEndpoint
	}
	n, err := s.repo.CountPools(ctx, tid)
	if err != nil {
		return nil, err
	}
	if n >= pooldom.MaxPoolsPerTenant {
		return nil, pooldom.ErrTooManyPools
	}
	if err := s.repo.CreatePool(ctx, p); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolCreated, auditdom.ResourceTypeProxyPool, p.ID.String()).
		WithResourceName(p.Name).
		WithMessage(fmt.Sprintf("Proxy pool '%s' created", p.Name)).
		WithMetadata("is_default", p.IsDefault).
		WithMetadata("enabled", p.Enabled).
		WithMetadata("strategy", p.Strategy).
		WithSeverity(auditdom.SeverityMedium))
	if len(entries) > 0 {
		if err := s.replace(ctx, p, entries, actx); err != nil {
			return nil, err
		}
	}
	return s.repo.GetPool(ctx, tid, p.ID)
}

// UpdatePoolInput is the input of UpdatePool; nil fields are unchanged.
type UpdatePoolInput struct {
	TenantID    string
	PoolID      string
	Name        *string
	Description *string
	Strategy    *string
	Enabled     *bool
	IsDefault   *bool
}

// UpdatePool changes a pool's own fields.
func (s *Service) UpdatePool(ctx context.Context, in UpdatePoolInput, actx auditapp.AuditContext) (*pooldom.Pool, error) {
	p, err := s.GetPool(ctx, in.TenantID, in.PoolID)
	if err != nil {
		return nil, err
	}
	before := *p
	if err := p.Update(in.Name, in.Description, in.Strategy, in.Enabled, in.IsDefault); err != nil {
		return nil, err
	}
	if p.Enabled && !before.Enabled && len(p.Endpoints) == 0 {
		return nil, pooldom.ErrEnabledNeedsEndpoint
	}
	if err := s.repo.UpdatePool(ctx, p); err != nil {
		return nil, err
	}
	changes := auditdom.NewChanges()
	if before.Name != p.Name {
		changes.Set("name", before.Name, p.Name)
	}
	if before.Enabled != p.Enabled {
		changes.Set("enabled", before.Enabled, p.Enabled)
	}
	if before.IsDefault != p.IsDefault {
		changes.Set("is_default", before.IsDefault, p.IsDefault)
	}
	if before.Strategy != p.Strategy {
		changes.Set("strategy", before.Strategy, p.Strategy)
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolUpdated, auditdom.ResourceTypeProxyPool, p.ID.String()).
		WithResourceName(p.Name).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("Proxy pool '%s' updated", p.Name)).
		WithSeverity(auditdom.SeverityMedium))
	return s.repo.GetPool(ctx, p.TenantID, p.ID)
}

// DeletePool removes a pool; PROXY_POOL_IN_USE while a sensor names it.
func (s *Service) DeletePool(ctx context.Context, tenantID, poolID string, actx auditapp.AuditContext) error {
	p, err := s.GetPool(ctx, tenantID, poolID)
	if err != nil {
		return err
	}
	if err := s.repo.DeletePool(ctx, p.TenantID, p.ID); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolDeleted, auditdom.ResourceTypeProxyPool, p.ID.String()).
		WithResourceName(p.Name).
		WithMessage(fmt.Sprintf("Proxy pool '%s' deleted", p.Name)).
		WithMetadata("endpoints", len(p.Endpoints)).
		WithSeverity(auditdom.SeverityHigh))
	return nil
}

// ReplaceEndpoints makes a pasted list the pool's endpoints.
func (s *Service) ReplaceEndpoints(ctx context.Context, tenantID, poolID, text string, actx auditapp.AuditContext) (*pooldom.Pool, error) {
	p, err := s.GetPool(ctx, tenantID, poolID)
	if err != nil {
		return nil, err
	}
	entries, err := pooldom.ParseList(text)
	if err != nil {
		return nil, err
	}
	// Emptying an enabled pool would leave its sensors without scan jobs.
	if p.Enabled && len(entries) == 0 && len(p.Endpoints) > 0 {
		return nil, pooldom.ErrEnabledNeedsEndpoint
	}
	if err := s.replace(ctx, p, entries, actx); err != nil {
		return nil, err
	}
	return s.repo.GetPool(ctx, p.TenantID, p.ID)
}

// replace merges entries into p's endpoints: the same address keeps its id,
// health and (with the masked marker) credentials; new credentials are
// encrypted bound to the tenant and endpoint and reset the endpoint's
// health; removed lines are deleted.
func (s *Service) replace(ctx context.Context, p *pooldom.Pool, entries []pooldom.ListEntry, actx auditapp.AuditContext) error {
	now := s.now().UTC()
	existing := map[string]*pooldom.Endpoint{}
	for _, e := range p.Endpoints {
		existing[endpointKey(e.Scheme, e.Host, e.Port)] = e
	}
	var (
		out                 = make([]*pooldom.Endpoint, 0, len(entries))
		added, credsChanged []string
		kept                = map[string]bool{}
		listChanged         = len(entries) != len(p.Endpoints)
	)
	for i, in := range entries {
		key := endpointKey(in.Scheme, in.Host, in.Port)
		e, ok := existing[key]
		if !ok {
			e = &pooldom.Endpoint{ID: shared.NewID(), TenantID: p.TenantID, PoolID: p.ID, Enabled: true,
				Health: pooldom.NewHealth(now), CreatedAt: now}
			added = append(added, in.Address())
			listChanged = true
		} else {
			kept[key] = true
			cp := *e
			e = &cp
		}
		if e.Scheme != in.Scheme || e.Priority != i || e.Label != in.Label {
			listChanged = true
		}
		e.Scheme, e.Host, e.Port, e.Label, e.Priority, e.UpdatedAt = in.Scheme, in.Host, in.Port, in.Label, i, now
		switch {
		case in.KeepCredentials:
			if !e.HasCredentials() {
				return &pooldom.ListError{Line: in.Line, Reason: fmt.Sprintf("%s has no stored credentials to keep; write them as user:password@", in.Address())}
			}
		case in.HasNewCredentials():
			if !s.canEncrypt() {
				return pooldom.ErrNoEncryption
			}
			ct, err := s.sealCredentials(e, in.Username, in.Password)
			if err != nil {
				return err
			}
			e.CredentialsEncrypted, e.CredentialsUpdatedAt = ct, &now
			e.Health.Reset(now)
			credsChanged = append(credsChanged, in.Address())
			listChanged = true
		default:
			if e.HasCredentials() {
				credsChanged = append(credsChanged, in.Address())
				listChanged = true
			}
			e.CredentialsEncrypted, e.CredentialsUpdatedAt = "", nil
		}
		out = append(out, e)
	}
	var removed []string
	for key, e := range existing {
		if !kept[key] {
			removed = append(removed, e.Address())
		}
	}
	if !listChanged && len(removed) == 0 {
		return nil
	}
	p.Revision++
	p.UpdatedAt = now
	if err := s.repo.ReplaceEndpoints(ctx, p, out); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolEndpointsChanged, auditdom.ResourceTypeProxyPool, p.ID.String()).
		WithResourceName(p.Name).
		WithMessage(fmt.Sprintf("Proxy pool '%s': %d endpoint(s), %d added, %d removed", p.Name, len(out), len(added), len(removed))).
		WithMetadata("added", added).
		WithMetadata("removed", removed).
		WithMetadata("revision", p.Revision).
		WithSeverity(auditdom.SeverityMedium))
	if len(credsChanged) > 0 {
		// The addresses only: a credential never enters the audit log.
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolCredentialsChanged, auditdom.ResourceTypeProxyPool, p.ID.String()).
			WithResourceName(p.Name).
			WithMessage(fmt.Sprintf("Proxy pool '%s': credentials changed for %d endpoint(s)", p.Name, len(credsChanged))).
			WithMetadata("endpoints", credsChanged).
			WithSeverity(auditdom.SeverityHigh))
	}
	return nil
}

func endpointKey(scheme, host string, port int) string {
	if scheme == pooldom.SchemeSOCKS5H {
		scheme = pooldom.SchemeSOCKS5
	}
	return fmt.Sprintf("%s|%s|%d", scheme, host, port)
}

// sealedCredentials is the plaintext an endpoint's ciphertext holds. The
// tenant and endpoint ids bind it: a ciphertext copied onto another row (or
// another tenant's row) does not open there.
type sealedCredentials struct {
	Tenant   string `json:"t"`
	Endpoint string `json:"e"`
	Username string `json:"u"`
	Password string `json:"p"`
}

func (s *Service) sealCredentials(e *pooldom.Endpoint, user, pass string) (string, error) {
	b, err := json.Marshal(sealedCredentials{Tenant: e.TenantID.String(), Endpoint: e.ID.String(), Username: user, Password: pass})
	if err != nil {
		return "", err
	}
	ct, err := s.enc.EncryptString(string(b))
	if err != nil {
		return "", fmt.Errorf("encrypt proxy credentials: %w", err)
	}
	return ct, nil
}

var errCredentialsUnreadable = errors.New("proxy credentials do not open")

func (s *Service) openCredentials(e *pooldom.Endpoint) (sealedCredentials, error) {
	var c sealedCredentials
	if !s.canEncrypt() {
		return c, errCredentialsUnreadable
	}
	pt, err := s.enc.DecryptString(e.CredentialsEncrypted)
	if err != nil {
		return c, errCredentialsUnreadable
	}
	if json.Unmarshal([]byte(pt), &c) != nil || c.Tenant != e.TenantID.String() || c.Endpoint != e.ID.String() {
		return sealedCredentials{}, errCredentialsUnreadable
	}
	return c, nil
}

// UpdateEndpointInput is the input of UpdateEndpoint.
type UpdateEndpointInput struct {
	TenantID    string
	PoolID      string
	EndpointID  string
	Enabled     *bool
	ResetHealth bool
}

// UpdateEndpoint enables or disables an endpoint, or resets its health (an
// administrator fixed the proxy: it comes back in probation at once).
func (s *Service) UpdateEndpoint(ctx context.Context, in UpdateEndpointInput, actx auditapp.AuditContext) (*pooldom.Pool, error) {
	p, err := s.GetPool(ctx, in.TenantID, in.PoolID)
	if err != nil {
		return nil, err
	}
	eid, err := parseRef(in.EndpointID, pooldom.ErrEndpointNotFound)
	if err != nil {
		return nil, err
	}
	var e *pooldom.Endpoint
	for _, c := range p.Endpoints {
		if c.ID == eid {
			e = c
		}
	}
	if e == nil {
		return nil, pooldom.ErrEndpointNotFound
	}
	changes := auditdom.NewChanges()
	if in.Enabled != nil && *in.Enabled != e.Enabled {
		changes.Set("enabled", e.Enabled, *in.Enabled)
		e.Enabled = *in.Enabled
	}
	if in.ResetHealth {
		changes.Set("state", e.Health.State, pooldom.StateProbation)
		e.Health.Reset(s.now().UTC())
	}
	p.Revision++
	p.UpdatedAt = s.now().UTC()
	if err := s.repo.UpdateEndpoint(ctx, p, e); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionProxyPoolEndpointUpdated, auditdom.ResourceTypeProxyPool, p.ID.String()).
		WithResourceName(p.Name).
		WithChanges(changes).
		WithMessage(fmt.Sprintf("Proxy pool '%s': endpoint %s updated", p.Name, e.Address())).
		WithMetadata("endpoint", e.Address()).
		WithSeverity(auditdom.SeverityMedium))
	return s.repo.GetPool(ctx, p.TenantID, p.ID)
}

// ListAssignments returns the tenant's sensor assignments.
func (s *Service) ListAssignments(ctx context.Context, tenantID string) ([]pooldom.Assignment, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListAssignments(ctx, tid)
}

// AssignSensor sets a sensor's network path: inherit (the organization
// default), direct, or a pool of the tenant.
func (s *Service) AssignSensor(ctx context.Context, tenantID, sensorID, mode, poolID string, actx auditapp.AuditContext) error {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return err
	}
	sid, err := parseRef(sensorID, pooldom.ErrSensorNotFound)
	if err != nil {
		return err
	}
	a := pooldom.Assignment{SensorID: sid, Mode: mode}
	var poolName string
	switch mode {
	case pooldom.ModeInherit:
		if poolID != "" {
			return shared.NewDomainError("INVALID_PROXY_POOL", "pool_id is only allowed with mode \"pool\"", shared.ErrValidation)
		}
	case pooldom.ModeDirect:
		if poolID != "" {
			return shared.NewDomainError("INVALID_PROXY_POOL", "pool_id is only allowed with mode \"pool\"", shared.ErrValidation)
		}
	case pooldom.ModePool:
		p, err := s.GetPool(ctx, tenantID, poolID)
		if err != nil {
			return err
		}
		a.PoolID, poolName = &p.ID, p.Name
	default:
		return shared.NewDomainError("INVALID_PROXY_POOL", "mode must be inherit, direct or pool", shared.ErrValidation)
	}
	before, err := s.repo.GetAssignment(ctx, tid, sid)
	if err != nil {
		return err
	}
	if mode == pooldom.ModeInherit {
		err = s.repo.DeleteAssignment(ctx, tid, sid)
	} else {
		err = s.repo.SetAssignment(ctx, tid, a, actorID(actx))
	}
	if err != nil {
		return err
	}
	changes := auditdom.NewChanges()
	changes.Set("network_path", describeAssignment(before), describeAssignment(&a))
	msg := fmt.Sprintf("Sensor network path set to %s", mode)
	if poolName != "" {
		msg += fmt.Sprintf(" (proxy pool '%s')", poolName)
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionSensorNetworkPathChanged, auditdom.ResourceTypeSensor, sid.String()).
		WithChanges(changes).
		WithMessage(msg).
		WithSeverity(auditdom.SeverityMedium))
	return nil
}

func describeAssignment(a *pooldom.Assignment) string {
	switch {
	case a == nil || a.Mode == pooldom.ModeInherit:
		return pooldom.ModeInherit
	case a.PoolID != nil:
		return pooldom.ModePool + ":" + a.PoolID.String()
	default:
		return a.Mode
	}
}

// Effective is the pool a sensor's scan jobs use now, and which target
// addresses it carries; nil when the sensor scans directly. A sensor's own
// assignment wins over the organization default; the default carries
// public targets only. A disabled default is off (its sensors scan
// directly: that is the organization's "use proxies" switch). A disabled
// pool a sensor is assigned to is still its path, with no endpoint: its
// jobs fail closed and never go direct, until the pool is enabled or the
// sensor gets another path (Direct is chosen explicitly).
func (s *Service) Effective(ctx context.Context, tenantID, sensorID shared.ID) (*pooldom.Pool, string, error) {
	a, err := s.repo.GetAssignment(ctx, tenantID, sensorID)
	if err != nil {
		return nil, "", err
	}
	if a != nil {
		if a.Mode != pooldom.ModePool || a.PoolID == nil {
			return nil, "", nil
		}
		p, err := s.repo.GetPool(ctx, tenantID, *a.PoolID)
		if err != nil {
			return nil, "", err
		}
		return p, pooldom.AppliesAll, nil
	}
	p, err := s.repo.DefaultPool(ctx, tenantID)
	if err != nil || p == nil || !p.Enabled {
		return nil, "", err
	}
	return p, pooldom.AppliesPublic, nil
}

// JobEgress is the egress member a scan job gets when sensorID takes it; nil
// when the sensor scans directly.
func (s *Service) JobEgress(ctx context.Context, tenantID, sensorID shared.ID) (*pooldom.JobEgress, error) {
	p, applies, err := s.Effective(ctx, tenantID, sensorID)
	if err != nil || p == nil {
		return nil, err
	}
	eg := pooldom.BuildJobEgress(p, applies, s.now())
	return &eg, nil
}

// Credential is one endpoint's credentials for a leasing sensor.
type Credential struct {
	EndpointID string
	Username   string
	Password   string
}

// CredentialsFor returns the credentials of poolID's endpoints for a sensor,
// only when poolID is the pool its jobs use now (the caller checked that the
// sensor holds the command's lease). Anything else is ErrPoolNotFound: the
// answer never tells a pool of another tenant from one that does not exist.
func (s *Service) CredentialsFor(ctx context.Context, tenantID, sensorID shared.ID, poolID string) ([]Credential, error) {
	pid, err := parseRef(poolID, pooldom.ErrPoolNotFound)
	if err != nil {
		return nil, err
	}
	p, _, err := s.Effective(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	if p == nil || p.ID != pid {
		return nil, pooldom.ErrPoolNotFound
	}
	out := []Credential{}
	if !p.Enabled {
		// A disabled pool carries nothing (BuildJobEgress lists no endpoint).
		return out, nil
	}
	now := s.now()
	for _, e := range p.Endpoints {
		if !e.HasCredentials() || !e.Enabled || !e.Health.Eligible(now) {
			continue
		}
		c, err := s.openCredentials(e)
		if err != nil {
			// Never sent, never logged with its value; the endpoint fails
			// on the sensor with a proxy_auth report and is quarantined.
			s.logger.Error("proxy credentials do not open", "tenant_id", tenantID.String(), "endpoint_id", e.ID.String())
			continue
		}
		out = append(out, Credential{EndpointID: e.ID.String(), Username: c.Username, Password: c.Password})
	}
	return out, nil
}

// Report is a sensor's health report for one job.
type Report struct {
	PoolID    string
	Endpoints map[string]pooldom.Signal // by endpoint id
}

// ApplyReport folds a sensor's report into the health of the pool's
// endpoints. The pool must be the one the reporting sensor's jobs use now
// (as in CredentialsFor): a sensor never moves the health of a pool it does
// not use, even one of its own organization. Unknown endpoints are ignored.
// An endpoint the platform quarantines is audited.
func (s *Service) ApplyReport(ctx context.Context, tenantID, sensorID shared.ID, r Report) error {
	pid, err := parseRef(r.PoolID, pooldom.ErrPoolNotFound)
	if err != nil {
		return err
	}
	if len(r.Endpoints) == 0 {
		return nil
	}
	p, _, err := s.Effective(ctx, tenantID, sensorID)
	if err != nil {
		return err
	}
	if p == nil || p.ID != pid {
		return pooldom.ErrPoolNotFound
	}
	return s.applyHealth(ctx, p, sensorID, r)
}

// applyHealth folds a sensor's report into the health of pool p's
// endpoints (the caller checked that the sensor may report on p).
func (s *Service) applyHealth(ctx context.Context, p *pooldom.Pool, sensorID shared.ID, r Report) error {
	tenantID, pid := p.TenantID, p.ID
	if len(r.Endpoints) == 0 {
		return nil
	}
	now := s.now().UTC()
	type change struct{ addr, state, lastError string }
	var changed []change
	err := s.repo.UpdateHealth(ctx, tenantID, pid, func(eps []*pooldom.Endpoint) {
		for _, e := range eps {
			sig, ok := r.Endpoints[e.ID.String()]
			if !ok {
				continue
			}
			if e.Health.Apply(sig, now) {
				changed = append(changed, change{addr: e.Address(), state: e.Health.State, lastError: e.Health.LastError})
			}
		}
	})
	if err != nil {
		return err
	}
	for _, c := range changed {
		s.logger.Info("proxy endpoint state changed", "tenant_id", tenantID.String(), "pool_id", pid.String(),
			"endpoint", c.addr, "state", c.state, "sensor_id", sensorID.String())
		if c.state != pooldom.StateQuarantined {
			continue
		}
		s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String()},
			auditapp.NewSuccessEvent(auditdom.ActionProxyPoolEndpointQuarantine, auditdom.ResourceTypeProxyPool, pid.String()).
				WithMessage(fmt.Sprintf("Proxy endpoint %s quarantined: %s", c.addr, strings.TrimSpace(c.lastError))).
				WithMetadata("endpoint", c.addr).
				WithMetadata("reported_by_sensor", sensorID.String()).
				WithSeverity(auditdom.SeverityMedium))
	}
	return nil
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write proxy pool audit event", "action", string(ev.Action), "error", err)
	}
}
