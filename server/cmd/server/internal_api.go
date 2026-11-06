package main

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"os"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/entitlement"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/internalapi"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// internalOrganizations adapts the limits repository to the internal API.
type internalOrganizations struct{ repo *postgres.LimitsRepository }

func (o internalOrganizations) Exists(ctx context.Context, id shared.ID) (bool, error) {
	return o.repo.OrganizationExists(ctx, id)
}

func (o internalOrganizations) Page(ctx context.Context, after *shared.ID, limit int) ([]internalapi.OrganizationRef, error) {
	ids, created, err := o.repo.OrganizationPage(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	out := make([]internalapi.OrganizationRef, 0, len(ids))
	for i := range ids {
		out = append(out, internalapi.OrganizationRef{ID: ids[i], CreatedAt: created[i]})
	}
	return out, nil
}

// internalProvisioner creates organizations as the control-plane actor.
type internalProvisioner struct {
	creator *tenantapp.OrganizationCreator
}

func (p internalProvisioner) Create(ctx context.Context, in tenantapp.CreateOrganizationInput) (*tenantapp.CreatedOrganization, error) {
	return p.creator.Create(ctx, in, auditapp.AuditContext{ActorEmail: entitlement.ControlPlaneActor})
}

// startInternalAPI starts the internal entitlements API when
// INTERNAL_API_ADDR is set (docs/architecture/limits.md) and turns on the
// control-plane source of limits. It returns nil when the API is off.
func startInternalAPI(cfg *config.Config, repos *Repositories, svc *Services, redisClient *redis.Client, log *logger.Logger) (*nethttp.Server, error) {
	ic := cfg.InternalAPI
	if !ic.Enabled() || svc.Entitlement == nil {
		return nil, nil
	}
	pemKeys, err := os.ReadFile(ic.JWTPublicKeysFile) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, fmt.Errorf("internal API: token keys: %w", err)
	}
	keys, err := internalapi.ParsePublicKeys(pemKeys)
	if err != nil {
		return nil, err
	}
	// Single-use tokens must be remembered across every replica: the replay
	// cache lives in Redis, and the API does not start without it.
	if redisClient == nil {
		return nil, errors.New("internal API: Redis is required (token replay cache shared by every replica)")
	}
	replay := internalapi.NewRedisReplayCache(redisClient)
	verifier, err := internalapi.NewVerifier(keys, ic.JWTIssuer, replay)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := internalapi.TLSConfig(ic.CertFile, ic.KeyFile, ic.ClientCAFile)
	if err != nil {
		return nil, err
	}
	// The control plane's rows take effect only with its API on.
	svc.Entitlement.SetSources(entitlement.NewControlPlaneSource(repos.Limits))
	deps := internalapi.Deps{
		Verifier:      verifier,
		Entitlements:  svc.Entitlement,
		IdlePolicy:    svc.IdleWorkspaces,
		Organizations: internalOrganizations{repo: repos.Limits},
		Audit:         repos.AdminAuditLog,
		Log:           log,
	}
	if svc.Tenant != nil && svc.UserProvisioning != nil {
		deps.Provisioner = internalProvisioner{creator: tenantapp.NewOrganizationCreator(svc.Tenant, svc.UserProvisioning, repos.User, log)}
	}
	srv := internalapi.NewServer(ic.Addr, tlsCfg, internalapi.NewHandler(deps))
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			log.Error("internal API listener stopped", "error", err)
		}
	}()
	log.Info("internal entitlements API listening", "addr", ic.Addr, "issuer", ic.JWTIssuer, "keys", len(keys))
	return srv, nil
}

// stopInternalAPI shuts the listener down.
func stopInternalAPI(srv *nethttp.Server, log *logger.Logger) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("internal API shutdown", "error", err)
	}
}
