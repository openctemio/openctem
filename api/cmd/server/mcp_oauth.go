package main

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/routes"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// newMCPDiscovery builds the OAuth discovery of the MCP endpoint from the
// public URL (RFC-062 §4). Without a usable APP_URL the MCP endpoint keeps
// working with `oct_` keys only, and MCP clients get no discovery; the
// reason is logged once at startup.
func newMCPDiscovery(cfg *config.Config, log *logger.Logger) *routes.MCPDiscovery {
	if cfg.App.URL == "" {
		log.Info("MCP OAuth discovery off: APP_URL is not set")
		return nil
	}
	e, err := mcpoauth.NewEndpoints(cfg.App.URL)
	if err != nil {
		log.Warn("MCP OAuth discovery off: APP_URL is not a usable public origin", "error", err.Error())
		return nil
	}
	return &routes.MCPDiscovery{
		Endpoints:      e,
		Metadata:       handler.NewMCPResourceMetadataHandler(e),
		AllowedOrigins: cfg.CORS.AllowedOrigins,
	}
}

// newMCPOAuthService builds the authorization server of the MCP endpoint
// (RFC-062). It needs the public endpoints (discovery), the database and the
// permission services; without any of them it is nil and the MCP endpoint
// accepts `oct_` keys only.
func newMCPOAuthService(d *routes.MCPDiscovery, deps *HandlerDeps, log *logger.Logger) *mcpoauthapp.Service {
	svc, repos, cfg := deps.Services, deps.Repos, deps.Config
	if d == nil || deps.DB == nil || svc == nil || repos == nil || svc.PermCache == nil || repos.Tenant == nil || repos.User == nil {
		return nil
	}
	var policies mcpoauthapp.PolicyReader
	if svc.Tenant != nil {
		policies = mcpPolicyReader{tenants: svc.Tenant}
	}
	var replay mcpoauthapp.ReplayCache
	if deps.RedisClient != nil {
		replay = redisReplayCache{client: deps.RedisClient}
	}
	var audit mcpoauthapp.AuditLogger
	if svc.Audit != nil {
		audit = svc.Audit
	}
	repo := repos.MCPOAuth
	if repo == nil {
		repo = postgres.NewMCPOAuthRepository(deps.DB)
	}
	s, err := mcpoauthapp.NewService(mcpoauthapp.Config{
		Repository:  repo,
		Connections: repo,
		Clients:     repo,
		// Write tools wait for the person's confirmation (RFC-062 §10).
		Confirmations: repo,
		// Deprecated by MCP; off unless the operator turns it on.
		DynamicRegistration: cfg.MCP.DynamicRegistration,
		// DPoP proof ids are remembered in Redis (one use per proof).
		Replay:    replay,
		Endpoints: d.Endpoints,
		// Codes and tokens are stored as HMAC-SHA256 with the application
		// key; tokens hashed under a previous key keep working during a
		// rotation.
		Pepper:      cfg.Encryption.Key,
		OldPeppers:  cfg.Encryption.PreviousKeys,
		Fetcher:     mcpoauthapp.NewHTTPMetadataFetcher(),
		Members:     apikey.NewMembershipChecker(repos.Tenant, repos.User),
		Permissions: apikey.NewHolderPermissions(repos.Tenant, svc.PermCache),
		Audit:       audit,
		Logger:      log,
		Policies:    policies,
		// Platform-wide verified client hosts (operator list).
		TrustedClientHosts: cfg.MCP.TrustedClientHosts,
	})
	if err != nil {
		log.Warn("MCP OAuth off", "error", err.Error())
		return nil
	}
	return s
}

// mcpPolicyReader reads an organization's MCP policy from its settings.
type mcpPolicyReader struct {
	tenants interface {
		GetMCPSettings(ctx context.Context, tenantID string) (*tenantdom.MCPSettings, error)
	}
}

func (r mcpPolicyReader) MCPPolicy(ctx context.Context, tenantID shared.ID) (tenantdom.MCPSettings, error) {
	if r.tenants == nil {
		return tenantdom.MCPSettings{}, nil
	}
	p, err := r.tenants.GetMCPSettings(ctx, tenantID.String())
	if err != nil {
		return tenantdom.MCPSettings{}, err
	}
	return *p, nil
}

// redisReplayCache remembers DPoP proof ids (RFC 9449 §11.1) with SETNX, so a
// proof is accepted once across every replica.
type redisReplayCache struct {
	client *redis.Client
}

func (c redisReplayCache) FirstUse(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return c.client.SetNX(ctx, key, "1", ttl)
}
