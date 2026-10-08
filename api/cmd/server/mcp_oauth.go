package main

import (
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/routes"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
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
