package integration

import (
	freshapp "github.com/openctemio/openctem/api/internal/app/assetfreshness"
	scopesvc "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// integrationTools is the catalog of an organization whose sensors report
// the built-in tools' contracts and one for zap (dast.web).
var integrationTools = stagetest.Source{Cat: stagetest.Catalog(stage.ToolFacts{Name: "zap", Implements: []stage.Key{stage.DASTWeb}})}

// integrationRecorder is the asset freshness recorder with integrationTools.
func integrationRecorder(repo *postgres.AssetFreshnessRepository) *freshapp.Recorder {
	r := freshapp.NewRecorder(repo, logger.NewNop())
	r.SetToolFacts(integrationTools)
	return r
}

// integrationGuard is the web job guard with integrationTools.
func integrationGuard(g *scopesvc.WebJobGuard) *scopesvc.WebJobGuard {
	g.SetToolFacts(integrationTools)
	return g
}
