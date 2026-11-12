package server

// Lookup jobs (docs/architecture/certificate-transparency-monitoring.md):
// the platform's passive lookups (lookup.ct@1) run on its instance-scope
// sensors, so the platform makes no outbound request for them.

import (
	"database/sql"

	"github.com/openctemio/openctem/server/internal/app/lookupjob"
	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	signerclient "github.com/openctemio/openctem/server/internal/infra/signer"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// newLookupJobService builds the lookup jobs (nil without a database). A
// platform without a job signer has the service but no sensor is ever
// offered a job: a platform sensor pins the signing key and would refuse an
// unsigned one.
func newLookupJobService(cfg *config.Config, db *sql.DB, log *logger.Logger) *lookupjob.Service {
	if db == nil {
		return nil
	}
	lc := lookupjob.Config{}
	if sock := cfg.SensorConfig.SignerSocket; sock != "" {
		lc.Signer = signerclient.NewClient(sock, cfg.SensorConfig.SignerTimeout)
	}
	return lookupjob.NewService(lc, postgres.NewLookupJobRepository(&postgres.DB{DB: db}), log)
}

// newLookupJobHandler serves the sensor routes (nil without the service).
func newLookupJobHandler(svc *Services, log *logger.Logger) *handler.LookupJobHandler {
	if svc == nil || svc.LookupJobs == nil {
		return nil
	}
	return handler.NewLookupJobHandler(svc.LookupJobs, log)
}
