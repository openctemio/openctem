package routes

import "github.com/openctemio/openctem/api/internal/infra/http/middleware"

// heavyReads caps, per tenant, the tenant-wide aggregate reads (dashboard
// metrics, finding and asset stats, attack-surface graphs) running at once.
// Each scans a tenant's findings or assets; without a cap, one tenant's burst
// of dashboard loads took every database connection. Extra requests wait.
var heavyReads = middleware.NewTenantWaitLimiter(4) //nolint:gochecknoglobals // one limiter shared by every heavy route
