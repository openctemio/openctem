package entitlement

import "github.com/openctemio/openctem/server/internal/metrics"

// refusals counts additions refused by a limit.
var refusals = metrics.LimitRefusalsTotal
