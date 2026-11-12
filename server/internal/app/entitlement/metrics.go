package entitlement

import "github.com/openctemio/openctem/api/internal/metrics"

// refusals counts additions refused by a limit.
var refusals = metrics.LimitRefusalsTotal
