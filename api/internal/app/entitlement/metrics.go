package entitlement

import "github.com/openctemio/openctem/api/internal/metrics"

// refusals counts additions refused by a plan limit.
var refusals = metrics.PlanLimitRefusalsTotal
