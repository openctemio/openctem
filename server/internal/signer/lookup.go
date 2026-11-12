package signer

// Lookup rules (docs/architecture/certificate-transparency-monitoring.md).
// A lookup statement asks a platform (instance-scope) sensor a passive
// question for one organization: which certificates Certificate
// Transparency lists for a root domain (lookup.ct@1). What bounds it,
// whatever the API asks:
//
//   - sensor_scope is instance: an organization's sensor is never asked;
//   - an organization's tenant id (the platform tenant id is refused by the
//     feed relay rules), so the scope ledger's exclusions apply to it;
//   - the tool is the one tool of a lookup capability, which the stage
//     catalog knows as passive (tier 0), so the ledger asks no approval
//     tier of it;
//   - exactly one target, a canonical root domain name;
//   - no templates, content, zone or limits.

import (
	"net/http"
	"slices"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/server/pkg/domain/lookupjob"
	"github.com/openctemio/openctem/server/pkg/jobsign"
)

// ReasonLookupShape is the refusal reason of the lookup rules.
const ReasonLookupShape = "lookup_shape"

// checkLookupShape applies the lookup rules; nil for another command type.
func checkLookupShape(st *jobsign.Statement) *refusal {
	if st.CommandType != jobsign.CommandTypeLookup {
		return nil
	}
	tools := make([]string, 0, len(lookupjob.Tools))
	for _, t := range lookupjob.Tools {
		tools = append(tools, t)
	}
	switch {
	case st.SensorScope != jobsign.SensorScopeInstance:
		return refuse(http.StatusForbidden, ReasonLookupShape, "a lookup runs only on a platform (instance) sensor")
	case !slices.Contains(tools, st.Tool):
		return refuse(http.StatusForbidden, ReasonLookupShape, "a lookup names the tool of a lookup capability")
	case len(st.Templates) > 0 || len(st.Content) > 0 || st.Zone != nil || len(st.Limits) > 0:
		return refuse(http.StatusBadRequest, ReasonLookupShape, "a lookup names no templates, content, zone or limits")
	case len(st.Targets) != 1:
		return refuse(http.StatusBadRequest, ReasonLookupShape, "a lookup names exactly one target")
	}
	if d, err := ctlookup.NormalizeDomain(st.Targets[0]); err != nil || d != st.Targets[0] {
		return refuse(http.StatusBadRequest, ReasonLookupShape, "a lookup target is a canonical root domain name")
	}
	return nil
}
