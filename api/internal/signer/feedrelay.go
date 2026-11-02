package signer

// Feed relay rules (docs/rfcs/RFC-142-feed-relay.md). A feed relay
// statement asks a platform-owned sensor to download named files of a
// signed feed. It belongs to no organization, so no scope ledger applies;
// what bounds it instead is the signer's own feed origin allowlist
// (SIGNER_FEED_ORIGINS): a compromised API cannot make the relay sensor,
// which sits in a network with internet access, fetch anything else.
//
//   - the platform tenant id (the nil UUID) is only for feed_relay, and
//     feed_relay only carries the platform tenant id;
//   - sensor_scope is instance (a platform sensor, never an organization's);
//   - no tool, templates, content, zone or limits;
//   - 1 to MaxFeedOrigins targets, each a canonical https origin listed in
//     the signer's allowlist.

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

// Refusal reasons of the feed relay rules.
const (
	ReasonFeedRelayShape  = "feed_relay_shape"
	ReasonFeedRelayOrigin = "feed_relay_origin"
	ReasonPlatformTenant  = "platform_tenant"
)

// checkFeedRelayShape applies the rules that need no configuration. It
// returns nil for a statement that is neither a feed relay nor carries the
// platform tenant id.
func checkFeedRelayShape(st *jobsign.Statement) *refusal {
	relay := st.CommandType == jobsign.CommandTypeFeedRelay
	platform := st.TenantID == jobsign.PlatformTenantID
	switch {
	case !relay && !platform:
		return nil
	case !relay:
		return refuse(http.StatusForbidden, ReasonPlatformTenant, "the platform tenant id is only for a feed relay statement")
	case !platform:
		return refuse(http.StatusForbidden, ReasonPlatformTenant, "a feed relay statement belongs to the platform, not an organization")
	case st.SensorScope != jobsign.SensorScopeInstance:
		return refuse(http.StatusForbidden, ReasonFeedRelayShape, "a feed relay runs only on a platform (instance) sensor")
	case st.Tool != "" || len(st.Templates) > 0 || len(st.Content) > 0 || st.Zone != nil || len(st.Limits) > 0:
		return refuse(http.StatusBadRequest, ReasonFeedRelayShape, "a feed relay names no tool, templates, content, zone or limits")
	case len(st.Targets) == 0 || len(st.Targets) > jobsign.MaxFeedOrigins:
		return refuse(http.StatusBadRequest, ReasonFeedRelayShape, "a feed relay names 1 to %d feed origins", jobsign.MaxFeedOrigins)
	}
	for i, t := range st.Targets {
		if jobsign.NormalizeFeedOrigin(t) != t {
			return refuse(http.StatusBadRequest, ReasonFeedRelayShape, "target %d is not a canonical https feed origin", i)
		}
	}
	return nil
}

// checkFeedOrigins refuses a feed relay statement naming an origin outside
// the allowlist.
func (s *Service) checkFeedOrigins(st *jobsign.Statement) *refusal {
	for i, t := range st.Targets {
		if !s.feedOrigins[t] {
			return refuse(http.StatusForbidden, ReasonFeedRelayOrigin, "target %d is not in the signer's feed origin allowlist (SIGNER_FEED_ORIGINS)", i)
		}
	}
	return nil
}
