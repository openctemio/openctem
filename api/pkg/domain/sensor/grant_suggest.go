package sensor

// Grant suggestion (docs/architecture/sensor-pairing.md, "Leaving the legacy
// grant"): the narrowest selectable profile that would have admitted every
// job a sensor ran in a look-back window, and its pushed results, and that
// widens nothing of the sensor's current grant. The suggestion is advisory:
// applying it goes through the same compare-and-swap, audit and checks as
// any grant change, and the platform re-computes it at apply time.

import (
	"encoding/json"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GrantUsage is what a sensor did in the look-back window.
type GrantUsage struct {
	// Jobs are the distinct jobs the sensor was given (type, payload, zone).
	Jobs []UsageJob
	// JobCount is the number of jobs in the window (duplicates included).
	JobCount int
	// PushIngest: the sensor sent results without a job.
	PushIngest bool
	// AssignedZones are the zones the sensor is assigned to now.
	AssignedZones []shared.ID
	// Complete is false when the window held more jobs than were read; no
	// suggestion is made then (coverage cannot be proved).
	Complete bool
}

// UsageJob is one job of the window.
type UsageJob struct {
	Type    string
	Payload json.RawMessage
	ZoneID  *shared.ID
}

// Suggestion reasons.
const (
	// SuggestReasonIncomplete: the window held too many jobs to read.
	SuggestReasonIncomplete = "usage_incomplete"
	// SuggestReasonNoFit: no selectable profile admits every job without
	// widening the current grant.
	SuggestReasonNoFit = "no_profile_fits"
	// SuggestReasonIdle: nothing ran in the window; the default of the
	// sensor's kind is suggested.
	SuggestReasonIdle = "no_activity"
	// SuggestReasonAlreadyNarrow: the current grant is already the
	// suggested profile (or narrower than every profile that fits).
	SuggestReasonAlreadyNarrow = "already_narrowest"
)

// UsageSummary is the part of the usage the console shows.
type UsageSummary struct {
	JobCount       int
	JobTypes       []string
	Tools          []string
	MaxTier        int
	PrivateTargets bool
	PublicTargets  bool
	ZoneCount      int
	PushIngest     bool
	Complete       bool
}

// GrantSuggestion is the result of SuggestGrant.
type GrantSuggestion struct {
	// Profile is the suggested profile; "" when there is none (Reason says why).
	Profile string
	// Grant is the grant applying Profile would store.
	Grant *Grant
	// Changed lists the dimensions that would change.
	Changed []string
	Reason  string
	Usage   UsageSummary
}

// suggestOrder is the order profiles are tried in, narrowest first: the
// passive, network-less ones, then public-only, then zone-bound internal,
// then the one that carries credentials.
var suggestOrder = []string{ProfileCollector, ProfileCIRunner, ProfileEndpoint, ProfileEASMExternal,
	ProfileInternalScanner, ProfileAuthenticatedScanner}

// ContractLookup returns the sensor's reported contract for a tool (nil:
// none). The tier a job is checked at is the one the claim uses.
type ContractLookup func(tool string) *ToolContract

// SuggestGrant returns the narrowest profile that admits every job of u and
// its pushed results, and never widens cur on any dimension (Widened is
// empty by construction; callers check it again before storing). The trust
// level is kept; the remote actions are kept (they are maintenance the
// platform starts, not work the sensor does). kind is the sensor's type:
// with no activity, its default profile is suggested when it widens nothing.
func SuggestGrant(cur Grant, kind SensorType, u GrantUsage, contracts ContractLookup) GrantSuggestion {
	if contracts == nil {
		contracts = func(string) *ToolContract { return nil }
	}
	out := GrantSuggestion{Usage: summarize(u, contracts)}
	if !u.Complete {
		out.Reason = SuggestReasonIncomplete
		return out
	}
	zones := suggestZones(cur, u)
	if len(u.Jobs) == 0 && !u.PushIngest {
		if g := candidate(cur, DefaultProfileFor(kind), zones); g != nil {
			return out.with(cur, g, SuggestReasonIdle)
		}
	}
	for _, p := range suggestOrder {
		g := candidate(cur, p, zones)
		if g == nil || !covers(*g, u, contracts) {
			continue
		}
		return out.with(cur, g, "")
	}
	out.Reason = SuggestReasonNoFit
	return out
}

func (s GrantSuggestion) with(cur Grant, g *Grant, reason string) GrantSuggestion {
	s.Changed = Changed(cur, *g)
	if len(s.Changed) == 0 && g.Profile == cur.Profile {
		s.Reason = SuggestReasonAlreadyNarrow
		return s
	}
	s.Profile, s.Grant, s.Reason = g.Profile, g, reason
	return s
}

// candidate builds profile p for cur's sensor, keeping cur's trust level and
// remote actions, or nil when it would widen cur on any dimension.
func candidate(cur Grant, p string, zones []shared.ID) *Grant {
	g, err := NewGrantFromProfile(cur.TenantID, cur.SensorID, p, zones)
	if err != nil {
		return nil
	}
	g.TrustLevel = cur.TrustLevel
	g.RemoteActions = append([]string{}, cur.RemoteActions...)
	g.CreatedAt = cur.CreatedAt
	if err := g.Normalize(); err != nil {
		return nil
	}
	if len(Widened(cur, *g)) > 0 {
		return nil
	}
	return g
}

// covers reports whether g admits every job of u (at the tier the sensor's
// tool contract gives it) and, when the sensor pushed results, push ingest.
func covers(g Grant, u GrantUsage, contracts ContractLookup) bool {
	if u.PushIngest && !g.Effective().AllowPushIngest {
		return false
	}
	for _, j := range u.Jobs {
		c := contracts(JobOf(j.Type, j.Payload).Tool)
		if g.AdmitContract(j.Type, j.Payload, j.ZoneID, c) != nil {
			return false
		}
	}
	return true
}

// suggestZones are the zones a zone-bound profile keeps to: the zones the
// window's jobs ran in and the sensor's assigned zones, inside cur's zone
// limit when it has one; nil (no limit) when there are none and cur has no
// limit either.
func suggestZones(cur Grant, u GrantUsage) []shared.ID {
	var zones []shared.ID
	add := func(z shared.ID) {
		if !slices.Contains(zones, z) && (cur.ZoneIDs == nil || slices.Contains(cur.ZoneIDs, z)) {
			zones = append(zones, z)
		}
	}
	for _, j := range u.Jobs {
		if j.ZoneID != nil {
			add(*j.ZoneID)
		}
	}
	for _, z := range u.AssignedZones {
		add(z)
	}
	if len(zones) == 0 && cur.ZoneIDs != nil {
		return append([]shared.ID{}, cur.ZoneIDs...)
	}
	return zones
}

func summarize(u GrantUsage, contracts ContractLookup) UsageSummary {
	s := UsageSummary{JobCount: u.JobCount, PushIngest: u.PushIngest, Complete: u.Complete, JobTypes: []string{}, Tools: []string{}}
	var zones []shared.ID
	for _, j := range u.Jobs {
		job := JobOf(j.Type, j.Payload)
		if !slices.Contains(s.JobTypes, job.Type) {
			s.JobTypes = append(s.JobTypes, job.Type)
		}
		if job.Tool != "" && !slices.Contains(s.Tools, job.Tool) {
			s.Tools = append(s.Tools, job.Tool)
		}
		if !slices.Contains(controlJobTyp, job.Type) {
			s.MaxTier = max(s.MaxTier, CommandTierFor(job.Type, job, contracts(job.Tool)))
		}
		if j.ZoneID != nil && !slices.Contains(zones, *j.ZoneID) {
			zones = append(zones, *j.ZoneID)
		}
		targets, _ := payloadTargets(j.Payload)
		for _, t := range targets {
			switch {
			case !isNetworkTarget(t):
			case isPrivateTarget(t):
				s.PrivateTargets = true
			default:
				s.PublicTargets = true
			}
		}
	}
	slices.Sort(s.JobTypes)
	slices.Sort(s.Tools)
	s.ZoneCount = len(zones)
	return s
}
