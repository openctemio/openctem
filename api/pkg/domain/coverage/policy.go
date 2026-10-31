package coverage

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Predicates a coverage rule may require (asset-types.yaml `requires`).
const (
	// RequiresResolves: the name has an address: a resolves_to relation,
	// an A/AAAA record its DNS resolution stored, or addresses a probe saw.
	RequiresResolves = "resolves"
	// RequiresWebPort: the open port is one of WebPorts.
	RequiresWebPort = "web_port"
	// RequiresWebPortOrUnscanned: a name is worth an HTTP probe: an
	// address it resolves to has an open port that may carry a web service
	// (IsWebPlausiblePort, or a detected http/https/ssl service on any
	// port), a web origin of
	// the name was seen, or its ports are unknown (no port scan of the name
	// or its addresses has succeeded and none of its addresses has an open
	// port on record). A name whose port scan found no web port is not
	// probed until one appears.
	RequiresWebPortOrUnscanned = "web_port_or_unscanned"
	// RequiresScopeEntry: an active scope entry covers the name.
	RequiresScopeEntry = "scope_entry"
	// RequiresNoNamedTwin: a web service is not only the address form of a
	// named one: its URL host is an IP address, and no active web service
	// reached by a host name serves that address on the same port. A named
	// virtual host or a CDN-fronted application answers its bare address
	// with a default page, so template checks run on the named service and
	// the address twin would only repeat them on the wrong page.
	RequiresNoNamedTwin = "no_named_twin"
)

// WebPorts are the ports an HTTP probe takes from an open port. A web
// service on another port is found by the probe of its name.
var WebPorts = []int{80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443}

// WebAltPorts are further ports that commonly carry a web service (admin
// panels, control panels, application servers, alternate TLS ports). An open
// port in WebAltPorts or in WebAltRangeFrom..WebAltRangeTo makes a name worth
// an HTTP probe (RequiresWebPortOrUnscanned): the probe of the name then
// tries it with the name's Host header and TLS server name, which a scan of
// the address alone cannot. They do not change what a probe takes from a bare
// address (WebPorts).
var WebAltPorts = []int{2082, 2083, 2086, 2087, 2095, 2096, 4443, 7000, 7080, 7443, 8181, 9001, 9080, 9090, 10000, 10443, 12443}

// WebAltRangeFrom and WebAltRangeTo bound the commonly used alternate HTTP
// range 8000-8999 (the SQL form matches the thousand WebAltRangeFrom/1000).
const (
	WebAltRangeFrom = 8000
	WebAltRangeTo   = 8999
)

// WebServiceNamePattern matches (case-insensitively) a service name that a
// port scan detected for a web service: http, https, ssl, http-alt,
// ssl/http, http-proxy and the like.
const WebServiceNamePattern = `^(ssl/)?(https?(-[a-z0-9]+)*|ssl)$`

// IsWebPlausiblePort reports whether an open port, by number alone, may carry
// a web service: WebPorts, WebAltPorts or the 8000-8999 range.
func IsWebPlausiblePort(p int) bool {
	return IsWebPort(p) || slices.Contains(WebAltPorts, p) || (p >= WebAltRangeFrom && p <= WebAltRangeTo)
}

// IsWebPort reports whether p is one of WebPorts.
func IsWebPort(p int) bool { return slices.Contains(WebPorts, p) }

// Rule is one coverage rule of a stored (type, sub-type) pair.
type Rule struct {
	Type       asset.AssetType
	SubType    string // "" = the core type (its non-alias sub-types)
	Capability string
	Every      time.Duration
	Requires   []string
	Expects    string
}

// GapAfter is how long a pair may go without a success before it is a
// coverage gap: twice its cadence.
func (r Rule) GapAfter() time.Duration { return 2 * r.Every }

// Rules returns every coverage rule of the registry, keyed by the stored
// pair it applies to.
func Rules() []Rule {
	var out []Rule
	for _, d := range asset.RegistryDocument().Types {
		t, sub := d.Type, ""
		if d.AliasOf != nil {
			t, sub = d.AliasOf.Type, d.AliasOf.SubType
		}
		for _, c := range d.Coverage {
			out = append(out, Rule{
				Type: t, SubType: sub, Capability: c.Capability,
				Every:    time.Duration(c.EverySeconds) * time.Second,
				Requires: slices.Clone(c.Requires), Expects: c.Expects,
			})
		}
	}
	return out
}

// RulesFor returns the coverage rules of one stored pair.
func RulesFor(t asset.AssetType, subType string) []Rule {
	rs := asset.CoverageRules(t, subType)
	out := make([]Rule, 0, len(rs))
	for _, c := range rs {
		out = append(out, Rule{Type: t, SubType: subType, Capability: c.Capability,
			Every:    time.Duration(c.EverySeconds) * time.Second,
			Requires: slices.Clone(c.Requires), Expects: c.Expects})
	}
	return out
}

// AliasSubTypes returns the sub-types of a core type that are aliases with
// their own coverage list: a core rule does not apply to them.
func AliasSubTypes(t asset.AssetType) []string {
	var out []string
	for _, d := range asset.RegistryDocument().Types {
		if d.AliasOf != nil && d.AliasOf.Type == t && d.AliasOf.SubType != "" {
			out = append(out, d.AliasOf.SubType)
		}
	}
	return out
}

// Entry is one line of an asset's coverage explanation.
type Entry struct {
	Capability    string     `json:"capability"`
	Vantage       string     `json:"vantage,omitempty"`
	State         State      `json:"state"`
	Reason        string     `json:"reason,omitempty"`
	EverySeconds  int        `json:"every_seconds,omitempty"`
	NextDueAt     *time.Time `json:"next_due_at,omitempty"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastOutcome   string     `json:"last_outcome,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	LastTool      string     `json:"last_tool,omitempty"`
	FailStreak    int        `json:"fail_streak,omitempty"`
	// UnreachedFrom names the organization's own scan zone or sensor whose
	// tasks found the target silent, for a pair paused for that (never a
	// platform sensor: "" then, and for any other pair).
	UnreachedFrom string `json:"unreached_from,omitempty"`
	// PlatformSide: the pair failed and its last outcome is platform side
	// (IsPlatformSide): the check did not run, which says nothing about the
	// asset. The asset page shows it as not checked, never as failing.
	PlatformSide bool `json:"platform_side,omitempty"`
	// Gap: the pair applies and has gone without a success for more than
	// twice its cadence (or never succeeded since it was planned that
	// long ago).
	Gap bool `json:"gap"`
}

// AssetView is an asset's coverage: one entry per rule of its type, plus
// any other ledger row of the asset (platform checks, connectors).
type AssetView struct {
	AssetID string  `json:"asset_id"`
	Entries []Entry `json:"entries"`
	Gaps    int     `json:"gaps"`
}

// ReasonNotPlanned marks a rule the ledger has no row for yet.
const ReasonNotPlanned = "not_planned"

// IsGap reports whether a row of a rule is a coverage gap at now.
func IsGap(r Rule, row *Row, now time.Time) bool {
	if r.Every <= 0 || row == nil {
		return false
	}
	switch row.State {
	case StateBlocked, StatePaused, StateNotApplicable:
		return false
	}
	if row.LastOutcome == OutcomeNoAnswer {
		// A name with no address is answered, and parked on its own
		// recheck schedule (also while a recheck runs).
		return false
	}
	since := row.CreatedAt
	if row.LastSuccessAt != nil {
		since = *row.LastSuccessAt
	}
	return now.Sub(since) > r.GapAfter()
}

// View builds an asset's coverage explanation.
func View(assetID shared.ID, rules []Rule, rows []Row, now time.Time) AssetView {
	v := AssetView{AssetID: assetID.String(), Entries: []Entry{}}
	byCap := make(map[string]*Row, len(rows))
	for i := range rows {
		if rows[i].Vantage == VantageInternet {
			byCap[rows[i].Capability] = &rows[i]
		}
	}
	seen := map[string]bool{}
	for _, r := range rules {
		seen[r.Capability] = true
		row := byCap[r.Capability]
		e := Entry{Capability: r.Capability, EverySeconds: int(r.Every / time.Second)}
		if row == nil {
			e.State, e.Reason = StateDue, ReasonNotPlanned
		} else {
			fill(&e, row)
			e.Gap = IsGap(r, row, now)
		}
		if e.Gap {
			v.Gaps++
		}
		v.Entries = append(v.Entries, e)
	}
	for i := range rows {
		if rows[i].Vantage == VantageInternet && seen[rows[i].Capability] {
			continue
		}
		e := Entry{Capability: rows[i].Capability, Vantage: rows[i].Vantage}
		fill(&e, &rows[i])
		v.Entries = append(v.Entries, e)
	}
	return v
}

func fill(e *Entry, row *Row) {
	e.State, e.Reason = row.State, row.Reason
	e.NextDueAt, e.LastAttemptAt, e.LastSuccessAt = row.NextDueAt, row.LastAttemptAt, row.LastSuccessAt
	e.LastOutcome, e.LastError, e.LastTool, e.FailStreak = row.LastOutcome, row.LastError, row.LastTool, row.FailStreak
	e.PlatformSide = row.State == StateFailed && IsPlatformSide(row.LastOutcome)
	if row.State == StatePaused && IsTargetSide(row.Reason) {
		e.UnreachedFrom = row.UnreachedFromName
	}
}

// Repository is the ledger as the coverage service needs it. Every method
// is scoped to one tenant.
type Repository interface {
	// ListForAsset returns every ledger row of an asset.
	ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]Row, error)
	// Reconcile makes the ledger match the policy for one tenant: a missing
	// row of an applicable rule is added as due, a row whose precondition
	// stopped holding becomes not applicable (and due again when it holds
	// again). It returns the rows added and changed.
	Reconcile(ctx context.Context, tenantID shared.ID, rules []Rule) (added, changed int, err error)
	// TenantsWithAssets returns the tenants that have active assets.
	TenantsWithAssets(ctx context.Context) ([]shared.ID, error)
}

// DueTarget is a due pair with what the planner needs to address it.
type DueTarget struct {
	AssetID    shared.ID
	Name       string
	Type       asset.AssetType
	SubType    string
	FailStreak int
	// PlatformFailStreak counts platform-side failures in a row (the check
	// did not run); FailStreak counts those of the target.
	PlatformFailStreak int
	// NeverCovered: the pair has never succeeded (no last success). For
	// subdomain enumeration of a root domain it marks a root still to be
	// onboarded with a deep pass (docs/architecture/asset-coverage.md).
	NeverCovered bool
	// Waited is how long the pair has been due (DueBatch; zero for a pair
	// taken within the lookahead, very long for one never scheduled).
	Waited time.Duration
}

// Target is the scan target of an asset: its name, or "host:port" for an
// open port (stored as "host:port:proto").
func (d DueTarget) Target() string {
	if d.Type == "service" && d.SubType == "open_port" {
		if i := strings.LastIndex(d.Name, ":"); i > 0 {
			if p := d.Name[i+1:]; p == "tcp" || p == "udp" || p == "sctp" {
				return d.Name[:i]
			}
		}
	}
	return d.Name
}

// RunState is the state of a run that holds queued pairs.
type RunState struct {
	RunID      shared.ID
	Capability string
	Status     string
	Error      string
	Tool       string
	// Unfinished are the targets the run did not finish.
	Unfinished []string
	QueuedAt   time.Time
	// NoSensor: a step of the run ended NO_SENSOR (no sensor took its
	// work before the run's deadline).
	NoSensor bool
}

// Run outcomes recorded on settled pairs.
const (
	OutcomeOK       = "ok"
	OutcomeNoOutput = "no_output"
	OutcomeFailed   = "failed"
	OutcomeStalled  = "stalled"
)

// Backoff is how long a failed pair waits before it is due again: one hour
// doubled per consecutive failure, at most the rule's cadence (and never
// more than a day).
func Backoff(every time.Duration, failStreak int) time.Duration {
	d := time.Hour
	for i := 1; i < failStreak && d < 24*time.Hour; i++ {
		d *= 2
	}
	if every > 0 && d > every {
		d = every
	}
	return min(d, 24*time.Hour)
}

// FailedPair is one pair settled as failed.
type FailedPair struct {
	AssetID shared.ID
	Outcome string
	Error   string
	// Observer is who saw a target-side outcome (ObserverKey); "" unknown.
	Observer string
}

// Planner is the ledger as the planner needs it. Every method is scoped to
// one tenant.
type Planner interface {
	// DueBatch returns up to limit pairs of a capability whose time has
	// come (due, failed after its back-off, covered past its cadence,
	// blocked past its recheck), highest priority and oldest first, on
	// active assets. When one of them is due now it also takes pairs due
	// within lookahead; when none is due now it returns nothing.
	DueBatch(ctx context.Context, tenantID shared.ID, capability string, limit int, lookahead time.Duration) ([]DueTarget, error)
	// HasScopeEntries reports whether the tenant has an active scope entry.
	HasScopeEntries(ctx context.Context, tenantID shared.ID) (bool, error)
	// PausedForReadiness returns, per capability, the readiness reason its
	// paused pairs carry.
	PausedForReadiness(ctx context.Context, tenantID shared.ID) (map[string]string, error)
	// PauseForReadiness pauses the capability's pairs whose time has come
	// with a readiness reason; they may resume after retryAfter.
	PauseForReadiness(ctx context.Context, tenantID shared.ID, capability, reason string, retryAfter time.Duration) (int, error)
	// ResumeFromReadiness makes pairs paused for a readiness reason due
	// again once their retry time has passed.
	ResumeFromReadiness(ctx context.Context, tenantID shared.ID, capability string) (int, error)
	// MarkQueued records that the pairs were handed to a run.
	MarkQueued(ctx context.Context, tenantID shared.ID, capability string, assetIDs []shared.ID, runID shared.ID, tool string) error
	// MarkBlocked records that the gate refused the pairs, with its code;
	// they are due again after recheck.
	MarkBlocked(ctx context.Context, tenantID shared.ID, capability string, reasons map[shared.ID]string, recheck time.Duration) error
	// QueuedRuns returns the runs that hold queued pairs of the tenant.
	QueuedRuns(ctx context.Context, tenantID shared.ID) ([]RunState, error)
	// RunTasks returns every task (command) of a run: the ones of its steps
	// (claim-time splits and follow-ups included) and the ones that name the
	// run in their payload.
	RunTasks(ctx context.Context, tenantID, runID shared.ID) ([]TaskResult, error)
	// SettleCovered settles queued pairs of a run as covered (with the
	// output check when expectsOrigin), due again after every.
	SettleCovered(ctx context.Context, tenantID, runID shared.ID, capability string, assetIDs []shared.ID, every time.Duration, expectsOrigin bool) (int, error)
	// SettleFailed settles queued pairs of a run as failed, each with its
	// outcome and error, due again after a back-off bounded by every.
	SettleFailed(ctx context.Context, tenantID, runID shared.ID, capability string, failed []FailedPair, every time.Duration) (int, error)
	// SettleTargetSide settles queued pairs of a run whose target did not
	// answer: paused with the outcome as the reason, the streak counted and
	// rechecked on the TargetSideRecheck schedule.
	SettleTargetSide(ctx context.Context, tenantID, runID shared.ID, capability string, pairs []FailedPair) (int, error)
	// SettleNoAnswer settles queued resolve.dns pairs of a run whose name
	// has no address: covered with OutcomeNoAnswer (the name is parked),
	// the consecutive no-answer streak counted, and rechecked on the
	// DeadNameRechecks schedule.
	SettleNoAnswer(ctx context.Context, tenantID, runID shared.ID, capability string, assetIDs []shared.ID) (int, error)
	// SettleUnresolved settles queued pairs of a run whose target the sensor
	// could not resolve: blocked with the pair's Outcome as the reason
	// (ReasonUnresolvable or ReasonResolverFailed), the streak counted and
	// rechecked on the DeadNameRechecks schedule. Never a failure.
	SettleUnresolved(ctx context.Context, tenantID, runID shared.ID, capability string, pairs []FailedPair) (int, error)
	// QueuedTargets returns the queued pairs a run holds.
	QueuedTargets(ctx context.Context, tenantID, runID shared.ID, capability string) ([]DueTarget, error)
	// AttemptsSince counts the pairs of the tenant attempted since t (the
	// daily budget).
	AttemptsSince(ctx context.Context, tenantID shared.ID, t time.Time) (int, error)
	// RecordRunClaim counts a finished run of the capability: unclaimed
	// (no sensor took it) adds one to the hold's streak, any other run
	// resets it. It returns the new streak.
	RecordRunClaim(ctx context.Context, tenantID shared.ID, capability string, unclaimed bool) (int, error)
	// Holds returns the tenant's holds with a streak, by capability.
	Holds(ctx context.Context, tenantID shared.ID) (map[string]Hold, error)
	// HoldCapability records the hold's fingerprint and probe time and
	// pauses the capability with ReadyNotClaimed until probeAt: its pairs
	// whose time has come, its failed pairs, and pairs paused for another
	// readiness reason.
	HoldCapability(ctx context.Context, tenantID shared.ID, capability, fingerprint string, probeAt time.Time) (int, error)
	// ResumeNow makes the capability's pairs paused for a readiness reason
	// due now, whatever their retry time.
	ResumeNow(ctx context.Context, tenantID shared.ID, capability string) (int, error)
	// FleetFingerprint is a hash of what decides whether the tenant's
	// work can be claimed: its sensors (state, tools, capabilities, local
	// policy), their grants, its zone assignments, its shared-fleet access
	// and the platform sensors' state and tools. Server-side only.
	FleetFingerprint(ctx context.Context, tenantID shared.ID) (string, error)
}

// CapabilityHealth is one tenant's coverage of one capability.
type CapabilityHealth struct {
	Capability string
	// Applicable pairs (not blocked, paused or not applicable).
	Applicable int
	// Gaps: applicable pairs without a success for more than twice the
	// cadence.
	Gaps int
	// Failing: failed pairs whose last 3 or more observations of the
	// target failed and whose last outcome is such an observation
	// (ObservedFailureOutcomes). Platform-side failures never count: the
	// check did not run, so it says nothing about the target.
	Failing int
	// OK and NoOutput: pairs settled in the last 24 h with and without the
	// expected output.
	OK, NoOutput int
	// Paused: pairs paused for a readiness reason; PausedReason is that
	// reason (the planner keeps one per capability).
	Paused       int
	PausedReason string
	// Unreachable: pairs paused because their target did not answer
	// (unreachable, timeout) from the sensors that tried; rechecked on the
	// TargetSideRecheck schedule. They are not counted in Gaps.
	Unreachable int
}

// Alert kinds.
const (
	AlertGap        = "gap"
	AlertOutputDrop = "output_drop"
	AlertFailing    = "failing"
	// AlertUnreachable: targets of the capability did not answer from the
	// organization's sensors (counts only, never the targets).
	AlertUnreachable = "unreachable"
)

// Output-drop and failing thresholds (owner decision D4).
const (
	OutputDropMinInputs = 20
	FailingStreak       = 3
)

// Alerts returns the alert kinds a capability's health raises: a gap; an
// output drop (no expected output over at least 20 settled inputs in a
// day); repeated failures (a pair failed 3 times in a row).
func (h CapabilityHealth) Alerts() []string {
	var out []string
	if h.Gaps > 0 {
		out = append(out, AlertGap)
	}
	if h.OK == 0 && h.NoOutput >= OutputDropMinInputs {
		out = append(out, AlertOutputDrop)
	}
	if h.Failing > 0 {
		out = append(out, AlertFailing)
	}
	if h.Unreachable > 0 {
		out = append(out, AlertUnreachable)
	}
	return out
}

// HealthReader reads a tenant's coverage health.
type HealthReader interface {
	// Health returns one entry per capability of the tenant's ledger;
	// cadence gives the cadence of each capability (a missing one is a day).
	Health(ctx context.Context, tenantID shared.ID, cadence map[string]time.Duration) ([]CapabilityHealth, error)
	// AlertStates returns the tenant's stored alert states.
	AlertStates(ctx context.Context, tenantID shared.ID) ([]AlertState, error)
	// SaveAlertStates upserts alert states of the tenant.
	SaveAlertStates(ctx context.Context, tenantID shared.ID, states []AlertState) error
}
