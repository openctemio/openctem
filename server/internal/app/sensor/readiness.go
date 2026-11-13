package sensor

// Sensor readiness (research/466 D10; docs/architecture/sensor-readiness.md):
// one checklist of what still stops a sensor from scanning, in the order a
// person fixes it, each item with the one action that fixes it and the
// permission that action needs. It reads only what the platform already
// knows (the sensor row, its grant, its last local policy report, the
// organization's zones and scope, its setup checklist) and changes nothing.
// Every gate keeps its own page and its own audit; the checklist only points
// at them.

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/pagination"
)

// Readiness item keys, in fix order.
const (
	ReadyOnline   = "online"
	ReadyTrusted  = "trusted"
	ReadyPrivate  = "private_targets"
	ReadyKill     = "kill_switch"
	ReadyNetworks = "networks"
	ReadyScope    = "scope"
	ReadySandbox  = "sandbox"
)

// Item states.
const (
	ReadyStateOK      = "ok"
	ReadyStateBlocked = "blocked"
	// ReadyStateWaiting: nothing to do but wait (the first heartbeat, a
	// scope entry another person must approve).
	ReadyStateWaiting = "waiting"
	// ReadyStateUnknown: the sensor did not report it (yet).
	ReadyStateUnknown = "unknown"
	// ReadyStateNotApplicable: the item does not apply to this sensor (an
	// internet-only sensor needs no private networks).
	ReadyStateNotApplicable = "not_applicable"
)

// Fix actions (the console maps each to one button).
const (
	FixShowInstall   = "show_install"
	FixPromote       = "promote"
	FixEnablePrivate = "enable_private"
	FixKillSwitchOff = "kill_switch_off"
	FixAddZone       = "add_zone"
	FixAddScope      = "add_scope"
	FixSandboxDocs   = "sandbox_docs"
)

// HostRequirementsDocs is the guide the sandbox fix links to.
const HostRequirementsDocs = "https://docs.openctem.io/sensors/host-requirements/"

// Permissions the fixes need (permission strings, kept here so the app
// layer does not import the permission catalog).
const (
	permGrantWiden = "sensors:grant:widen"
	permZonesWrite = "sensors:zones:write"
	permZonesRead  = "sensors:zones:read"
	permScopeWrite = "attack_surface:scope:write"
)

// ReadinessFix is the one action that clears an item.
type ReadinessFix struct {
	Action string `json:"action" enums:"show_install,promote,enable_private,kill_switch_off,add_zone,add_scope,sandbox_docs"`
	// Permission is what the action needs in the console ("" for a step on
	// the sensor's host, done by the host owner).
	Permission string `json:"permission,omitempty"`
	// Allowed: the caller holds Permission (always true without one).
	Allowed bool `json:"allowed"`
	// Patterns are the ranges the fix acts on (add_zone, add_scope).
	Patterns []string `json:"patterns,omitempty"`
	// HostLine is the line or command for the host owner (enable_private,
	// kill_switch_off).
	HostLine string `json:"host_line,omitempty"`
	// Docs links the guide (sandbox_docs).
	Docs string `json:"docs,omitempty"`
}

// ReadinessItem is one line of the checklist.
type ReadinessItem struct {
	Key   string `json:"key" enums:"online,trusted,private_targets,kill_switch,networks,scope,sandbox"`
	State string `json:"state" enums:"ok,blocked,waiting,unknown,not_applicable"`
	// Count is the number of things the item counts: zones assigned
	// (networks), ranges not in scope or awaiting approval (scope).
	Count int           `json:"count,omitempty"`
	Fix   *ReadinessFix `json:"fix,omitempty"`
}

// Readiness is the checklist of one sensor.
type Readiness struct {
	SensorID string `json:"sensor_id"`
	// Ready: no item is blocked, waiting or unknown.
	Ready bool            `json:"ready"`
	Items []ReadinessItem `json:"items"`
} // @name SensorReadiness

// ReadinessGrants reads a sensor's grant.
type ReadinessGrants interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error)
}

// ReadinessZones lists the organization's zones.
type ReadinessZones interface {
	List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error)
}

// ReadinessScope lists the organization's scope entries of some statuses.
type ReadinessScope interface {
	ListByStatus(ctx context.Context, tenantID shared.ID, statuses []scopedom.Status) ([]*scopedom.Target, error)
}

// ReadinessCaller is who asks: the permissions that decide Allowed, and
// whether they may see the host's setup checklist (sensors:write).
type ReadinessCaller struct {
	Has          func(permission string) bool
	SeesHostInfo bool
}

// ReadinessService builds the checklist.
type ReadinessService struct {
	sensors *SensorService
	grants  ReadinessGrants
	zones   ReadinessZones
	scope   ReadinessScope
}

// NewReadinessService builds the service; grants, zones and scope may be
// nil (their items then read unknown).
func NewReadinessService(sensors *SensorService, grants ReadinessGrants, zones ReadinessZones, scope ReadinessScope) *ReadinessService {
	return &ReadinessService{sensors: sensors, grants: grants, zones: zones, scope: scope}
}

// Readiness returns the checklist of a sensor of the tenant. A sensor of
// another tenant, or a shared one, is shared.ErrNotFound.
func (s *ReadinessService) Readiness(ctx context.Context, tenantID, sensorID string, caller ReadinessCaller) (*Readiness, error) {
	sen, err := s.sensors.GetSensor(ctx, tenantID, sensorID)
	if err != nil {
		return nil, err
	}
	if sen.TenantID == nil || sen.TenantID.String() != tenantID {
		return nil, shared.ErrNotFound
	}
	in := ReadinessInput{Sensor: sen}
	if s.grants != nil {
		if in.Grant, err = s.grants.Get(ctx, *sen.TenantID, sen.ID); err != nil && !errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
	}
	if s.zones != nil {
		if in.Zones, err = s.zones.List(ctx, *sen.TenantID); err != nil {
			return nil, err
		}
		in.ZonesKnown = true
	}
	if s.scope != nil {
		entries, err := s.scope.ListByStatus(ctx, *sen.TenantID, []scopedom.Status{scopedom.StatusActive, scopedom.StatusPending})
		if err != nil && !errors.Is(err, ErrTooManyScopeEntries) {
			return nil, err
		}
		in.ScopeKnown = err == nil
		for _, e := range entries {
			if e.Status() == scopedom.StatusPending {
				in.PendingScope = append(in.PendingScope, e)
			} else {
				in.ActiveScope = append(in.ActiveScope, e)
			}
		}
	}
	if caller.SeesHostInfo {
		if v, err := s.sensors.ConfigReport(ctx, tenantID, sensorID); err == nil {
			in.ConfigChecks = make([]sensordom.ConfigCheck, 0, len(v.Checks))
			for _, c := range v.Checks {
				in.ConfigChecks = append(in.ConfigChecks, c.Check)
			}
			in.ConfigKnown = v.State != ConfigReportStateNone
		}
	}
	r := BuildReadiness(in, caller.Has)
	return &r, nil
}

// ReadinessInput is everything the checklist is computed from.
type ReadinessInput struct {
	Sensor       *sensordom.Sensor
	Grant        *sensordom.Grant
	Zones        []*scanzone.Zone
	ZonesKnown   bool
	ActiveScope  []*scopedom.Target
	PendingScope []*scopedom.Target
	ScopeKnown   bool
	ConfigChecks []sensordom.ConfigCheck
	ConfigKnown  bool
}

// scansInternal reports whether the sensor's grant may scan private
// networks: a grant limited to public targets or to none never does.
func scansInternal(g *sensordom.Grant) bool {
	return g != nil && g.TargetNetwork == sensordom.TargetNetworkAny && slices.Contains(g.JobTypes, "scan")
}

// sandboxCheckID is the setup check that says whether tool runs are
// network-confined on the host.
const sandboxCheckID = "runtime.sandbox_network"

// privateHostLine and killSwitchHostLine are what the host owner runs.
const (
	privateHostLine = "SENSOR_ALLOW_PRIVATE_TARGETS=1"
	// The stop file's path is the sensor's setting (SENSOR_KILL_SWITCH_FILE)
	// and is not reported to the platform, so the text names no path.
	killSwitchHostLine = "remove the STOP file the sensor reads at SENSOR_KILL_SWITCH_FILE"
)

// readinessFixer builds fixes with Allowed from the caller's permissions.
type readinessFixer func(permission string) bool

func (has readinessFixer) fix(action, perm string) *ReadinessFix {
	return &ReadinessFix{Action: action, Permission: perm, Allowed: perm == "" || (has != nil && has(perm))}
}

// BuildReadiness computes the checklist (pure; has may be nil: nothing is
// allowed).
func BuildReadiness(in ReadinessInput, has func(string) bool) Readiness {
	fx := readinessFixer(has)
	sen := in.Sensor
	internal := scansInternal(in.Grant)
	mine, ranges := sensorZones(in.Zones, sen.ID)
	needsPrivate := internal || len(ranges) > 0
	out := Readiness{SensorID: sen.ID.String(), Items: []ReadinessItem{
		onlineItem(sen, fx),
		trustedItem(in.Grant, fx),
		privateItem(sen.LocalPolicy, needsPrivate),
		killSwitchItem(sen.LocalPolicy),
		networksItem(in.ZonesKnown, internal, len(mine), fx),
		scopeItem(in, ranges, fx),
		sandboxItem(in),
	}}
	out.Ready = true
	for _, it := range out.Items {
		// The sandbox only limits jobs that need confinement; an unknown
		// one (a caller who may not see host details) does not block.
		if it.Key == ReadySandbox && it.State == ReadyStateUnknown {
			continue
		}
		if it.State == ReadyStateBlocked || it.State == ReadyStateWaiting || it.State == ReadyStateUnknown {
			out.Ready = false
		}
	}
	return out
}

// sensorZones are the zones the sensor is assigned to and their private
// ranges.
func sensorZones(zones []*scanzone.Zone, sensorID shared.ID) ([]*scanzone.Zone, []netip.Prefix) {
	var mine []*scanzone.Zone
	var ranges []netip.Prefix
	for _, z := range zones {
		if z == nil || !z.HasSensor(sensorID) {
			continue
		}
		mine = append(mine, z)
		for _, p := range z.Ranges {
			if scanzone.IsPrivate(p.Addr()) && !slices.Contains(ranges, p) {
				ranges = append(ranges, p)
			}
		}
	}
	return mine, ranges
}

func onlineItem(sen *sensordom.Sensor, fx readinessFixer) ReadinessItem {
	switch {
	case sen.Status != sensordom.SensorStatusActive:
		return ReadinessItem{Key: ReadyOnline, State: ReadyStateBlocked}
	case sen.LastSeenAt == nil:
		return ReadinessItem{Key: ReadyOnline, State: ReadyStateWaiting, Fix: fx.fix(FixShowInstall, "")}
	case sen.Health == sensordom.SensorHealthOnline || sen.Health == sensordom.SensorHealthLate:
		return ReadinessItem{Key: ReadyOnline, State: ReadyStateOK}
	default:
		return ReadinessItem{Key: ReadyOnline, State: ReadyStateBlocked, Fix: fx.fix(FixShowInstall, "")}
	}
}

func trustedItem(g *sensordom.Grant, fx readinessFixer) ReadinessItem {
	switch {
	case g == nil:
		return ReadinessItem{Key: ReadyTrusted, State: ReadyStateUnknown}
	case g.TrustLevel == sensordom.TrustTrusted:
		return ReadinessItem{Key: ReadyTrusted, State: ReadyStateOK}
	default:
		return ReadinessItem{Key: ReadyTrusted, State: ReadyStateBlocked, Fix: fx.fix(FixPromote, permGrantWiden)}
	}
}

// privateItem: the host allows private targets (only its owner can change
// it). The sensor reports the switch only inside an enforced policy's
// summary; without one the platform cannot tell.
func privateItem(lp *sensordom.LocalPolicyReport, needed bool) ReadinessItem {
	hostFix := &ReadinessFix{Action: FixEnablePrivate, Allowed: true, HostLine: privateHostLine}
	switch {
	case !needed:
		return ReadinessItem{Key: ReadyPrivate, State: ReadyStateNotApplicable}
	case lp != nil && lp.Summary != nil && lp.Summary.AllowPrivate:
		return ReadinessItem{Key: ReadyPrivate, State: ReadyStateOK}
	case lp != nil && lp.Summary != nil:
		return ReadinessItem{Key: ReadyPrivate, State: ReadyStateBlocked, Fix: hostFix}
	default:
		return ReadinessItem{Key: ReadyPrivate, State: ReadyStateUnknown, Fix: hostFix}
	}
}

func killSwitchItem(lp *sensordom.LocalPolicyReport) ReadinessItem {
	switch {
	case lp == nil:
		return ReadinessItem{Key: ReadyKill, State: ReadyStateUnknown}
	case lp.KillSwitch:
		return ReadinessItem{Key: ReadyKill, State: ReadyStateBlocked,
			Fix: &ReadinessFix{Action: FixKillSwitchOff, Allowed: true, HostLine: killSwitchHostLine}}
	default:
		return ReadinessItem{Key: ReadyKill, State: ReadyStateOK}
	}
}

func networksItem(known, internal bool, zones int, fx readinessFixer) ReadinessItem {
	switch {
	case !internal && zones == 0:
		return ReadinessItem{Key: ReadyNetworks, State: ReadyStateNotApplicable}
	case !known:
		return ReadinessItem{Key: ReadyNetworks, State: ReadyStateUnknown}
	case zones == 0:
		return ReadinessItem{Key: ReadyNetworks, State: ReadyStateBlocked, Fix: fx.fix(FixAddZone, permZonesWrite)}
	default:
		return ReadinessItem{Key: ReadyNetworks, State: ReadyStateOK, Count: zones}
	}
}

// scopeItem: the zone ranges are in scope, or wait for someone's approval.
func scopeItem(in ReadinessInput, ranges []netip.Prefix, fx readinessFixer) ReadinessItem {
	if len(ranges) == 0 {
		return ReadinessItem{Key: ReadyScope, State: ReadyStateNotApplicable}
	}
	if !in.ScopeKnown {
		return ReadinessItem{Key: ReadyScope, State: ReadyStateUnknown}
	}
	var missing []string
	waiting := 0
	for _, p := range ranges {
		switch {
		case coveredBy(p, in.ActiveScope):
		case coveredBy(p, in.PendingScope):
			waiting++
		default:
			missing = append(missing, p.String())
		}
	}
	switch {
	case len(missing) > 0:
		f := fx.fix(FixAddScope, permScopeWrite)
		// The ranges are the zones' private networks: only a caller who
		// may read zones gets them; the others get the count.
		if fx != nil && fx(permZonesRead) {
			f.Patterns = missing
		}
		return ReadinessItem{Key: ReadyScope, State: ReadyStateBlocked, Count: len(missing), Fix: f}
	case waiting > 0:
		return ReadinessItem{Key: ReadyScope, State: ReadyStateWaiting, Count: waiting}
	default:
		return ReadinessItem{Key: ReadyScope, State: ReadyStateOK}
	}
}

// sandboxItem: tool confinement on the host (the setup checklist, read for
// owners and administrators only).
func sandboxItem(in ReadinessInput) ReadinessItem {
	if !in.ConfigKnown {
		return ReadinessItem{Key: ReadySandbox, State: ReadyStateUnknown}
	}
	for _, c := range in.ConfigChecks {
		if c.ID == sandboxCheckID && (c.Status == sensordom.CheckFail || c.Status == sensordom.CheckWarn) {
			return ReadinessItem{Key: ReadySandbox, State: ReadyStateBlocked,
				Fix: &ReadinessFix{Action: FixSandboxDocs, Allowed: true, Docs: HostRequirementsDocs}}
		}
	}
	return ReadinessItem{Key: ReadySandbox, State: ReadyStateOK}
}

// coveredBy reports whether one scope entry covers every address of p.
func coveredBy(p netip.Prefix, entries []*scopedom.Target) bool {
	for _, e := range entries {
		switch e.TargetType() {
		case scopedom.TargetTypeCIDR, scopedom.TargetTypeIPAddress, scopedom.TargetTypeIPRange:
		default:
			continue
		}
		ps, err := scanzone.ParseRanges([]string{e.Pattern()})
		if err != nil {
			continue
		}
		for _, q := range ps {
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				return true
			}
		}
	}
	return false
}

// ScopeTargetLister is the scope entry list ScopeByStatus pages through.
type ScopeTargetLister interface {
	List(ctx context.Context, filter scopedom.TargetFilter, page pagination.Pagination) (pagination.Result[*scopedom.Target], error)
}

// MaxReadinessScopeEntries bounds how many address entries the checklist
// reads; an organization with more reads "unknown" rather than a guess.
const MaxReadinessScopeEntries = 2000

// ErrTooManyScopeEntries: the organization has more address entries than
// the checklist reads.
var ErrTooManyScopeEntries = errors.New("too many scope entries for the readiness check")

// ScopeByStatus adapts the scope entry repository to ReadinessScope: the
// organization's address entries (IP, range, CIDR) of the statuses.
type ScopeByStatus struct{ Repo ScopeTargetLister }

// ListByStatus implements ReadinessScope.
func (a ScopeByStatus) ListByStatus(ctx context.Context, tenantID shared.ID, statuses []scopedom.Status) ([]*scopedom.Target, error) {
	tid := tenantID.String()
	filter := scopedom.TargetFilter{TenantID: &tid, Statuses: statuses,
		TargetTypes: []scopedom.TargetType{scopedom.TargetTypeCIDR, scopedom.TargetTypeIPAddress, scopedom.TargetTypeIPRange}}
	var out []*scopedom.Target
	for page := 1; ; page++ {
		res, err := a.Repo.List(ctx, filter, pagination.New(page, 100))
		if err != nil {
			return nil, err
		}
		out = append(out, res.Data...)
		if len(out) > MaxReadinessScopeEntries {
			return nil, ErrTooManyScopeEntries
		}
		if len(res.Data) < 100 || page >= res.TotalPages {
			return out, nil
		}
	}
}
