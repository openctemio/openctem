package ingest

// Result binding (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.3,
// owner decision Q6 (a)): which existing objects a sensor report may change.
//
// A report is bound when it names a command assigned to the submitting sensor
// and still open; it may then change the existing assets the command's
// targets cover, and reopen findings a person resolved on them. Anything else
// a sensor sends is unsolicited: it may create assets and findings and update
// open findings, but it never changes an existing asset (flags, exposure,
// classification, ownership, status, name) and never reopens a finding a
// person resolved.

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// BindingKind is where a report's authority comes from.
type BindingKind int

const (
	// BindingUnsolicited: a sensor report that names no command (the zero
	// value, so a caller that says nothing gets the limited behavior).
	BindingUnsolicited BindingKind = iota
	// BindingCommand: a report for a command assigned to the submitting
	// sensor and open when the report arrived.
	BindingCommand
	// BindingTrusted: not a sensor report: a tenant upload, a platform
	// import, or a quarantined report a person accepted.
	BindingTrusted
	// BindingCIRun: a report uploaded with a CI run's token (RFC-051). The
	// run was admitted by the tenant's trust configuration for exactly one
	// repository; the report may change that repository asset and nothing
	// else, and never resolves findings on a source's say-so.
	BindingCIRun
)

// Binding is the authority behind a report.
type Binding struct {
	Kind BindingKind
	// CommandID is the bound command (BindingCommand only).
	CommandID *shared.ID
	// Targets are the bound command's targets: the scope inside which the
	// report may change existing assets.
	Targets []string
	// Tool is the bound command's tool ("" when it names none); a bound
	// report must be from that tool.
	Tool string
	// CommandType is the bound command's type (BindingCommand only).
	CommandType command.CommandType
	// StepRunID is the workflow step run the bound command belongs to (nil
	// for a command outside a scan run): the scan run its results came from.
	StepRunID *shared.ID
	// CIRunID is the CI run the report belongs to (BindingCIRun only).
	CIRunID *shared.ID
	// DispatchedAt is when the bound command was handed to the sensor
	// (BindingCommand only): the report cannot have observed anything
	// earlier, so its timestamp is clamped up to it.
	DispatchedAt time.Time
	// JobPorts and JobTopPorts are the bound command's port settings
	// (BindingCommand only): what a port scan covered.
	JobPorts, JobTopPorts string
}

// Run is the scan task or CI run the report belongs to ("" for none).
func (b Binding) Run() string {
	switch {
	case b.CommandID != nil:
		return b.CommandID.String()
	case b.CIRunID != nil:
		return b.CIRunID.String()
	}
	return ""
}

// CommandBinding binds a report to cmd, which the caller has checked is
// assigned to the submitting sensor and open.
func CommandBinding(cmd *command.Command) Binding {
	id := cmd.ID
	dispatched := cmd.CreatedAt
	if cmd.AcknowledgedAt != nil {
		dispatched = *cmd.AcknowledgedAt
	}
	ports, top := command.PayloadPortSettings(cmd.Payload)
	return Binding{Kind: BindingCommand, CommandID: &id, Targets: CommandTargets(cmd), Tool: commandTool(cmd),
		CommandType: cmd.Type, StepRunID: cmd.StepRunID, DispatchedAt: dispatched, JobPorts: ports, JobTopPorts: top}
}

// TrustedBinding is the binding of a server-side ingest.
func TrustedBinding() Binding { return Binding{Kind: BindingTrusted} }

// CIRunBinding binds a report to a CI run on one repository (RFC-051).
func CIRunBinding(runID shared.ID, repository string) Binding {
	id := runID
	return Binding{Kind: BindingCIRun, CIRunID: &id, Targets: []string{repository}}
}

// String is the binding's audit and response label.
func (b Binding) String() string {
	switch b.Kind {
	case BindingCommand:
		return "command"
	case BindingTrusted:
		return "trusted"
	case BindingCIRun:
		return "ci_run"
	default:
		return "unsolicited"
	}
}

// unsolicitedRoles are the sensor roles whose job is to push results nobody
// asked for: collectors. Their unsolicited reports are applied (with the
// unsolicited limits) whatever the tenant's mode. CI runs are not sensors and
// never reach this gate (they use the ci_run binding).
var unsolicitedRoles = map[sensor.SensorType]bool{
	sensor.SensorTypeCollector: true,
}

// RoleMayPushUnsolicited reports whether a sensor of type t may push results
// without a command.
func RoleMayPushUnsolicited(t sensor.SensorType) bool { return unsolicitedRoles[t] }

// CommandTargets are the targets a command's payload names ("targets" and
// "target", the keys sensors read), trimmed and de-duplicated.
func CommandTargets(cmd *command.Command) []string {
	if cmd == nil {
		return nil
	}
	return command.PayloadTargets(cmd.Payload)
}

// coverTarget is one command target, parsed once.
type coverTarget struct {
	host   string // lower-case host or IP, no port, no trailing dot
	path   string // lower-case path without trailing "/" or ".git"
	prefix *netip.Prefix
}

// parseLocator splits a target or asset name ("https://Host:443/a/b.git",
// "host/a", "10.0.0.0/24", "git@host:org/repo") into host and path.
func parseLocator(s string) (host, path string) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 && !strings.Contains(s[:at], "/") {
		s = s[at+1:] // user@host...
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	host, path = s, ""
	if i := strings.Index(s, "/"); i >= 0 {
		host, path = s[:i], s[i:]
	}
	// git@host:org/repo (scp-like): a colon followed by a non-port.
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") && strings.Count(host, ":") == 1 {
		rest := host[i+1:]
		if rest != "" && strings.Trim(rest, "0123456789") != "" {
			path = "/" + rest + path
		}
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	path = strings.TrimSuffix(strings.TrimSuffix(path, "/"), ".git")
	return host, path
}

func newCoverTargets(targets []string) []coverTarget {
	out := make([]coverTarget, 0, len(targets))
	for _, t := range targets {
		if p, err := netip.ParsePrefix(strings.TrimSpace(t)); err == nil {
			pp := p.Masked()
			out = append(out, coverTarget{prefix: &pp})
			continue
		}
		host, path := parseLocator(t)
		if host == "" {
			continue
		}
		out = append(out, coverTarget{host: host, path: path})
	}
	return out
}

// coversLocator reports whether the target covers a host (and path).
func (t coverTarget) coversLocator(host, path string) bool {
	if t.prefix != nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return t.prefix.Contains(ip.Unmap())
		}
		return false
	}
	switch {
	case host == t.host:
		// A host-only target covers the whole host, and a host-level asset
		// (no path) is covered by any target on its host; an asset with a
		// path (a repository) must be the target's path or below it.
		return t.path == "" || path == "" || path == t.path || strings.HasPrefix(path, t.path+"/")
	case t.path == "" && strings.HasSuffix(host, "."+t.host):
		// A subdomain of a domain target.
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if tip, err := netip.ParseAddr(t.host); err == nil {
			return ip.Unmap() == tip.Unmap()
		}
	}
	return false
}

// namesLocator reports whether the target is this host (and path) itself,
// or a range that contains this address. A subdomain of a domain target is
// covered (coversLocator) but not named.
func (t coverTarget) namesLocator(host, path string) bool {
	if t.prefix != nil {
		return t.coversLocator(host, path)
	}
	if host == t.host {
		return t.path == "" || path == t.path
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if tip, err := netip.ParseAddr(t.host); err == nil {
			return ip.Unmap() == tip.Unmap()
		}
	}
	return false
}

// alterScope decides which existing assets one ingest may change, and so
// which human-resolved findings it may reopen. It is filled while the
// report's assets are processed.
type alterScope struct {
	all bool
	// commandBound: the report names a command assigned to the submitting
	// sensor (BindingCommand). Only such reports may resolve findings on a
	// source's say-so (source_resolve.go).
	commandBound bool
	// commandTool and commandType are the bound command's tool and type
	// (BindingCommand only): what a source-asserted resolve must match.
	commandTool string
	commandType command.CommandType
	targets     []coverTarget
	// allowed are the persisted ids of the assets this report may change:
	// those it created and the existing ones its command covers.
	allowed map[shared.ID]bool
	// actor, when set, is the data scope of the person behind an upload
	// (Options.Actor): it reports whether they may change an existing asset.
	actor func(shared.ID) bool
	// seen are the persisted assets this ingest created or updated, by id:
	// whether it created them and their stored name and type. Attribution
	// (scan_attribution.go) reads them.
	seen map[shared.ID]seenAsset
	// untrusted are the tracked attributes the report's source may not
	// decide (RFC-069): an asset it creates does not take its claims.
	untrusted map[asset.TrackedAttribute]bool
}

// dropUntrustedClaims clears, on an asset this report creates, the tracked
// values its source is not trusted for. Criticality and exposure keep the
// creation value (an asset needs one); later reports of an untrusted
// source never change them.
func (s *alterScope) dropUntrustedClaims(a *asset.Asset) {
	if s == nil || a == nil {
		return
	}
	if s.untrusted[asset.AttrOwnerRef] {
		a.SetOwnerRef("")
	}
	if s.untrusted[asset.AttrDataClassification] {
		_ = a.SetDataClassification("")
	}
}

// seenAsset is one asset an ingest wrote.
type seenAsset struct {
	created bool
	name    string
	typ     asset.TypeRef
}

// note records an asset this ingest created or updated.
func (s *alterScope) note(a *asset.Asset, id shared.ID, created bool) {
	if s == nil || a == nil || id.IsZero() {
		return
	}
	if s.seen == nil {
		s.seen = map[shared.ID]seenAsset{}
	}
	prev, had := s.seen[id]
	s.seen[id] = seenAsset{created: created || (had && prev.created), name: a.Name(),
		typ: asset.TypeRef{Type: a.Type(), SubType: a.SubType()}}
}

// typedTarget reports whether an asset name is one of the bound command's
// targets itself (the same host, the same repository path, or an address
// inside a range the tenant listed), not a name found under one: what the
// tenant typed (research/22 E7).
func (s *alterScope) typedTarget(name string) bool {
	if s == nil || len(s.targets) == 0 {
		return false
	}
	host, path := parseLocator(name)
	for _, t := range s.targets {
		if t.namesLocator(host, path) {
			return true
		}
	}
	return false
}

// withActor limits the scope to the assets the upload's actor may change.
// Each decision is looked up once; a lookup error denies (fail closed).
func (s *alterScope) withActor(ctx context.Context, a ActorScope) *alterScope {
	if a == nil {
		return s
	}
	memo := map[shared.ID]bool{}
	s.actor = func(id shared.ID) bool {
		if ok, seen := memo[id]; seen {
			return ok
		}
		ids, err := a.AssetsInScope(ctx, []shared.ID{id})
		ok := err == nil && len(ids) == 1 && ids[0] == id
		memo[id] = ok
		return ok
	}
	return s
}

// actorRestricted reports whether an upload's actor limits this ingest.
func (s *alterScope) actorRestricted() bool { return s != nil && s.actor != nil }

// actorDenies reports whether the upload's actor may not change asset id.
func (s *alterScope) actorDenies(id shared.ID) bool {
	return s != nil && s.actor != nil && !s.actor(id)
}

// skipOutOfScope records a report asset the upload's actor may not change.
func skipOutOfScope(output *Output, ref string) {
	output.AssetsSkippedOutOfScope++
	if ref != "" {
		if output.OutOfScopeAssetRefs == nil {
			output.OutOfScopeAssetRefs = map[string]bool{}
		}
		output.OutOfScopeAssetRefs[ref] = true
	}
}

func newAlterScope(b Binding) *alterScope {
	s := &alterScope{allowed: map[shared.ID]bool{}}
	switch b.Kind {
	case BindingTrusted:
		s.all = true
	case BindingCommand:
		s.targets = newCoverTargets(b.Targets)
		s.commandBound = true
		s.commandTool, s.commandType = b.Tool, b.CommandType
	case BindingCIRun:
		s.targets = newCoverTargets(b.Targets)
	}
	return s
}

// fullScope is the scope of the trusted, public entry points.
func fullScope() *alterScope { return &alterScope{all: true, allowed: map[shared.ID]bool{}} }

// mayAlter reports whether the report may change the existing asset a.
func (s *alterScope) mayAlter(a *asset.Asset) bool {
	if a != nil && s.actorDenies(a.ID()) {
		return false
	}
	if s == nil || s.all {
		return true
	}
	if a == nil {
		return false
	}
	return s.coversLocated(a.Name(), a.Properties())
}

// coversLocated reports whether a target covers an asset with this name and
// these properties (its name, or one of its IP addresses).
func (s *alterScope) coversLocated(name string, properties map[string]any) bool {
	if s == nil || len(s.targets) == 0 {
		return false
	}
	locators := [][2]string{}
	host, path := parseLocator(name)
	locators = append(locators, [2]string{host, path})
	for _, ip := range ExtractAllIPs(properties, name) {
		locators = append(locators, [2]string{strings.ToLower(ip), ""})
	}
	for _, t := range s.targets {
		for _, l := range locators {
			if t.coversLocator(l[0], l[1]) {
				return true
			}
		}
	}
	return false
}

func (s *alterScope) allow(id shared.ID) {
	if s != nil && !id.IsZero() {
		s.allowed[id] = true
	}
}

// allowedAsset reports whether findings on the persisted asset id may be
// reopened after a person resolved them.
func (s *alterScope) allowedAsset(id shared.ID) bool {
	if s.actorDenies(id) {
		return false
	}
	return s == nil || s.all || s.allowed[id]
}
