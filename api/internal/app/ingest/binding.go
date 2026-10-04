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
	"encoding/json"
	"net"
	"net/netip"
	"strings"

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
	// StepRunID is the pipeline step run the bound command belongs to (nil
	// for a command outside a pipeline): the scan run its results came from.
	StepRunID *shared.ID
}

// CommandBinding binds a report to cmd, which the caller has checked is
// assigned to the submitting sensor and open.
func CommandBinding(cmd *command.Command) Binding {
	id := cmd.ID
	return Binding{Kind: BindingCommand, CommandID: &id, Targets: CommandTargets(cmd), Tool: commandTool(cmd), StepRunID: cmd.StepRunID}
}

// TrustedBinding is the binding of a server-side ingest.
func TrustedBinding() Binding { return Binding{Kind: BindingTrusted} }

// String is the binding's audit and response label.
func (b Binding) String() string {
	switch b.Kind {
	case BindingCommand:
		return "command"
	case BindingTrusted:
		return "trusted"
	default:
		return "unsolicited"
	}
}

// unsolicitedRoles are the sensor roles whose job is to push results nobody
// asked for: collectors and CI runners. Their unsolicited reports are applied
// (with the unsolicited limits) whatever the tenant's mode.
var unsolicitedRoles = map[sensor.SensorType]bool{
	sensor.SensorTypeCollector: true,
	sensor.SensorTypeRunner:    true,
}

// RoleMayPushUnsolicited reports whether a sensor of type t may push results
// without a command.
func RoleMayPushUnsolicited(t sensor.SensorType) bool { return unsolicitedRoles[t] }

// CommandTargets are the targets a command's payload names ("targets" and
// "target", the keys sensors read), trimmed and de-duplicated.
func CommandTargets(cmd *command.Command) []string {
	if cmd == nil || len(cmd.Payload) == 0 {
		return nil
	}
	var p struct {
		Targets []any `json:"targets"`
		Target  any   `json:"target"`
	}
	if json.Unmarshal(cmd.Payload, &p) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v any) {
		s, ok := v.(string)
		if !ok {
			return
		}
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, t := range p.Targets {
		add(t)
	}
	add(p.Target)
	return out
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

// alterScope decides which existing assets one ingest may change, and so
// which human-resolved findings it may reopen. It is filled while the
// report's assets are processed.
type alterScope struct {
	all bool
	// commandBound: the report names a command assigned to the submitting
	// sensor (BindingCommand). Only such reports may resolve findings on a
	// source's say-so (source_resolve.go).
	commandBound bool
	targets      []coverTarget
	// allowed are the persisted ids of the assets this report may change:
	// those it created and the existing ones its command covers.
	allowed map[shared.ID]bool
	// actor, when set, is the data scope of the person behind an upload
	// (Options.Actor): it reports whether they may change an existing asset.
	actor func(shared.ID) bool
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
	if len(s.targets) == 0 || a == nil {
		return false
	}
	locators := [][2]string{}
	host, path := parseLocator(a.Name())
	locators = append(locators, [2]string{host, path})
	for _, ip := range ExtractAllIPs(a.Properties(), a.Name()) {
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
