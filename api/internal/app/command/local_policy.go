package command

// The sensor-local policy on the platform side (RFC-040 §5.7): the jobs a
// sensor refused under its policy are reported (detection A11), and a
// tenant can keep jobs with private targets away from sensors that run
// without a policy (owner decision Q3 (a)).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RefusalObserver is told about every command a sensor failed; it acts on
// those its local policy refused. Satisfied by the sensor service.
type RefusalObserver interface {
	ObserveLocalPolicyRefusal(ctx context.Context, tenantID, sensorID shared.ID, commandID, errorMessage string)
}

// WithRefusalObserver reports failed commands to o (sensor timeline and
// audit for local-policy refusals).
func WithRefusalObserver(o RefusalObserver) Option {
	return func(s *Service) { s.refusals = o }
}

// PrivateTargetPolicy says whether a tenant keeps jobs with private targets
// away from sensors that report no enforced local policy. Satisfied by the
// tenant service.
type PrivateTargetPolicy interface {
	RequiresLocalPolicyForPrivateTargets(ctx context.Context, tenantID shared.ID) (bool, error)
}

// WithPrivateTargetPolicy makes Poll and Acknowledge apply p.
func WithPrivateTargetPolicy(p PrivateTargetPolicy) Option {
	return func(s *Service) { s.privatePolicy = p }
}

// ErrLocalPolicyRequired: the command names private targets, the tenant
// requires a local policy for them, and the claiming sensor enforces none.
// It wraps ErrCommandClaimed and shared.ErrConflict, so a sensor is told
// "claimed" (v2 command-claimed, v1 409) and the command stays pending for
// one that qualifies.
var ErrLocalPolicyRequired = fmt.Errorf("%w (%w): private targets need a sensor with a local policy", ErrCommandClaimed, shared.ErrConflict)

// withholdPrivate reports whether this sensor must not get commands with
// private targets: the tenant requires a local policy for them and the
// sensor enforces none. Errors fail closed (withhold).
func (s *Service) withholdPrivate(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) bool {
	if s.privatePolicy == nil || sensorID == nil {
		return false
	}
	required, err := s.privatePolicy.RequiresLocalPolicyForPrivateTargets(ctx, tenantID)
	if err != nil {
		s.logger.Warn("cannot read the tenant's private-target policy; withholding private targets",
			"tenant_id", tenantID.String(), "error", err)
		return true
	}
	if !required {
		return false
	}
	if s.sensors == nil {
		return true
	}
	a, err := s.sensors.GetByTenantAndID(ctx, tenantID, *sensorID)
	if err != nil || a == nil {
		return true
	}
	return !a.LocalPolicy.Enforced() || a.LocalPolicy.KillSwitch
}

// anyPrivateTarget reports whether a command of cmds names private targets.
func anyPrivateTarget(cmds []*commanddom.Command) bool {
	for _, c := range cmds {
		if HasPrivateTarget(c.Payload) {
			return true
		}
	}
	return false
}

// withoutPrivateTargets drops the commands that name private targets.
func withoutPrivateTargets(cmds []*commanddom.Command) []*commanddom.Command {
	out := cmds[:0:0]
	for _, c := range cmds {
		if !HasPrivateTarget(c.Payload) {
			out = append(out, c)
		}
	}
	return out
}

// HasPrivateTarget reports whether a command payload names a private,
// loopback, link-local or CGNAT address, a range that overlaps one, or a
// host name of a private namespace (localhost, .local, .internal, .lan,
// .corp, .home.arpa, .localdomain, .intranet). A payload it cannot read counts as
// private (fail closed). Names that resolve to private addresses in public
// DNS are not detected here; the sensor's own policy covers them.
func HasPrivateTarget(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return false
	}
	var p struct {
		Target  json.RawMessage `json:"target"`
		Targets []string        `json:"targets"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return true
	}
	targets := p.Targets
	if len(p.Target) > 0 && string(p.Target) != "null" {
		var str string
		var obj struct {
			Address string `json:"address"`
		}
		switch {
		case json.Unmarshal(p.Target, &str) == nil:
			targets = append(targets, str)
		case json.Unmarshal(p.Target, &obj) == nil:
			targets = append(targets, obj.Address)
		default:
			return true
		}
	}
	for _, t := range targets {
		if isPrivateTarget(t) {
			return true
		}
	}
	return false
}

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

var privateSuffixes = []string{".local", ".internal", ".lan", ".corp", ".home.arpa", ".localhost", ".localdomain", ".intranet"}

func isPrivateTarget(target string) bool {
	host := strings.TrimSpace(target)
	if host == "" || strings.HasPrefix(host, "/") || strings.HasPrefix(host, ".") {
		return false // a filesystem path (code scan), not a network target
	}
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return true
		}
		host = u.Hostname()
	}
	if p, err := netip.ParsePrefix(host); err == nil {
		for _, pp := range privatePrefixes {
			if pp.Overlaps(p) {
				return true
			}
		}
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i] // registry/path of an image reference
	}
	host = strings.Trim(host, "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, pp := range privatePrefixes {
			if pp.Contains(a) {
				return true
			}
		}
		return a.IsUnspecified()
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "localhost" {
		return true
	}
	for _, sfx := range privateSuffixes {
		if strings.HasSuffix(name, sfx) {
			return true
		}
	}
	return false
}
