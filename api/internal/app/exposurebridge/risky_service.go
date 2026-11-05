package exposurebridge

// Risky internet-facing services (docs/architecture/service-kinds.md).
//
// An open port whose kind was measured (any source but a port guess) and
// whose kind the registry marks risky (remote access, file sharing, a
// database, a cache, an orchestration API, an industrial protocol, ...)
// raises a risky_service_exposed exposure when the service is reachable
// from the internet. Its severity is the kind's; the kind's anonymous
// severity when a probe saw the service answer without credentials (that
// is its own exposure, so the severity a person reviewed never changes
// under them). Dedupe keys: port, transport and kind. When the kind
// changes, stops being risky, is only a guess again, or the anonymous state
// flips, the other exposures of the port are resolved automatically.

import (
	"fmt"
	"net"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// Keys and values the port projections share.
const (
	subTypeOpenPort = "open_port"
	keyPort         = "port"
	keyProtocol     = "protocol"
	transportTCP    = "tcp"
)

// Detail keys of service kind facts on port exposures (not dedupe keys,
// except "service", which holds the kind on a risky service exposure).
const (
	detailServiceKind  = "service_kind"
	detailKindSource   = "kind_source"
	detailServiceLabel = "service_label"
	detailServiceGuess = "service_guess"
	detailAnonymous    = "anonymous_access"
)

// AutoResolveServiceKindNote marks a risky service exposure resolved because
// a later scan saw the port speak something else, or no longer risky.
const AutoResolveServiceKindNote = "Resolved automatically: the service on this port is no longer of this kind, or no longer reachable this way."

// riskSeverity maps a registry risk to an exposure severity.
var riskSeverity = map[string]exposure.Severity{
	"low":      exposure.SeverityLow,
	"medium":   exposure.SeverityMedium,
	"high":     exposure.SeverityHigh,
	"critical": exposure.SeverityCritical,
}

// portTransport is the transport of a port asset: transport, else a
// transport older ingest filed under protocol, else tcp.
func portTransport(props map[string]any) string {
	for _, k := range []string{"transport", keyProtocol} {
		switch v := strings.ToLower(propString(props, k)); v {
		case transportTCP, "udp", "sctp":
			return v
		}
	}
	return transportTCP
}

// riskyTitle is the title (part of the dedupe identity) of a risky service
// exposure. Changing a risky kind's label re-keys its exposures.
func riskyTitle(def asset.ServiceKindDefinition, port int, transport string, anonymous bool) string {
	if anonymous {
		return fmt.Sprintf("%s reachable from the internet without authentication (port %d/%s)", def.Label, port, transport)
	}
	return fmt.Sprintf("%s reachable from the internet (port %d/%s)", def.Label, port, transport)
}

// riskyCandidate is the risky service exposure an open port raises, if any.
type riskyCandidate struct {
	def       asset.ServiceKindDefinition
	anonymous bool
	severity  exposure.Severity
}

// riskyServiceOf decides whether an open port raises a risky service
// exposure.
func riskyServiceOf(a *asset.Asset) (riskyCandidate, bool) {
	props := a.Properties()
	kind, src := asset.ServiceKindOf(props)
	if kind == "" || src.IsGuess() || !src.IsValid() {
		return riskyCandidate{}, false
	}
	def, ok := asset.LookupServiceKind(kind)
	if !ok || def.Risk == "" {
		return riskyCandidate{}, false
	}
	if st := strings.ToLower(propString(props, "state")); st == "closed" || st == "filtered" {
		return riskyCandidate{}, false
	}
	if !internetFacing(a) {
		return riskyCandidate{}, false
	}
	c := riskyCandidate{def: def, severity: riskSeverity[def.Risk]}
	if propBool(props, asset.PropKeyHasAnonymousAccess) && def.RiskAnonymous != "" {
		c.anonymous = true
		c.severity = riskSeverity[def.RiskAnonymous]
	}
	if c.severity == "" {
		return riskyCandidate{}, false
	}
	return c, true
}

// internetFacing reports whether a service is reachable from the internet:
// its exposure says so, or it listens on a public address (the host of its
// name or of its host attribute, or one of its addresses). An exposure set
// to private, restricted or isolated decides.
func internetFacing(a *asset.Asset) bool {
	switch a.Exposure() {
	case asset.ExposurePublic:
		return true
	case asset.ExposurePrivate, asset.ExposureIsolated, asset.ExposureRestricted:
		return false
	}
	if a.IsInternetAccessible() {
		return true
	}
	props := a.Properties()
	candidates := append([]string{serviceHost(a.Name()), propString(props, "host")}, asset.IPAddresses(props)...)
	for _, c := range candidates {
		if isPublicAddress(c) {
			return true
		}
	}
	return false
}

// serviceHost is the host part of an open port's stored name
// ("203.0.113.5:443:tcp", "[2001:db8::1]:443:tcp", "2001:db8::1:443:tcp"):
// the name without its trailing transport and port.
func serviceHost(name string) string {
	parts := strings.Split(strings.TrimSpace(name), ":")
	if n := len(parts); n > 1 {
		switch strings.ToLower(parts[n-1]) {
		case "tcp", "udp", "sctp":
			parts = parts[:n-1]
		}
	}
	if n := len(parts); n > 1 && isDigits(parts[n-1]) {
		parts = parts[:n-1]
	}
	return strings.Trim(strings.Join(parts, ":"), "[]")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cgnat is the shared address space (RFC 6598), not reachable from the
// internet.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// isPublicAddress reports whether s is a routable public address.
func isPublicAddress(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !cgnat.Contains(ip)
}

// buildRiskyServiceEvent projects an open port into a risky_service_exposed
// exposure, or nil when it raises none.
func (b *AssetBridge) buildRiskyServiceEvent(a *asset.Asset) *exposure.ExposureEvent {
	c, ok := riskyServiceOf(a)
	if !ok {
		return nil
	}
	props := a.Properties()
	port := propInt(props, keyPort)
	if port <= 0 {
		return nil
	}
	transport := portTransport(props)
	_, src := asset.ServiceKindOf(props)
	details := map[string]any{
		discoverySourceKey: SourceReconScan,
		keyPort:            port,      // dedupe key
		keyProtocol:        transport, // dedupe key
		"service":          c.def.ID,  // dedupe key
		detailServiceLabel: c.def.Label,
		detailKindSource:   string(src),
		"service_category": c.def.Category,
	}
	if c.anonymous {
		details[detailAnonymous] = true
	}
	return b.newEvent(a, exposure.EventTypeRiskyServiceExposed, c.severity,
		riskyTitle(c.def, port, transport, c.anonymous), details,
		"A service of a kind that should not be reachable from the internet")
}

// staleRiskyFingerprints are the fingerprints of every risky service
// exposure the open port could have raised other than current (nil = none
// now): the ones to resolve.
func staleRiskyFingerprints(a *asset.Asset, current *exposure.ExposureEvent) []string {
	props := a.Properties()
	port := propInt(props, keyPort)
	if port <= 0 || a.SubType() != subTypeOpenPort {
		return nil
	}
	transport := portTransport(props)
	keep := ""
	if current != nil {
		keep = current.Fingerprint()
	}
	var out []string
	for _, def := range asset.ServiceKinds() {
		if def.Risk == "" {
			continue
		}
		for _, anonymous := range []bool{false, true} {
			if anonymous && def.RiskAnonymous == "" {
				continue
			}
			details := map[string]any{keyPort: port, keyProtocol: transport, "service": def.ID}
			fp := exposure.Fingerprint(a.TenantID().String(), exposure.EventTypeRiskyServiceExposed.String(),
				riskyTitle(def, port, transport, anonymous), SourceReconScan, a.ID().String(), details)
			if fp != keep {
				out = append(out, fp)
			}
		}
	}
	return out
}
