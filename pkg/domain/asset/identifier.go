package asset

import (
	"net"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Asset identity: the identifiers that say which real-world thing an asset
// is. A name and an IP address are attributes that change (renames, DHCP);
// the strong identifiers below do not. Ingest matches an incoming asset on
// strong identifiers first, in IdentifierKind rank order, then on the exact
// name, then on an IP address seen within the trust window.
// See docs/architecture/asset-identity-resolution.md.

// IdentifierKind is the kind of an asset identifier.
type IdentifierKind string

// Identifier kinds, strongest first.
const (
	IdentifierHostID    IdentifierKind = "host_id"       // OS host ID read by a sensor
	IdentifierCloudID   IdentifierKind = "cloud_id"      // cloud instance ID, VM ID or ARN
	IdentifierBIOSUUID  IdentifierKind = "bios_uuid"     // SMBIOS system UUID
	IdentifierSerial    IdentifierKind = "serial_number" // hardware serial number
	IdentifierMAC       IdentifierKind = "mac"           // globally administered unicast MAC
	IdentifierSCMRepoID IdentifierKind = "scm_repo_id"   // SCM repository / project ID
	IdentifierFQDN      IdentifierKind = "fqdn"
	IdentifierHostname  IdentifierKind = "hostname"
	IdentifierIP        IdentifierKind = "ip"
)

// AllIdentifierKinds returns every kind, strongest first.
func AllIdentifierKinds() []IdentifierKind {
	return []IdentifierKind{
		IdentifierHostID, IdentifierCloudID, IdentifierBIOSUUID, IdentifierSerial,
		IdentifierMAC, IdentifierSCMRepoID, IdentifierFQDN, IdentifierHostname, IdentifierIP,
	}
}

// Rank orders kinds by trust: lower is stronger. Unknown kinds rank last.
func (k IdentifierKind) Rank() int {
	for i, kind := range AllIdentifierKinds() {
		if k == kind {
			return i
		}
	}
	return len(AllIdentifierKinds())
}

// IsValid reports whether k is a known kind.
func (k IdentifierKind) IsValid() bool { return k.Rank() < len(AllIdentifierKinds()) }

// IsStrong reports whether one value identifies one asset per tenant. Strong
// identifiers are unique per tenant; FQDN, hostname and IP are not.
func (k IdentifierKind) IsStrong() bool {
	switch k {
	case IdentifierHostID, IdentifierCloudID, IdentifierBIOSUUID, IdentifierSerial,
		IdentifierMAC, IdentifierSCMRepoID:
		return true
	}
	return false
}

// IsSingleValued reports whether an asset has at most one value of this
// kind. Two different values of a single-valued kind prove two different
// assets, which is what vetoes a match. A host has several MAC addresses, so
// a different MAC proves nothing.
func (k IdentifierKind) IsSingleValued() bool {
	switch k {
	case IdentifierHostID, IdentifierCloudID, IdentifierBIOSUUID, IdentifierSerial, IdentifierSCMRepoID:
		return true
	}
	return false
}

// IdentifierKey is one (kind, value) pair.
type IdentifierKey struct {
	Kind  IdentifierKind
	Value string
}

// Identifier is one identifier recorded for an asset.
type Identifier struct {
	AssetID   shared.ID
	Kind      IdentifierKind
	Value     string
	Source    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Key returns the identifier's (kind, value).
func (i Identifier) Key() IdentifierKey { return IdentifierKey{Kind: i.Kind, Value: i.Value} }

// NormalizeIdentifier canonicalizes a value of kind k. ok is false for a
// value that must not be used as an identifier: empty, a placeholder, or a
// MAC address many machines share.
func NormalizeIdentifier(k IdentifierKind, value string) (string, bool) {
	v := strings.TrimSpace(value)
	if v == "" || len(v) > 512 {
		return "", false
	}
	switch k {
	case IdentifierMAC:
		return NormalizeMAC(v)
	case IdentifierBIOSUUID, IdentifierHostID:
		v = strings.ToLower(strings.Trim(v, "{}"))
		if placeholderValue(v) {
			return "", false
		}
		return v, true
	case IdentifierSerial:
		if placeholderValue(strings.ToLower(v)) {
			return "", false
		}
		return v, true
	case IdentifierCloudID:
		// ARNs are case-sensitive; instance and VM IDs are not.
		if strings.HasPrefix(v, "arn:") {
			return v, true
		}
		return strings.ToLower(v), true
	case IdentifierSCMRepoID:
		return strings.ToLower(v), true
	case IdentifierFQDN, IdentifierHostname:
		v = strings.ToLower(strings.TrimSuffix(v, "."))
		if net.ParseIP(v) != nil || v == "localhost" || strings.HasPrefix(v, "localhost.") {
			return "", false
		}
		return v, true
	case IdentifierIP:
		ip := net.ParseIP(strings.Trim(v, "[]"))
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return "", false
		}
		return ip.String(), true
	}
	return "", false
}

// placeholderValue reports BIOS UUIDs, host IDs and serials that vendors
// ship unset, which many machines share.
func placeholderValue(lower string) bool {
	compact := strings.NewReplacer("-", "", " ", "", ":", "").Replace(lower)
	if strings.Trim(compact, "0") == "" || strings.Trim(compact, "f") == "" {
		return true
	}
	switch lower {
	case "none", "null", "n/a", "na", "unknown", "default string", "to be filled by o.e.m.",
		"to be filled by oem", "system serial number", "not specified", "not applicable",
		"0123456789", "123456789", "chassis serial number", "invalid", "default":
		return true
	}
	// "03000200-0400-0500-0006-000700080009" is the AMI/Supermicro default UUID.
	return compact == "03000200040005000006000700080009"
}

// sharedMACPrefixes are globally administered MAC addresses (or prefixes)
// that many machines report: VPN and dial-up adapters with a fixed address,
// and the virtual router MACs of VRRP and HSRP.
var sharedMACPrefixes = []string{
	"00:00:5e:00:01:", // VRRP (IPv4)
	"00:00:5e:00:02:", // VRRP (IPv6)
	"00:00:0c:07:ac:", // Cisco HSRP v1
	"00:00:0c:9f:f",   // Cisco HSRP v2
	"00:07:b4:00:",    // Cisco GLBP
	"00:05:9a:3c:7a:00",
	"00:09:0f:fe:00:01", // Fortinet FortiClient virtual adapter
	"50:50:54:50:30:30", // Windows WAN Miniport ("PPP00")
	"20:41:53:59:4e:ff", // Windows RAS async adapter
	"33:50:6f:45:30:30", // Windows WAN Miniport
	"00:ff:",            // TAP-style virtual adapters
}

// NormalizeMAC returns a MAC address as lower-case colon-separated hex. ok
// is false for addresses that do not identify one machine: malformed, zero,
// broadcast, multicast, locally administered (Docker, VPN and most virtual
// NICs set that bit), and the known shared addresses above.
func NormalizeMAC(value string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		// Accept bare hex ("001A2B3C4D5E").
		v := strings.TrimSpace(value)
		if len(v) != 12 {
			return "", false
		}
		hw, err = net.ParseMAC(v[0:2] + ":" + v[2:4] + ":" + v[4:6] + ":" + v[6:8] + ":" + v[8:10] + ":" + v[10:12])
		if err != nil {
			return "", false
		}
	}
	if len(hw) != 6 {
		return "", false
	}
	if hw[0]&0x01 != 0 || hw[0]&0x02 != 0 {
		return "", false // multicast/broadcast, or locally administered
	}
	s := strings.ToLower(hw.String())
	if s == "00:00:00:00:00:00" {
		return "", false
	}
	for _, p := range sharedMACPrefixes {
		if strings.HasPrefix(s, p) {
			return "", false
		}
	}
	return s, true
}

// SCMRepoIdentifier builds the scm_repo_id value for a repository: the SCM
// host from the repository's normalized name ("github.com/org/repo") and the
// ID the host assigned, so the same number on two hosts does not collide.
func SCMRepoIdentifier(repoName, repoID string) string {
	repoID = strings.TrimSpace(repoID)
	if repoID == "" {
		return ""
	}
	host, _, found := strings.Cut(strings.ToLower(repoName), "/")
	if found && strings.Contains(host, ".") {
		return host + ":" + strings.ToLower(repoID)
	}
	return strings.ToLower(repoID)
}
