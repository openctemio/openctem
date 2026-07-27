package audit

import (
	"strings"
	"testing"
)

// audit_logs.actor_ip is varchar(45). Postgres does NOT truncate on INSERT — it
// rejects the row:
//
//	INSERT INTO audit_logs (…, actor_ip) VALUES (…, '[2001:0db8:…:7334]:54321')
//	ERROR: value too long for type character varying(45)
//
// and because the audit write is best-effort (`_ = LogEvent(...)`), the failure
// is invisible: the audit row AND its hash-chain entry are simply never written.
// Several handlers assign the raw X-Forwarded-For header, so an attacker could
// suppress the record of their own request by sending a long one.
func TestWithActorIP_BoundsToColumnWidth(t *testing.T) {
	log, err := NewAuditLog(ActionAssetMarkedStale, ResourceTypeAsset, "res-1", ResultSuccess)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}

	// A forged, over-long header.
	log.WithActorIP(strings.Repeat("9", 500))
	if got := len(log.ActorIP()); got > maxActorIPLen {
		t.Fatalf("actor_ip len = %d, want <= %d (the row would be rejected)", got, maxActorIPLen)
	}
}

// A perfectly legitimate IPv6 RemoteAddr is 47 characters — over the limit — so
// this is not only an attack path, it broke real IPv6 clients.
func TestWithActorIP_LegitimateIPv6RemoteAddrFits(t *testing.T) {
	const ipv6RemoteAddr = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:54321" // 47 chars
	if len(ipv6RemoteAddr) <= maxActorIPLen {
		t.Fatalf("test premise broken: %d chars is not over the %d limit", len(ipv6RemoteAddr), maxActorIPLen)
	}

	log, _ := NewAuditLog(ActionAssetMarkedStale, ResourceTypeAsset, "res-1", ResultSuccess)
	log.WithActorIP(ipv6RemoteAddr)

	if got := len(log.ActorIP()); got > maxActorIPLen {
		t.Fatalf("actor_ip len = %d, want <= %d", got, maxActorIPLen)
	}
}

// Callers pass the whole X-Forwarded-For chain; only the leftmost entry is the
// client, and keeping just it is both more correct and shorter.
func TestWithActorIP_KeepsOnlyTheClientHop(t *testing.T) {
	log, _ := NewAuditLog(ActionAssetMarkedStale, ResourceTypeAsset, "res-1", ResultSuccess)
	log.WithActorIP(" 203.0.113.7 , 10.0.0.1, 10.0.0.2 ")

	if got := log.ActorIP(); got != "203.0.113.7" {
		t.Fatalf("actor_ip = %q, want the leftmost hop %q", got, "203.0.113.7")
	}
}

// The ordinary case must be untouched.
func TestWithActorIP_PlainAddressUnchanged(t *testing.T) {
	log, _ := NewAuditLog(ActionAssetMarkedStale, ResourceTypeAsset, "res-1", ResultSuccess)
	log.WithActorIP("192.0.2.10")

	if got := log.ActorIP(); got != "192.0.2.10" {
		t.Fatalf("actor_ip = %q, want it unchanged", got)
	}
}
